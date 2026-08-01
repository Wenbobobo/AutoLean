from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from autolean_contracts import (
    LEAN_OLEAN_MEDIA_TYPE,
    VERIFICATION_EVIDENCE_MEDIA_TYPE,
    AcceptedDependencyV1,
    AttestationPurposeV1,
    DependencyClosureArtifactRefV1,
    DependencyClosureFileV1,
    DependencyClosureManifestV1,
    DependencyClosureModuleV1,
    DependencyDeclarationInventoryV1,
    DependencyDeclarationKindV1,
    DependencyKindV1,
    DependencyReferenceV1,
    EditRegionV1,
    FormalDependencyBindingV2,
    FormalDependencySupplyV2,
    FormalEdgeKindV1,
    FormalEdgeV1,
    FormalGraphV1,
    FormalizationTaskBundleV2,
    FormalNodeKindV1,
    FormalNodeV1,
    HashKindV1,
    StableIdentifierV1,
    StatementContractV2,
    StatementStatusV1,
    build_dependency_closure_ref,
    build_proof_boundary_v2,
    builder_attestation_payload,
    dependency_tree_hash,
    digest_model,
    stable_identifier,
)
from autolean_control_plane import ArtifactRef
from autolean_control_plane.errors import InvalidTransition, StaleFence
from pydantic import ValidationError
from test_service import _builder_signer, _bundle, _id, _plane


def _v2_fixture(
    *,
    target_kind: FormalNodeKindV1 = FormalNodeKindV1.THEOREM,
    extra_nodes: tuple[tuple[str, FormalNodeKindV1, str], ...] = (),
    body_edges: tuple[tuple[str, str], ...] = (),
    formal_body_dependencies: tuple[tuple[str, str], ...] = (),
    bindings: tuple[tuple[str, str], ...] = (),
    untracked_binding_node_keys: tuple[str, ...] = (),
    allowed_edit_regions: tuple[EditRegionV1, ...] = (),
    closure_backed_dependency_keys: tuple[str, ...] = (),
) -> tuple[FormalizationTaskBundleV2, DependencyClosureManifestV1, bytes]:
    """Build a self-contained V2 fixture with an explicit body-dependency graph.

    The closure remains empty and every supplied binding is image-owned.  That isolates graph
    binding validation from the separate closure-manifest admission rules.
    """

    base = _bundle(bundle_key="stage-b-v2")
    node_ids = {"target": _id("stage-b-target")}
    node_ids.update({key: _id(f"stage-b-{key}") for key, _kind, _name in extra_nodes})
    node_ids.update({key: _id(f"stage-b-{key}") for key in untracked_binding_node_keys})
    dependency_ids = {
        key: _id(f"stage-b-dependency-{key}") for key, _target_name in formal_body_dependencies
    }
    closure_backed_keys = set(closure_backed_dependency_keys)
    dependencies = tuple(
        DependencyReferenceV1(
            dependency_id=dependency_ids[key],
            kind=DependencyKindV1.FORMAL_BODY,
            target=target_name,
        )
        for key, target_name in formal_body_dependencies
    )
    formal_bindings = tuple(
        sorted(
            (
                FormalDependencyBindingV2(
                    dependency_id=dependency_ids[dependency_key],
                    formal_node_id=node_ids[node_key],
                    supply=(
                        FormalDependencySupplyV2.CLOSURE
                        if dependency_key in closure_backed_keys
                        else FormalDependencySupplyV2.IMAGE_OWNED
                    ),
                )
                for dependency_key, node_key in bindings
            ),
            key=lambda binding: binding.dependency_id.value,
        )
    )
    payload = base.contract.model_dump(mode="python", round_trip=True)
    policy = payload["policy"]
    assert isinstance(policy, dict)
    policy["allowed_edit_regions"] = allowed_edit_regions
    payload.update(
        {
            "schema_version": "2.0",
            "formal_target_node_id": node_ids["target"],
            "dependency_mode": (
                "compositional_bridge" if closure_backed_keys else "independent_reproof"
            ),
            "dependencies": dependencies,
            "formal_dependency_bindings": formal_bindings,
            "status": StatementStatusV1.DRAFT,
            "freeze": None,
        }
    )
    draft = StatementContractV2.model_validate(payload)
    assert base.contract.freeze is not None
    payload.update(
        {
            "status": StatementStatusV1.FROZEN,
            "freeze": base.contract.freeze.model_copy(
                update={"contract_hash": draft.semantic_hash()}
            ),
        }
    )
    contract = StatementContractV2.model_validate(payload)
    graphs = base.graphs.model_copy(
        update={
            "formal": FormalGraphV1(
                graph_id=_id("stage-b-formal"),
                revision=1,
                nodes=(
                    FormalNodeV1(
                        node_id=node_ids["target"],
                        kind=target_kind,
                        declaration_name="AutoLean.Test.fixture",
                    ),
                    *(
                        FormalNodeV1(
                            node_id=node_ids[key],
                            kind=kind,
                            declaration_name=declaration_name,
                        )
                        for key, kind, declaration_name in extra_nodes
                    ),
                ),
                edges=tuple(
                    FormalEdgeV1(
                        edge_id=_id(f"stage-b-body-edge-{source}-{target}"),
                        source=node_ids[source],
                        target=node_ids[target],
                        kind=FormalEdgeKindV1.BODY_DEPENDS_ON,
                    )
                    for source, target in body_edges
                ),
            )
        }
    )
    data = b"stage-b fixture olean"
    artifact = DependencyClosureArtifactRefV1(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        media_type=LEAN_OLEAN_MEDIA_TYPE,
    )
    files = (
        DependencyClosureFileV1(
            relative_path="AutoLean/Test/Foundation.olean",
            artifact=artifact,
        ),
    )
    closure_bindings = {
        dependency_key: node_key
        for dependency_key, node_key in bindings
        if dependency_key in closure_backed_keys
    }
    evidence_data = b"stage-b accepted dependency evidence"
    evidence = DependencyClosureArtifactRefV1(
        sha256=hashlib.sha256(evidence_data).hexdigest(),
        size=len(evidence_data),
        media_type=VERIFICATION_EVIDENCE_MEDIA_TYPE,
    )
    accepted_dependencies = tuple(
        sorted(
            (
                AcceptedDependencyV1(
                    dependency_id=dependency_ids[key],
                    formal_node_id=node_ids[node_key],
                    contract_id=_id(f"stage-b-prerequisite-contract-{key}"),
                    revision=1,
                    contract_hash=digest_model(
                        HashKindV1.CONTRACT,
                        {"stage_b_prerequisite": key},
                    ),
                    declaration_name=target_name,
                    canonical_type_hash=digest_model(
                        HashKindV1.ELABORATED_TYPE,
                        {"stage_b_prerequisite": key},
                    ),
                    module_name="AutoLean.Test.Foundation",
                    verification_evidence=evidence,
                )
                for key, target_name in formal_body_dependencies
                for node_key in (closure_bindings.get(key),)
                if node_key is not None
            ),
            key=lambda dependency: dependency.dependency_id.value,
        )
    )
    declaration_inventory = tuple(
        sorted(
            (
                DependencyDeclarationInventoryV1(
                    declaration_name=dependency.declaration_name,
                    kind=DependencyDeclarationKindV1.THEOREM,
                    canonical_type_hash=dependency.canonical_type_hash,
                    module_name=dependency.module_name,
                )
                for dependency in accepted_dependencies
            ),
            key=lambda declaration: declaration.declaration_name,
        )
    )
    manifest = DependencyClosureManifestV1(
        closure_id=stable_identifier("dependency-closure", "stage-b-v2"),
        environment_hash=contract.formal.environment.environment_hash,
        tree_hash=dependency_tree_hash(files),
        target_contract_id=contract.contract_id,
        target_revision=contract.revision,
        target_contract_hash=contract.semantic_hash(),
        target_declaration="AutoLean.Test.fixture",
        target_canonical_type_hash=contract.formal.elaborated_type_hash,
        entry_modules=("AutoLean.Test.Foundation",),
        files=files,
        modules=(
            DependencyClosureModuleV1(
                module_name="AutoLean.Test.Foundation",
                olean_path="AutoLean/Test/Foundation.olean",
            ),
        ),
        declaration_inventory=declaration_inventory,
        accepted_dependencies=accepted_dependencies,
    )
    reference = build_dependency_closure_ref(manifest)
    unsigned = FormalizationTaskBundleV2(
        bundle_id=base.bundle_id,
        contract=contract,
        graphs=graphs,
        graph_snapshot_hash=digest_model(HashKindV1.GRAPH_SNAPSHOT, graphs),
        proof_boundary=build_proof_boundary_v2(contract, reference),
        dependency_closure=reference,
    )
    attestation = _builder_signer().issue(
        purpose=AttestationPurposeV1.BUILDER_FREEZE,
        payload=builder_attestation_payload(unsigned),
        evidence_identity="stage-b-v2",
        ttl_seconds=3600,
    )
    return unsigned.model_copy(update={"builder_attestation": attestation}), manifest, data


def test_v2_accepts_exact_transitive_formal_body_predecessor_bindings() -> None:
    bundle, _manifest, _data = _v2_fixture(
        extra_nodes=(
            ("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),
            ("indirect", FormalNodeKindV1.THEOREM, "AutoLean.Test.indirect_dependency"),
        ),
        body_edges=(("indirect", "direct"), ("direct", "target")),
        formal_body_dependencies=(
            ("direct", "AutoLean.Test.direct_dependency"),
            ("indirect", "AutoLean.Test.indirect_dependency"),
        ),
        bindings=(("direct", "direct"), ("indirect", "indirect")),
    )

    assert {
        binding.formal_node_id.value for binding in bundle.contract.formal_dependency_bindings
    } == {_id("stage-b-direct").value, _id("stage-b-indirect").value}


def test_v2_compositional_bridge_binds_exact_closure_backed_dependency_ids() -> None:
    bundle, _manifest, _data = _v2_fixture(
        extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
        body_edges=(("direct", "target"),),
        formal_body_dependencies=(("direct", "AutoLean.Test.direct_dependency"),),
        bindings=(("direct", "direct"),),
        closure_backed_dependency_keys=("direct",),
    )
    dependency_id = bundle.contract.formal_dependency_bindings[0].dependency_id

    assert bundle.contract.dependency_mode == "compositional_bridge"
    assert bundle.dependency_closure.formal_body_dependency_ids == (dependency_id,)


@pytest.mark.parametrize("closure_ids", ((), (_id("stage-b-closure-extra"),)))
def test_v2_rejects_missing_or_extra_closure_backed_dependency_ids(
    closure_ids: tuple[StableIdentifierV1, ...],
) -> None:
    bundle, _manifest, _data = _v2_fixture(
        extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
        body_edges=(("direct", "target"),),
        formal_body_dependencies=(("direct", "AutoLean.Test.direct_dependency"),),
        bindings=(("direct", "direct"),),
        closure_backed_dependency_keys=("direct",),
    )
    if closure_ids:
        replacement_ids = tuple(
            sorted(
                (
                    bundle.contract.formal_dependency_bindings[0].dependency_id,
                    *closure_ids,
                ),
                key=lambda item: item.value,
            )
        )
    else:
        replacement_ids = ()
    replacement = bundle.dependency_closure.model_copy(
        update={"formal_body_dependency_ids": replacement_ids}
    )

    with pytest.raises(ValidationError, match="closure IDs must exactly match"):
        FormalizationTaskBundleV2(
            bundle_id=bundle.bundle_id,
            contract=bundle.contract,
            graphs=bundle.graphs,
            graph_snapshot_hash=bundle.graph_snapshot_hash,
            proof_boundary=bundle.proof_boundary,
            dependency_closure=replacement,
        )


def test_v2_rejects_omitted_transitive_formal_body_predecessor_binding() -> None:
    with pytest.raises(
        ValidationError,
        match=r"exactly cover transitive BODY_DEPENDS_ON predecessors.*missing=",
    ):
        _v2_fixture(
            extra_nodes=(
                ("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),
                (
                    "indirect",
                    FormalNodeKindV1.THEOREM,
                    "AutoLean.Test.indirect_dependency",
                ),
            ),
            body_edges=(("indirect", "direct"), ("direct", "target")),
            formal_body_dependencies=(("direct", "AutoLean.Test.direct_dependency"),),
            bindings=(("direct", "direct"),),
        )


def test_v2_rejects_unrelated_formal_body_binding() -> None:
    with pytest.raises(
        ValidationError,
        match=r"exactly cover transitive BODY_DEPENDS_ON predecessors.*unrelated=",
    ):
        _v2_fixture(
            extra_nodes=(
                ("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),
                (
                    "unrelated",
                    FormalNodeKindV1.THEOREM,
                    "AutoLean.Test.unrelated_dependency",
                ),
            ),
            body_edges=(("direct", "target"),),
            formal_body_dependencies=(
                ("direct", "AutoLean.Test.direct_dependency"),
                ("unrelated", "AutoLean.Test.unrelated_dependency"),
            ),
            bindings=(("direct", "direct"), ("unrelated", "unrelated")),
        )


def test_v2_rejects_formal_body_binding_to_unknown_graph_node() -> None:
    with pytest.raises(
        ValidationError, match="dependency binding references an unknown formal node"
    ):
        _v2_fixture(
            formal_body_dependencies=(("missing", "AutoLean.Test.missing_dependency"),),
            bindings=(("missing", "missing"),),
            untracked_binding_node_keys=("missing",),
        )


def test_v2_rejects_reversed_body_dependency_edge_as_a_binding_source() -> None:
    with pytest.raises(
        ValidationError,
        match=r"exactly cover transitive BODY_DEPENDS_ON predecessors.*unrelated=",
    ):
        _v2_fixture(
            extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
            body_edges=(("target", "direct"),),
            formal_body_dependencies=(("direct", "AutoLean.Test.direct_dependency"),),
            bindings=(("direct", "direct"),),
        )


def test_v2_rejects_duplicate_formal_node_binding() -> None:
    with pytest.raises(ValidationError, match="dependency binding nodes must be unique"):
        _v2_fixture(
            extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
            body_edges=(("direct", "target"),),
            formal_body_dependencies=(
                ("first", "AutoLean.Test.direct_dependency"),
                ("second", "AutoLean.Test.direct_dependency"),
            ),
            bindings=(("first", "direct"), ("second", "direct")),
        )


def test_v2_rejects_formal_body_binding_target_drift() -> None:
    with pytest.raises(
        ValidationError,
        match="formal node does not match the contract target",
    ):
        _v2_fixture(
            extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
            body_edges=(("direct", "target"),),
            formal_body_dependencies=(("direct", "AutoLean.Test.unrelated_dependency"),),
            bindings=(("direct", "direct"),),
        )


def test_v2_rejects_noncanonical_formal_body_dependency_target() -> None:
    with pytest.raises(
        ValidationError,
        match="formal-body dependency target must be a canonical Lean declaration",
    ):
        _v2_fixture(
            extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "not a canonical Lean declaration"),),
            body_edges=(("direct", "target"),),
            formal_body_dependencies=(("direct", "not a canonical Lean declaration"),),
            bindings=(("direct", "direct"),),
        )


def test_v2_rejects_duplicate_contract_dependency_identifiers() -> None:
    with pytest.raises(ValidationError, match="contract dependency identifiers must be unique"):
        _v2_fixture(
            extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
            body_edges=(("direct", "target"),),
            formal_body_dependencies=(
                ("direct", "AutoLean.Test.direct_dependency"),
                ("direct", "AutoLean.Test.direct_dependency"),
            ),
            bindings=(("direct", "direct"),),
        )


def test_v2_rejects_line_ranged_edit_region_payload() -> None:
    with pytest.raises(
        ValidationError, match="V2 bundles do not support line-ranged editable regions"
    ):
        _v2_fixture(
            allowed_edit_regions=(
                EditRegionV1(
                    artifact_ref="Proof.lean",
                    start_line=1,
                    end_line=1,
                ),
            )
        )


@pytest.mark.parametrize(
    "target_kind",
    (
        FormalNodeKindV1.DEFINITION,
        FormalNodeKindV1.IMPORT,
        FormalNodeKindV1.INSTANCE,
        FormalNodeKindV1.NOTATION,
    ),
)
def test_v2_rejects_non_theorem_formal_target_kind(target_kind: FormalNodeKindV1) -> None:
    with pytest.raises(ValidationError, match="formal target node must be a theorem declaration"):
        _v2_fixture(target_kind=target_kind)


def test_claim_scoped_v2_retrieval_only_exposes_registered_closure(tmp_path: Path) -> None:
    bundle, manifest, data = _v2_fixture()
    plane = _plane(tmp_path)
    manifest_ref = plane.artifacts.put_bytes(manifest.canonical_bytes())
    blob_ref = plane.artifacts.put_bytes(data)
    binding = plane.register_bundle(bundle, idempotency_key="stage-b-register")
    assert binding.bundle_schema_version == "2.0"
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="stage-b-worker",
        ttl_seconds=120,
        idempotency_key="stage-b-claim",
    )
    assert plane.fetch_claimed_bundle(receipt).schema_version == "2.0"
    assert (
        plane.read_claimed_dependency_artifact(receipt, manifest_ref) == manifest.canonical_bytes()
    )
    assert plane.read_claimed_dependency_artifact(receipt, blob_ref) == data

    with pytest.raises(InvalidTransition, match="not reachable"):
        plane.read_claimed_dependency_artifact(
            receipt,
            ArtifactRef(digest="0" * 64, size=1),
        )


def test_v2_registration_rejects_self_declared_dependency_verification_blob(
    tmp_path: Path,
) -> None:
    bundle, manifest, data = _v2_fixture(
        extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
        body_edges=(("direct", "target"),),
        formal_body_dependencies=(("direct", "AutoLean.Test.direct_dependency"),),
        bindings=(("direct", "direct"),),
        closure_backed_dependency_keys=("direct",),
    )
    plane = _plane(tmp_path)
    plane.artifacts.put_bytes(manifest.canonical_bytes())
    plane.artifacts.put_bytes(data)
    # Blob existence and a verification-evidence media type are not admission authority.  The
    # current accepted-verification protocol does not bind this declaration to the exported
    # module/OLean blob asserted by the closure manifest.
    plane.artifacts.put_bytes(b"stage-b accepted dependency evidence")

    with pytest.raises(InvalidTransition, match="module-bound dependency admission"):
        plane.register_bundle(bundle, idempotency_key="stage-b-self-declared-verification")


def test_claim_scoped_retrieval_rejects_wrong_claim_stale_fence_and_substitution(
    tmp_path: Path,
) -> None:
    bundle, manifest, data = _v2_fixture()
    plane = _plane(tmp_path)
    manifest_ref = plane.artifacts.put_bytes(manifest.canonical_bytes())
    blob_ref = plane.artifacts.put_bytes(data)
    plane.register_bundle(bundle, idempotency_key="stage-b-register")
    receipt = plane.claim(
        bundle.bundle_id.value,
        worker_id="stage-b-worker",
        ttl_seconds=120,
        idempotency_key="stage-b-claim",
    )

    wrong_claim = replace(
        receipt,
        bundle_id="urn:autolean:v1:control-test:00000000-0000-0000-0000-000000000000",
    )
    with pytest.raises(InvalidTransition):
        plane.read_claimed_dependency_artifact(wrong_claim, manifest_ref)

    stale_lease = replace(receipt.lease, fencing_token=receipt.lease.fencing_token + 1)
    with pytest.raises((InvalidTransition, StaleFence)):
        plane.read_claimed_dependency_artifact(replace(receipt, lease=stale_lease), manifest_ref)

    path = plane.artifacts._path_for_digest(blob_ref.digest)
    path.write_bytes(b"substituted")
    with pytest.raises(InvalidTransition, match="unavailable or corrupt"):
        plane.read_claimed_dependency_artifact(receipt, blob_ref)


def test_v2_registration_rejects_manifest_target_revision_drift(tmp_path: Path) -> None:
    bundle, manifest, data = _v2_fixture()
    manifest_payload = manifest.model_dump(mode="python", round_trip=True)
    manifest_payload["target_revision"] = manifest.target_revision + 1
    drifted_manifest = DependencyClosureManifestV1.model_validate(manifest_payload)
    drifted_reference = build_dependency_closure_ref(drifted_manifest)
    unsigned_payload = bundle.model_dump(mode="python", round_trip=True)
    unsigned_payload.update(
        {
            "dependency_closure": drifted_reference,
            "proof_boundary": build_proof_boundary_v2(bundle.contract, drifted_reference),
            "builder_attestation": None,
        }
    )
    unsigned = FormalizationTaskBundleV2.model_validate(unsigned_payload)
    drifted_bundle = unsigned.model_copy(
        update={
            "builder_attestation": _builder_signer().issue(
                purpose=AttestationPurposeV1.BUILDER_FREEZE,
                payload=builder_attestation_payload(unsigned),
                evidence_identity="stage-b-drifted-target",
                ttl_seconds=3600,
            )
        }
    )
    plane = _plane(tmp_path)
    plane.artifacts.put_bytes(drifted_manifest.canonical_bytes())
    plane.artifacts.put_bytes(data)
    with pytest.raises(InvalidTransition, match="different contract revision"):
        plane.register_bundle(drifted_bundle, idempotency_key="stage-b-drifted-register")


@pytest.mark.parametrize(
    ("field", "replacement", "match"),
    (
        (
            "formal_node_id",
            _id("stage-b-manifest-substituted-node"),
            "accepted formal node differs from frozen binding",
        ),
        (
            "declaration_name",
            "AutoLean.Test.manifest_substituted_dependency",
            "accepted declaration differs from frozen dependency",
        ),
    ),
)
def test_v2_registration_rejects_manifest_dependency_binding_substitution(
    tmp_path: Path,
    field: str,
    replacement: StableIdentifierV1 | str,
    match: str,
) -> None:
    bundle, manifest, data = _v2_fixture(
        extra_nodes=(("direct", FormalNodeKindV1.THEOREM, "AutoLean.Test.direct_dependency"),),
        body_edges=(("direct", "target"),),
        formal_body_dependencies=(("direct", "AutoLean.Test.direct_dependency"),),
        bindings=(("direct", "direct"),),
        closure_backed_dependency_keys=("direct",),
    )
    manifest_payload = manifest.model_dump(mode="python", round_trip=True)
    accepted_payload = manifest_payload["accepted_dependencies"][0]
    assert isinstance(accepted_payload, dict)
    accepted_payload[field] = replacement
    if field == "declaration_name":
        inventory_payload = manifest_payload["declaration_inventory"][0]
        assert isinstance(inventory_payload, dict)
        inventory_payload["declaration_name"] = replacement
    substituted_manifest = DependencyClosureManifestV1.model_validate(manifest_payload)
    reference = build_dependency_closure_ref(substituted_manifest)
    unsigned_payload = bundle.model_dump(mode="python", round_trip=True)
    unsigned_payload.update(
        {
            "dependency_closure": reference,
            "proof_boundary": build_proof_boundary_v2(bundle.contract, reference),
            "builder_attestation": None,
        }
    )
    unsigned = FormalizationTaskBundleV2.model_validate(unsigned_payload)
    substituted_bundle = unsigned.model_copy(
        update={
            "builder_attestation": _builder_signer().issue(
                purpose=AttestationPurposeV1.BUILDER_FREEZE,
                payload=builder_attestation_payload(unsigned),
                evidence_identity=f"stage-b-manifest-substitution-{field}",
                ttl_seconds=3600,
            )
        }
    )
    plane = _plane(tmp_path)
    plane.artifacts.put_bytes(substituted_manifest.canonical_bytes())
    plane.artifacts.put_bytes(data)
    plane.artifacts.put_bytes(b"stage-b accepted dependency evidence")

    with pytest.raises(InvalidTransition, match=match):
        plane.register_bundle(
            substituted_bundle,
            idempotency_key=f"stage-b-manifest-substitution-{field}",
        )
