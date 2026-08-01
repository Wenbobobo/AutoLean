from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from autolean_builder.adapters.research_scout import (
    ImmutableArtifactCommitmentV1,
    ResearchScoutAdapterError,
    ResearchScoutAdapterV1,
    ResearchScoutEgressClassV1,
    ResearchScoutInputArtifactsV1,
    ResearchScoutRequestV1,
    ResearchScoutRoleV1,
    ResearchScoutSourceRefV1,
)
from autolean_contracts import canonical_json_bytes
from pydantic import ValidationError


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _request_and_artifacts() -> tuple[ResearchScoutRequestV1, ResearchScoutInputArtifactsV1]:
    goal = "Find a finite toy obstruction for the fixed research mission."
    graph_hash = _sha256(b"frozen graph snapshot")
    source = ResearchScoutSourceRefV1(
        source_id="source-fixture",
        span_id="span-fixture",
        hash=_sha256(b"permitted source span"),
    )
    artifacts = ResearchScoutInputArtifactsV1(
        goal=ImmutableArtifactCommitmentV1(
            artifact_id="goal-artifact",
            sha256=_sha256(goal.encode("utf-8")),
        ),
        context_pack=ImmutableArtifactCommitmentV1(
            artifact_id="context-pack", sha256=_sha256(b"role-scoped context")
        ),
        context_artifact=ImmutableArtifactCommitmentV1(
            artifact_id="context-artifact", sha256=_sha256(b"context artifact")
        ),
        graph_snapshot=ImmutableArtifactCommitmentV1(
            artifact_id="graph-snapshot", sha256=graph_hash
        ),
        rights_scope=ImmutableArtifactCommitmentV1(
            artifact_id="rights-scope", sha256=_sha256(b"rights record")
        ),
        provider_snapshot=ImmutableArtifactCommitmentV1(
            artifact_id="fake-snapshot-v1", sha256=_sha256(b"provider snapshot")
        ),
        source_refs=(source,),
        predecessor_proposal_ids=("a" * 64,),
    )
    request = ResearchScoutRequestV1(
        request_id="request-fixture",
        mission_id="mission-fixture",
        revision=0,
        contract_hash=None,
        graph_snapshot_hash=graph_hash,
        context_pack_hash=artifacts.context_pack.sha256,
        input_artifacts_sha256=artifacts.computed_sha256(),
        role=ResearchScoutRoleV1.CONSTRUCTIVE,
        goal=goal,
        context_artifact_sha256=artifacts.context_artifact.sha256,
        rights_scope_id=artifacts.rights_scope.artifact_id,
        provider_snapshot_id=artifacts.provider_snapshot.artifact_id,
        attempt_budget={"max_attempts": 1, "max_output_tokens": 32},
        egress_class=ResearchScoutEgressClassV1.LOCAL,
        provenance={
            "source_ids": (source.source_id,),
            "source_span_ids": (source.span_id,),
            "retrieval_hash": graph_hash,
        },
    )
    return request, artifacts


def _response_bytes(
    request: ResearchScoutRequestV1,
    artifacts: ResearchScoutInputArtifactsV1,
    **updates: object,
) -> bytes:
    payload: dict[str, object] = {
        "schema_version": "autolean.research-scout-response.v1",
        "request_id": request.request_id,
        "kind": "lemma",
        "statement": "A finite witness suggests the proposed route.",
        "evidence": "Enumerate the finite cases and preserve the counterexample boundary.",
        "dependency_refs": ["a" * 64],
        "source_refs": [artifacts.source_refs[0].model_dump(mode="json")],
        "context_pack_hash": request.context_pack_hash,
        "provider": {"provider_id": "fake", "model_id": "fake-model-v1"},
        "usage": {"input_tokens": 7, "output_tokens": 11, "cost_micro_usd": 0},
        "status": "untrusted_proposal",
    }
    payload.update(updates)
    identity_payload = dict(payload)
    identity_payload.pop("proposal_id", None)
    identity_payload.pop("output_sha256", None)
    digest = _sha256(canonical_json_bytes(identity_payload))
    payload["proposal_id"] = digest
    payload["output_sha256"] = digest
    return canonical_json_bytes(payload)


def test_fake_round_trip_is_canonical_and_proposal_only() -> None:
    request, artifacts = _request_and_artifacts()
    adapter = ResearchScoutAdapterV1()

    request_bytes = adapter.request_bytes(request, artifacts)
    assert adapter.parse_request(request_bytes, artifacts) == request
    response_bytes = _response_bytes(request, artifacts)

    proposal = adapter.accept_response(request, artifacts, response_bytes)

    assert proposal.authority == "machine_advisory"
    assert proposal.promotion is False
    assert proposal.event_kind == "research_hypothesis"
    assert proposal.proposal_id == proposal.output_sha256
    assert proposal.response_cas_sha256 == _sha256(response_bytes)
    assert proposal.canonical_bytes() == canonical_json_bytes(proposal)


def test_control_plane_event_projection_drops_private_proposal_text_and_authority_paths() -> None:
    request, artifacts = _request_and_artifacts()
    proposal = ResearchScoutAdapterV1().accept_response(
        request,
        artifacts,
        _response_bytes(request, artifacts),
    )

    event = proposal.control_plane_event()
    payload = event.model_dump(mode="json")

    assert event.proposal_id == proposal.proposal_id
    assert event.output_sha256 == proposal.output_sha256
    assert event.response_cas_sha256 == proposal.response_cas_sha256
    assert event.authority == "machine_advisory"
    assert event.promotion is False
    assert set(payload) == {
        "schema_version",
        "proposal_id",
        "event_kind",
        "proposal_kind",
        "request_id",
        "context_pack_hash",
        "output_sha256",
        "response_cas_sha256",
        "dependency_refs",
        "source_refs",
        "provider",
        "authority",
        "promotion",
    }
    public_bytes = canonical_json_bytes(event)
    assert proposal.statement.encode("utf-8") not in public_bytes
    assert proposal.evidence.encode("utf-8") not in public_bytes
    for forbidden in (b"usage", b"contract_id", b"bundle_id", b"proof", b"verification"):
        assert forbidden not in public_bytes


def test_hash_and_context_substitution_fail_closed() -> None:
    request, artifacts = _request_and_artifacts()
    adapter = ResearchScoutAdapterV1()

    with pytest.raises(ResearchScoutAdapterError, match="goal does not match"):
        adapter.request_bytes(
            request.model_copy(update={"goal": "substituted objective"}), artifacts
        )

    contract_hash = _sha256(b"frozen contract revision")
    frozen_artifacts = artifacts.model_copy(
        update={
            "contract": ImmutableArtifactCommitmentV1(
                artifact_id="contract-fixture",
                sha256=contract_hash,
            )
        }
    )
    frozen_request = request.model_copy(
        update={
            "contract_id": "contract-fixture",
            "revision": 1,
            "contract_hash": contract_hash,
            "input_artifacts_sha256": frozen_artifacts.computed_sha256(),
        }
    )
    assert adapter.request_bytes(frozen_request, frozen_artifacts)
    with pytest.raises(ResearchScoutAdapterError, match="existing contract"):
        adapter.request_bytes(
            frozen_request,
            frozen_artifacts.model_copy(
                update={
                    "contract": ImmutableArtifactCommitmentV1(
                        artifact_id="contract-fixture",
                        sha256="b" * 64,
                    )
                }
            ),
        )

    substituted = _response_bytes(
        request,
        artifacts,
        context_pack_hash="b" * 64,
    )
    with pytest.raises(ResearchScoutAdapterError, match="context hash"):
        adapter.accept_response(request, artifacts, substituted)


def test_unknown_predecessor_cannot_enter_advisory_closure() -> None:
    request, artifacts = _request_and_artifacts()
    response = _response_bytes(request, artifacts, dependency_refs=["b" * 64])

    with pytest.raises(ResearchScoutAdapterError, match="unknown predecessor"):
        ResearchScoutAdapterV1().accept_response(request, artifacts, response)


def test_request_binds_rights_provider_sources_and_predecessor_inventory() -> None:
    request, artifacts = _request_and_artifacts()
    source = artifacts.source_refs[0]
    substitutions = (
        artifacts.model_copy(
            update={"rights_scope": artifacts.rights_scope.model_copy(update={"sha256": "b" * 64})}
        ),
        artifacts.model_copy(
            update={
                "provider_snapshot": artifacts.provider_snapshot.model_copy(
                    update={"sha256": "b" * 64}
                )
            }
        ),
        artifacts.model_copy(
            update={"source_refs": (source.model_copy(update={"hash": "b" * 64}),)}
        ),
        artifacts.model_copy(update={"predecessor_proposal_ids": ("b" * 64,)}),
    )

    for substituted in substitutions:
        with pytest.raises(ResearchScoutAdapterError, match="input artifact inventory"):
            ResearchScoutAdapterV1().request_bytes(request, substituted)


def test_authority_escalation_and_unknown_response_fields_are_rejected() -> None:
    request, artifacts = _request_and_artifacts()
    payload = {
        "schema_version": "autolean.research-scout-response.v1",
        "request_id": request.request_id,
        "kind": "lemma",
        "statement": "A proposal must stay advisory.",
        "evidence": "No authority is inferred from this text.",
        "dependency_refs": [],
        "source_refs": [],
        "context_pack_hash": request.context_pack_hash,
        "provider": {"provider_id": "fake", "model_id": "fake-model-v1"},
        "usage": {"input_tokens": 0, "output_tokens": 0, "cost_micro_usd": 0},
        "status": "untrusted_proposal",
        "authority": "kernel_verified",
        "promotion": True,
    }
    digest = _sha256(canonical_json_bytes(payload))
    payload["proposal_id"] = digest
    payload["output_sha256"] = digest

    with pytest.raises(ResearchScoutAdapterError, match="typed schema"):
        ResearchScoutAdapterV1().accept_response(request, artifacts, canonical_json_bytes(payload))


def test_paths_secrets_and_raw_context_egress_are_rejected() -> None:
    request, artifacts = _request_and_artifacts()
    for host_path in (
        "C:\\Users\\operator\\private theorem",
        r"\\operator-share\private theorem",
        "file:///home/operator/private theorem",
    ):
        with pytest.raises(ValidationError, match="host path"):
            ResearchScoutRequestV1.model_validate(
                {
                    **request.model_dump(mode="json"),
                    "goal": host_path,
                }
            )
    with pytest.raises(ValidationError, match="secret-like"):
        ResearchScoutRequestV1.model_validate(
            {
                **request.model_dump(mode="json"),
                "goal": "api_key=not-an-artifact",
            }
        )
    request_payload = request.model_dump(mode="json")
    request_payload["raw_context"] = "/home/operator/private.txt"
    with pytest.raises(ResearchScoutAdapterError, match="typed schema"):
        ResearchScoutAdapterV1().parse_request(canonical_json_bytes(request_payload), artifacts)
    with pytest.raises(ResearchScoutAdapterError, match="typed schema"):
        ResearchScoutAdapterV1().accept_response(
            request,
            artifacts,
            _response_bytes(request, artifacts, evidence=r"Read \\operator-share\private."),
        )


def test_disallowed_provider_non_utf8_and_proof_holes_fail_before_authority_paths() -> None:
    request, artifacts = _request_and_artifacts()
    forbidden_artifacts = artifacts.model_copy(
        update={
            "provider_snapshot": ImmutableArtifactCommitmentV1(
                artifact_id="unapproved-snapshot-v1", sha256=artifacts.provider_snapshot.sha256
            )
        }
    )
    forbidden_request = request.model_copy(
        update={
            "provider_snapshot_id": "unapproved-snapshot-v1",
            "input_artifacts_sha256": forbidden_artifacts.computed_sha256(),
        }
    )
    adapter = ResearchScoutAdapterV1()

    with pytest.raises(ResearchScoutAdapterError, match="allowlist"):
        adapter.request_bytes(forbidden_request, forbidden_artifacts)
    with pytest.raises(ResearchScoutAdapterError, match="valid UTF-8 JSON"):
        adapter.parse_request(b"\xff", artifacts)
    with pytest.raises(ResearchScoutAdapterError, match="duplicate key"):
        adapter.parse_request(
            b'{"schema_version":"autolean.research-scout-request.v1",'
            b'"schema_version":"autolean.research-scout-request.v1"}',
            artifacts,
        )
    with pytest.raises(ResearchScoutAdapterError, match="typed schema"):
        adapter.accept_response(
            request,
            artifacts,
            _response_bytes(
                request,
                artifacts,
                kind="proof_candidate",
                evidence="by\n  sorry",
            ),
        )


def test_forbidden_provider_family_cannot_use_the_custom_provider_seam() -> None:
    request, artifacts = _request_and_artifacts()

    with pytest.raises(ValidationError, match="not permitted"):
        ResearchScoutRequestV1.model_validate(
            {
                **request.model_dump(mode="json"),
                "provider_snapshot_id": "custom-claude-snapshot-v1",
            }
        )

    custom_artifacts = artifacts.model_copy(
        update={
            "provider_snapshot": ImmutableArtifactCommitmentV1(
                artifact_id="custom-snapshot-v1",
                sha256=artifacts.provider_snapshot.sha256,
            )
        }
    )
    custom_request = request.model_copy(
        update={
            "provider_snapshot_id": "custom-snapshot-v1",
            "egress_class": ResearchScoutEgressClassV1.APPROVED_CUSTOM,
            "input_artifacts_sha256": custom_artifacts.computed_sha256(),
        }
    )
    response = _response_bytes(
        custom_request,
        custom_artifacts,
        provider={"provider_id": "custom", "model_id": "anthropic-compatible-v1"},
    )

    with pytest.raises(ResearchScoutAdapterError, match="typed schema"):
        ResearchScoutAdapterV1().accept_response(custom_request, custom_artifacts, response)


def test_adapter_has_no_runtime_or_authority_import_surface() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "autolean_builder" / "adapters" / "research_scout.py"
    )
    implementation = source.read_text(encoding="utf-8")

    assert "autolean_prover" not in implementation
    assert "autolean_control_plane" not in implementation
    assert "sqlite" not in implementation
    assert "subprocess" not in implementation
    assert "verify_submission" not in implementation
    assert "StatementContract" not in implementation
    assert "httpx" not in implementation
    assert "requests" not in implementation
    assert "socket" not in implementation
    assert "import danus" not in implementation.lower()
