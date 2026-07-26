"""Cross-component admission checks for Builder's internal canonical-type record."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import cast

from autolean_contracts import (
    DigestV1,
    FormalizationTaskBundleV1,
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
)

from .errors import InvalidTransition
from .events import JsonObject

_CHECK_FIELDS = frozenset({"check_name", "authority", "passed", "evidence"})
_ENVELOPE_FIELDS = frozenset({"schema_version", "record", "record_hash"})
_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "claim",
        "definitional_equivalence_claimed",
        "semantic_equivalence_claimed",
        "promotion_authority",
        "contract_id",
        "revision",
        "draft_contract_hash",
        "source_hash",
        "generation_task_hash",
        "selected_statement_hash",
        "environment_hash",
        "expected_elaborated_type_hash",
        "environment",
        "reference",
        "candidates",
    }
)
_ENVIRONMENT_FIELDS = frozenset(
    {
        "assurance",
        "adapter_id",
        "image",
        "worker_image_digest",
        "lean_version",
        "mathlib_revision",
        "lake_manifest_sha256",
        "type_format",
        "query_schema_version",
        "query_protocol",
        "query_identity_sha256",
        "build_receipt_canonical_sha256",
        "execution_policy_sha256",
        "source_inputs_sha256",
        "source_rendering_profile",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "subject_id",
        "statement_source_hash",
        "declaration",
        "canonical_type",
        "canonical_type_hash",
        "canonical_type_sha256",
        "environment_facts_sha256",
        "query",
    }
)
_QUERY_FIELDS = frozenset(
    {
        "query_output_canonical_json",
        "query_output_sha256",
        "source_snapshot_sha256",
        "sealed_candidate_sha256",
        "candidate_direct_imports_sha256",
        "module_import_closure_sha256",
        "observed_axioms",
        "observed_axioms_sha256",
    }
)
_QUERY_SHA256_FIELDS = frozenset(
    {
        "query_output_sha256",
        "source_snapshot_sha256",
        "sealed_candidate_sha256",
        "candidate_direct_imports_sha256",
        "module_import_closure_sha256",
        "observed_axioms_sha256",
    }
)
_DIGEST_FIELDS = frozenset({"schema_version", "kind", "algorithm", "value"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ASSURANCE_PROFILES = {
    "scripted_fake": (
        "autolean_builder.testing.ScriptedCanonicalTypeQuery",
        "autolean.scripted-canonical-query.v1",
        "autolean.scripted-canonical-query.v1",
        "autolean.scripted-header.v1",
    ),
    "local_oci_prefreeze": (
        "scripts.oci_mathlib_worker.query_declarations",
        "autolean.mathlib-declaration-query-evidence.v1",
        "autolean.mathlib-declaration-query.v1",
        "autolean.declaration-type-observation.v1",
    ),
}


@dataclass(frozen=True, slots=True)
class CanonicalTypeAdmission:
    assurance: str
    promotion_authority: bool = False


def validate_canonical_type_check(
    bundle: FormalizationTaskBundleV1,
    artifact: JsonObject,
    *,
    task: JsonObject,
    generation_task_hash: DigestV1,
    allow_test_only_non_authoritative: bool,
) -> CanonicalTypeAdmission:
    check = _unique_canonical_check(_list(artifact, "automatic_checks"))
    envelope = _canonical_json_object(_text(check, "evidence"))
    _exact(envelope, _ENVELOPE_FIELDS, "Builder canonical type check envelope")
    if _text(envelope, "schema_version") != "autolean.builder-canonical-type-check.v1":
        raise InvalidTransition("Builder canonical type check envelope has an unexpected schema")
    record = _object(envelope.get("record"), "Builder canonical type record")
    record_hash = _digest(envelope, "record_hash", HashKindV1.FREEZE_EVIDENCE)
    if record_hash != digest_bytes(HashKindV1.FREEZE_EVIDENCE, canonical_json_bytes(record)):
        raise InvalidTransition("Builder canonical type record hash is inconsistent")
    _exact(record, _RECORD_FIELDS, "Builder canonical type record")
    if (
        _text(record, "schema_version") != "autolean.builder-canonical-type-gate.v1"
        or _text(record, "claim") != "exact_canonical_printer_text_identity"
        or record.get("definitional_equivalence_claimed") is not False
        or record.get("semantic_equivalence_claimed") is not False
        or record.get("promotion_authority") is not False
    ):
        raise InvalidTransition("Builder canonical type record changes or overstates its claim")

    formal = bundle.contract.formal
    if formal.elaborated_type is None or formal.elaborated_type_hash is None:
        raise InvalidTransition("Builder canonical type record requires an elaborated contract")
    expected_digests = {
        "draft_contract_hash": _digest(task, "draft_contract_hash", HashKindV1.CONTRACT),
        "source_hash": _digest(task, "source_hash", HashKindV1.SOURCE_BYTES),
        "generation_task_hash": generation_task_hash,
        "selected_statement_hash": formal.statement_source_hash,
        "environment_hash": formal.environment.environment_hash,
        "expected_elaborated_type_hash": formal.elaborated_type_hash,
    }
    for key, expected in expected_digests.items():
        if _digest(record, key, expected.kind) != expected:
            raise InvalidTransition(f"Builder canonical type record has a different {key}")
    if (
        _text(record, "contract_id") != bundle.contract.contract_id.value
        or _integer(record, "revision") != bundle.contract.revision
    ):
        raise InvalidTransition("Builder canonical type record targets another contract revision")

    environment = _object(record.get("environment"), "Builder canonical type environment")
    assurance, environment_hash = _validate_environment(
        bundle,
        environment,
        allow_test_only_non_authoritative=allow_test_only_non_authoritative,
    )
    declaration = f"{formal.namespace}.{formal.declaration_name}"
    _validate_observation(
        _object(record.get("reference"), "Builder canonical type reference"),
        assurance=assurance,
        environment=environment,
        subject_id="contract-selected-reference",
        statement_source=formal.lean_statement_source,
        statement_source_hash=formal.statement_source_hash,
        declaration=declaration,
        imports_allowlist=tuple(formal.imports_allowlist),
        canonical_type=formal.elaborated_type,
        canonical_type_hash=formal.elaborated_type_hash,
        environment_hash=environment_hash,
    )

    candidates = _list(artifact, "candidates")
    observations = _list(record, "candidates")
    if len(candidates) != len(observations):
        raise InvalidTransition("Builder canonical type record has a different candidate count")
    candidate_ids: list[str] = []
    for index, (candidate_value, observation_value) in enumerate(
        zip(candidates, observations, strict=True)
    ):
        candidate = _object(
            candidate_value,
            f"Builder fidelity artifact candidate {index}",
        )
        candidate_id = _text(candidate, "candidate_id")
        candidate_ids.append(candidate_id)
        _validate_observation(
            _object(
                observation_value,
                f"Builder canonical type candidate {index}",
            ),
            assurance=assurance,
            environment=environment,
            subject_id=candidate_id,
            statement_source=_text(candidate, "lean_statement_source"),
            statement_source_hash=digest_text(
                HashKindV1.STATEMENT_SOURCE,
                _text(candidate, "lean_statement_source"),
            ),
            declaration=declaration,
            imports_allowlist=tuple(formal.imports_allowlist),
            canonical_type=formal.elaborated_type,
            canonical_type_hash=formal.elaborated_type_hash,
            environment_hash=environment_hash,
        )
    if len(candidate_ids) != len(set(candidate_ids)):
        raise InvalidTransition("Builder canonical type record repeats a candidate identifier")
    return CanonicalTypeAdmission(assurance=assurance)


def _unique_canonical_check(values: list[object]) -> JsonObject:
    matches: list[JsonObject] = []
    for value in values:
        check = _object(value, "Builder fidelity automatic check")
        if check.get("check_name") == "canonical_elaborated_type_identity":
            matches.append(check)
    if len(matches) != 1:
        raise InvalidTransition(
            "Builder fidelity artifact requires exactly one canonical type check"
        )
    check = matches[0]
    _exact(check, _CHECK_FIELDS, "Builder canonical type check")
    if _text(check, "authority") != "automatic" or check.get("passed") is not True:
        raise InvalidTransition("Builder canonical type check is not an automatic pass")
    return check


def _validate_environment(
    bundle: FormalizationTaskBundleV1,
    environment: JsonObject,
    *,
    allow_test_only_non_authoritative: bool,
) -> tuple[str, str]:
    _exact(environment, _ENVIRONMENT_FIELDS, "Builder canonical type environment")
    assurance = _text(environment, "assurance")
    if assurance not in _ASSURANCE_PROFILES:
        raise InvalidTransition("Builder canonical type assurance is unsupported")
    if not allow_test_only_non_authoritative:
        raise InvalidTransition("non-authoritative canonical type evidence cannot be registered")
    formal_environment = bundle.contract.formal.environment
    worker_digest = _text(environment, "worker_image_digest")
    expected_manifest = (
        None
        if formal_environment.lake_manifest_hash is None
        else formal_environment.lake_manifest_hash.value
    )
    if (
        _text(environment, "lean_version") != formal_environment.lean_version
        or _text(environment, "mathlib_revision") != formal_environment.mathlib_revision
        or worker_digest != formal_environment.verifier_execution_policy.worker_image_digest
        or not _text(environment, "image").endswith(f"@{worker_digest}")
        or environment.get("lake_manifest_sha256") != expected_manifest
        or _text(environment, "type_format") != "autolean.lean-pp-expr.v1"
    ):
        raise InvalidTransition(
            "Builder canonical type environment differs from the frozen contract"
        )
    observed_profile = tuple(
        _text(environment, key)
        for key in (
            "adapter_id",
            "query_schema_version",
            "query_protocol",
            "source_rendering_profile",
        )
    )
    if observed_profile != _ASSURANCE_PROFILES[assurance]:
        raise InvalidTransition(
            "Builder canonical type assurance differs from its closed execution profile"
        )
    for key in (
        "query_identity_sha256",
        "build_receipt_canonical_sha256",
        "execution_policy_sha256",
        "source_inputs_sha256",
    ):
        _sha256(environment, key)
    return assurance, hashlib.sha256(canonical_json_bytes(environment)).hexdigest()


def _validate_observation(
    observation: JsonObject,
    *,
    assurance: str,
    environment: JsonObject,
    subject_id: str,
    statement_source: str,
    statement_source_hash: DigestV1,
    declaration: str,
    imports_allowlist: tuple[str, ...],
    canonical_type: str,
    canonical_type_hash: DigestV1,
    environment_hash: str,
) -> None:
    _exact(observation, _OBSERVATION_FIELDS, "Builder canonical type observation")
    canonical_type_value = _text(observation, "canonical_type")
    observed_type_hash = _digest(
        observation,
        "canonical_type_hash",
        HashKindV1.ELABORATED_TYPE,
    )
    if (
        _text(observation, "subject_id") != subject_id
        or _text(observation, "declaration") != declaration
        or canonical_type_value != canonical_type
        or _sha256(observation, "canonical_type_sha256")
        != hashlib.sha256(canonical_type_value.encode("utf-8")).hexdigest()
        or _sha256(observation, "environment_facts_sha256") != environment_hash
        or _digest(
            observation,
            "statement_source_hash",
            HashKindV1.STATEMENT_SOURCE,
        )
        != statement_source_hash
        or observed_type_hash != canonical_type_hash
        or observed_type_hash != digest_text(HashKindV1.ELABORATED_TYPE, canonical_type_value)
    ):
        raise InvalidTransition(
            "Builder canonical type observation differs from its Builder inputs"
        )
    query = _object(observation.get("query"), "Builder canonical type query facts")
    _exact(query, _QUERY_FIELDS, "Builder canonical type query facts")
    for key in _QUERY_SHA256_FIELDS:
        _sha256(query, key)
    query_output = _text(query, "query_output_canonical_json")
    _canonical_json_object(query_output)
    if (
        _sha256(query, "query_output_sha256")
        != hashlib.sha256(query_output.encode("ascii")).hexdigest()
    ):
        raise InvalidTransition("Builder canonical query output hash is inconsistent")
    axioms = _texts(query, "observed_axioms")
    if axioms != tuple(sorted(set(axioms))) or any(item != item.strip() for item in axioms):
        raise InvalidTransition("Builder canonical type observed axioms are invalid")
    expected_axioms_sha256 = hashlib.sha256(canonical_json_bytes(axioms) + b"\n").hexdigest()
    if _sha256(query, "observed_axioms_sha256") != expected_axioms_sha256:
        raise InvalidTransition("Builder canonical type observed axiom hash is inconsistent")
    _validate_raw_query_output(
        _canonical_json_object(query_output),
        assurance=assurance,
        environment=environment,
        subject_id=subject_id,
        statement_source=statement_source,
        statement_source_hash=statement_source_hash,
        declaration=declaration,
        imports_allowlist=imports_allowlist,
        canonical_type=canonical_type_value,
        canonical_type_sha256=_sha256(observation, "canonical_type_sha256"),
        query=query,
        observed_axioms=axioms,
    )


def _validate_raw_query_output(
    document: JsonObject,
    *,
    assurance: str,
    environment: JsonObject,
    subject_id: str,
    statement_source: str,
    statement_source_hash: DigestV1,
    declaration: str,
    imports_allowlist: tuple[str, ...],
    canonical_type: str,
    canonical_type_sha256: str,
    query: JsonObject,
    observed_axioms: tuple[str, ...],
) -> None:
    if assurance == "scripted_fake":
        _validate_scripted_raw_query_output(
            document,
            subject_id=subject_id,
            statement_source=statement_source,
            statement_source_hash=statement_source_hash,
            declaration=declaration,
            imports_allowlist=imports_allowlist,
            canonical_type=canonical_type,
            canonical_type_sha256=canonical_type_sha256,
            query=query,
            observed_axioms=observed_axioms,
        )
        return
    if assurance == "local_oci_prefreeze":
        _validate_local_oci_raw_query_output(
            document,
            environment=environment,
            subject_id=subject_id,
            statement_source=statement_source,
            declaration=declaration,
            imports_allowlist=imports_allowlist,
            canonical_type=canonical_type,
            canonical_type_sha256=canonical_type_sha256,
            query=query,
            observed_axioms=observed_axioms,
        )
        return
    raise InvalidTransition("Builder canonical type assurance is unsupported")


_SCRIPTED_RAW_FIELDS = frozenset(
    {
        "canonical_type",
        "canonical_type_sha256",
        "declaration",
        "imports_allowlist",
        "observed_axioms",
        "observed_axioms_sha256",
        "schema_version",
        "source_snapshot_sha256",
        "statement_source_hash",
        "subject_id",
    }
)
_LOCAL_RAW_FIELDS = frozenset(
    {
        "build_receipt_canonical_sha256",
        "execution_policy",
        "execution_policy_sha256",
        "image",
        "observation",
        "schema_version",
        "sealed_candidate_sha256",
        "source_inputs_sha256",
        "source_snapshot_sha256",
    }
)
_LOCAL_OBSERVATION_FIELDS = frozenset(
    {
        "candidate_direct_imports",
        "candidate_direct_imports_sha256",
        "declarations",
        "image_identity",
        "module_import_closure",
        "module_import_closure_sha256",
    }
)
_LOCAL_DECLARATION_FIELDS = frozenset(
    {
        "canonical_type",
        "canonical_type_sha256",
        "declaration",
        "observed_axioms",
        "observed_axioms_sha256",
    }
)
_LOCAL_EXECUTION_POLICY_FIELDS = frozenset(
    {"container_policy", "image", "phases", "schema_version"}
)


def _validate_scripted_raw_query_output(
    document: JsonObject,
    *,
    subject_id: str,
    statement_source: str,
    statement_source_hash: DigestV1,
    declaration: str,
    imports_allowlist: tuple[str, ...],
    canonical_type: str,
    canonical_type_sha256: str,
    query: JsonObject,
    observed_axioms: tuple[str, ...],
) -> None:
    _exact(document, _SCRIPTED_RAW_FIELDS, "Builder scripted canonical query output")
    if (
        _text(document, "schema_version") != "autolean.scripted-canonical-query-output.v1"
        or _text(document, "subject_id") != subject_id
        or _digest(document, "statement_source_hash", HashKindV1.STATEMENT_SOURCE)
        != statement_source_hash
        or _text(document, "declaration") != declaration
        or _text(document, "canonical_type") != canonical_type
        or _sha256(document, "canonical_type_sha256") != canonical_type_sha256
        or tuple(_texts(document, "imports_allowlist")) != imports_allowlist
        or _sha256(document, "source_snapshot_sha256")
        != hashlib.sha256(statement_source.encode("utf-8")).hexdigest()
        or _sha256(document, "source_snapshot_sha256") != _sha256(query, "source_snapshot_sha256")
        or tuple(_texts(document, "observed_axioms")) != observed_axioms
        or _sha256(document, "observed_axioms_sha256") != _sha256(query, "observed_axioms_sha256")
    ):
        raise InvalidTransition("Builder scripted raw query output is detached")


def _validate_local_oci_raw_query_output(
    document: JsonObject,
    *,
    environment: JsonObject,
    subject_id: str,
    statement_source: str,
    declaration: str,
    imports_allowlist: tuple[str, ...],
    canonical_type: str,
    canonical_type_sha256: str,
    query: JsonObject,
    observed_axioms: tuple[str, ...],
) -> None:
    _exact(document, _LOCAL_RAW_FIELDS, "Builder local OCI canonical query output")
    raw_observation = _object(document.get("observation"), "Builder local OCI observation")
    _exact(raw_observation, _LOCAL_OBSERVATION_FIELDS, "Builder local OCI observation")
    declarations = _list(raw_observation, "declarations")
    if len(declarations) != 1:
        raise InvalidTransition("Builder local OCI query must contain one declaration")
    raw_declaration = _object(declarations[0], "Builder local OCI declaration")
    _exact(raw_declaration, _LOCAL_DECLARATION_FIELDS, "Builder local OCI declaration")
    execution_policy = _object(
        document.get("execution_policy"), "Builder local OCI execution policy"
    )
    _exact(execution_policy, _LOCAL_EXECUTION_POLICY_FIELDS, "Builder local OCI execution policy")
    image_identity = _object(raw_observation.get("image_identity"), "Builder local OCI identity")
    phases = _list(execution_policy, "phases")
    query_phases = [
        phase for phase in phases if isinstance(phase, dict) and phase.get("name") == "query"
    ]
    if len(query_phases) != 1:
        raise InvalidTransition("Builder local OCI execution policy has no unique query phase")
    query_phase = _object(query_phases[0], "Builder local OCI query phase")
    direct_imports = tuple(_texts(raw_observation, "candidate_direct_imports"))
    import_closure = tuple(_texts(raw_observation, "module_import_closure"))
    expected_snapshot = _render_oci_type_query_source_hash(
        statement_source=statement_source,
        namespace=declaration.rpartition(".")[0],
        imports_allowlist=imports_allowlist,
    )
    if (
        _text(document, "schema_version") != _text(environment, "query_schema_version")
        or _text(document, "image") != _text(environment, "image")
        or _sha256(document, "build_receipt_canonical_sha256")
        != _sha256(environment, "build_receipt_canonical_sha256")
        or _sha256(document, "execution_policy_sha256")
        != _sha256(environment, "execution_policy_sha256")
        or _sha256(document, "source_inputs_sha256") != _sha256(environment, "source_inputs_sha256")
        or _sha256(document, "source_snapshot_sha256") != expected_snapshot
        or _sha256(document, "source_snapshot_sha256") != _sha256(query, "source_snapshot_sha256")
        or _sha256(document, "sealed_candidate_sha256") != _sha256(query, "sealed_candidate_sha256")
        or _text(execution_policy, "image") != _text(environment, "image")
        or _text(execution_policy, "schema_version")
        != "autolean.mathlib-declaration-execution-policy.v1"
        or query_phase.get("declarations") != [declaration]
        or query_phase.get("protocol") != _text(environment, "query_protocol")
        or hashlib.sha256(canonical_json_bytes(execution_policy) + b"\n").hexdigest()
        != _sha256(environment, "execution_policy_sha256")
        or hashlib.sha256(canonical_json_bytes(image_identity)).hexdigest()
        != _sha256(environment, "query_identity_sha256")
        or _sha256(raw_observation, "candidate_direct_imports_sha256")
        != _sha256(query, "candidate_direct_imports_sha256")
        or hashlib.sha256(canonical_json_bytes(direct_imports) + b"\n").hexdigest()
        != _sha256(query, "candidate_direct_imports_sha256")
        or _sha256(raw_observation, "module_import_closure_sha256")
        != _sha256(query, "module_import_closure_sha256")
        or hashlib.sha256(canonical_json_bytes(import_closure) + b"\n").hexdigest()
        != _sha256(query, "module_import_closure_sha256")
        or not set(imports_allowlist) <= set(direct_imports)
        or not set(direct_imports) <= {*imports_allowlist, "Init"}
        or "Candidate" not in import_closure
        or _text(raw_declaration, "declaration") != declaration
        or _text(raw_declaration, "canonical_type") != canonical_type
        or _sha256(raw_declaration, "canonical_type_sha256") != canonical_type_sha256
        or tuple(_texts(raw_declaration, "observed_axioms")) != observed_axioms
        or _sha256(raw_declaration, "observed_axioms_sha256")
        != _sha256(query, "observed_axioms_sha256")
    ):
        raise InvalidTransition(f"Builder local OCI raw query output is detached from {subject_id}")


_DECLARATION_HEADER_RE = re.compile(r"\A(?:theorem|lemma)\b")


def _render_oci_type_query_source_hash(
    *,
    statement_source: str,
    namespace: str,
    imports_allowlist: tuple[str, ...],
) -> str:
    statement = statement_source
    if ":=" in statement:
        carrier = statement
    else:
        match = _DECLARATION_HEADER_RE.match(statement)
        if match is None:
            raise InvalidTransition("Builder local OCI statement is not a theorem or lemma")
        carrier = f"axiom{statement[match.end() :]}"
    imports = [f"import {name}" for name in imports_allowlist]
    lines = [*imports]
    if imports:
        lines.append("")
    lines.extend((f"namespace {namespace}", "", carrier, ""))
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _canonical_json_object(value: str) -> JsonObject:
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise InvalidTransition("Builder canonical type evidence is not strict JSON") from error
    result = _object(parsed, "Builder canonical type evidence")
    if canonical_json_bytes(result) != value.encode("utf-8"):
        raise InvalidTransition("Builder canonical type evidence is not canonically serialized")
    return result


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _exact(value: JsonObject, expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        raise InvalidTransition(f"{label} has unexpected or missing fields")


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise InvalidTransition(f"{label} must be a JSON object")
    return cast(JsonObject, value)


def _list(value: JsonObject, key: str) -> list[object]:
    result = value.get(key)
    if not isinstance(result, list):
        raise InvalidTransition(f"Builder canonical type {key} must be a list")
    items: list[object] = []
    items.extend(result)
    return items


def _text(value: JsonObject, key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise InvalidTransition(f"Builder canonical type {key} must be text")
    return result


def _texts(value: JsonObject, key: str) -> tuple[str, ...]:
    result = _list(value, key)
    if not all(isinstance(item, str) and item for item in result):
        raise InvalidTransition(f"Builder canonical type {key} must contain text")
    return tuple(cast(str, item) for item in result)


def _integer(value: JsonObject, key: str) -> int:
    result = value.get(key)
    if isinstance(result, bool) or not isinstance(result, int):
        raise InvalidTransition(f"Builder canonical type {key} must be an integer")
    return result


def _sha256(value: JsonObject, key: str) -> str:
    result = _text(value, key)
    if not _SHA256_RE.fullmatch(result):
        raise InvalidTransition(f"Builder canonical type {key} is not SHA-256")
    return result


def _digest(value: JsonObject, key: str, kind: HashKindV1) -> DigestV1:
    raw = _object(value.get(key), f"Builder canonical type {key}")
    _exact(raw, _DIGEST_FIELDS, f"Builder canonical type {key}")
    try:
        result = DigestV1.model_validate(raw)
    except ValueError as error:
        raise InvalidTransition(f"Builder canonical type {key} is invalid") from error
    if result.kind is not kind:
        raise InvalidTransition(f"Builder canonical type {key} has an unexpected kind")
    return result
