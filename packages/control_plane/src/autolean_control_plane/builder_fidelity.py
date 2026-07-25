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
        "query_output_sha256",
        "source_snapshot_sha256",
        "sealed_candidate_sha256",
        "candidate_direct_imports_sha256",
        "module_import_closure_sha256",
        "observed_axioms",
        "observed_axioms_sha256",
    }
)
_DIGEST_FIELDS = frozenset({"schema_version", "kind", "algorithm", "value"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NON_AUTHORITATIVE_ASSURANCES = frozenset({"scripted_fake", "local_oci_prefreeze"})


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
        subject_id="contract-selected-reference",
        statement_source_hash=formal.statement_source_hash,
        declaration=declaration,
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
            subject_id=candidate_id,
            statement_source_hash=digest_text(
                HashKindV1.STATEMENT_SOURCE,
                _text(candidate, "lean_statement_source"),
            ),
            declaration=declaration,
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
    if assurance not in _NON_AUTHORITATIVE_ASSURANCES:
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
    for key in (
        "adapter_id",
        "query_schema_version",
        "query_protocol",
        "source_rendering_profile",
    ):
        _text(environment, key)
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
    subject_id: str,
    statement_source_hash: DigestV1,
    declaration: str,
    canonical_type: str,
    canonical_type_hash: DigestV1,
    environment_hash: str,
) -> None:
    _exact(observation, _OBSERVATION_FIELDS, "Builder canonical type observation")
    if (
        _text(observation, "subject_id") != subject_id
        or _text(observation, "declaration") != declaration
        or _text(observation, "canonical_type") != canonical_type
        or _sha256(observation, "canonical_type_sha256")
        != hashlib.sha256(canonical_type.encode("utf-8")).hexdigest()
        or _sha256(observation, "environment_facts_sha256") != environment_hash
        or _digest(
            observation,
            "statement_source_hash",
            HashKindV1.STATEMENT_SOURCE,
        )
        != statement_source_hash
        or _digest(
            observation,
            "canonical_type_hash",
            HashKindV1.ELABORATED_TYPE,
        )
        != canonical_type_hash
    ):
        raise InvalidTransition(
            "Builder canonical type observation differs from its Builder inputs"
        )
    query = _object(observation.get("query"), "Builder canonical type query facts")
    _exact(query, _QUERY_FIELDS, "Builder canonical type query facts")
    for key in _QUERY_FIELDS - {"observed_axioms"}:
        _sha256(query, key)
    axioms = _texts(query, "observed_axioms")
    if axioms != tuple(sorted(set(axioms))) or any(item != item.strip() for item in axioms):
        raise InvalidTransition("Builder canonical type observed axioms are invalid")


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
