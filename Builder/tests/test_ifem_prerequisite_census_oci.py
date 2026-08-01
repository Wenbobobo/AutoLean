from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import autolean_builder.ifem_prerequisite_census_oci as census_oci
import pytest
from autolean_builder.ifem_prerequisite_census import (
    DEFAULT_PLAN_PATH,
    IFEMPrerequisiteCensusResultV1,
    completed_unreviewed_result,
    load_ifem_prerequisite_census_plan,
    normalize_query_observation,
)
from autolean_builder.ifem_prerequisite_census_oci import (
    PROTOCOL,
    RECEIPT_SCHEMA,
    WORKER_ROOT,
    IFEMPrerequisiteCensusOCIError,
    IFEMPrerequisiteCensusOCIExecutionEnvelopeV1,
    IFEMPrerequisiteCensusWorkerBuildReceiptV1,
    _build_execution_envelope,
    _docker_build_command,
    _read_image_id,
    _staged_context_sha256,
    _verify_base_environment,
    _verify_base_layer_prefix,
    _verify_image_configuration,
    docker_query_command,
    load_worker_receipt,
    verify_execution_artifacts,
    verify_worker_image,
    worker_asset_hashes,
)
from autolean_contracts import canonical_json_bytes

ROOT = Path(__file__).resolve().parents[2]


def _raw_observation() -> bytes:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    nodes: list[dict[str, object]] = []
    for query_index, query in enumerate(plan.queries):
        candidates: list[dict[str, object]] = []
        for candidate_index, declaration in enumerate(query.candidate_declarations):
            present = query_index == 0 and candidate_index == 0
            candidates.append(
                {
                    "canonical_type": "Type" if present else None,
                    "declaration": declaration,
                    "declaration_kind": "inductive" if present else None,
                    "observed_axioms": [],
                    "present": present,
                }
            )
        nodes.append({"candidates": candidates, "node_id": query.node_id})
    payload = {
        "direct_imports": list(plan.environment.direct_imports),
        "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
        "lean_toolchain": plan.environment.lean_toolchain,
        "mathlib_revision": plan.environment.mathlib_revision,
        "nodes": nodes,
        "plan_content_sha256": plan.content_sha256,
        "protocol": plan.protocol,
        "schema_version": "autolean.ifem-prerequisite-query-raw.v1",
        "type_format": "autolean.lean-pp-expr.v1",
    }
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _write_model(path: Path, model: object) -> None:
    path.write_bytes(canonical_json_bytes(model) + b"\n")


def _receipt() -> IFEMPrerequisiteCensusWorkerBuildReceiptV1:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    assets = worker_asset_hashes()
    payload: dict[str, object] = {
        "base_image": ("sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab"),
        "base_image_id": (
            "sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab"
        ),
        "builder_freeze": "forbidden",
        "child_image": "sha256:" + "a" * 64,
        "dockerfile_sha256": assets["dockerfile_sha256"],
        "docker_builder": "classic",
        "docker_engine_version": "28.3.2",
        "evidence_state": "Partial",
        "helper_sha256": assets["helper_sha256"],
        "lake_manifest_sha256": plan.environment.lake_manifest_sha256,
        "lean_toolchain": plan.environment.lean_toolchain,
        "mathlib_revision": plan.environment.mathlib_revision,
        "parent_image": (
            "autolean/mathlib-worker@sha256:"
            "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
        ),
        "plan_content_sha256": plan.content_sha256,
        "prover_handoff": "forbidden",
        "schema_version": RECEIPT_SCHEMA,
        "semantic_classification": "not_authorized",
        "staged_context_sha256": _staged_context_sha256(WORKER_ROOT),
        "wrapper_sha256": assets["wrapper_sha256"],
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return IFEMPrerequisiteCensusWorkerBuildReceiptV1.model_validate(payload)


def test_worker_recipe_is_separate_compiled_and_network_isolated() -> None:
    dockerfile_path = ROOT / "Prover" / "worker" / "Dockerfile.ifem-prerequisite-census-query"
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    helper = (ROOT / "Prover" / "worker" / "AutoleanIFEMPrerequisiteCensusQuery.lean").read_text(
        encoding="utf-8"
    )
    wrapper = (ROOT / "Prover" / "worker" / "autolean-ifem-prerequisite-census-query").read_text(
        encoding="utf-8"
    )

    assert "supportInterpreter := true" in dockerfile
    assert "lake build autoleanIfemPrerequisiteCensusQuery" in dockerfile
    assert "FROM sha256:6c54c3600b2572d" in dockerfile
    assert "# syntax=" not in dockerfile
    assert "MATHLIB_NO_CACHE_ON_UPDATE=1" in dockerfile
    assert "AutoleanIFEMPinnedProfileQuery" not in dockerfile
    assert "Mathlib.Analysis.InnerProductSpace.LaxMilgram" in helper
    assert "Mathlib.Analysis.Normed.Operator.Bilinear" in helper
    assert '"classification"' not in helper
    assert "ifem-prerequisite-census-built-artifacts.sha256" in wrapper


def test_build_command_uses_iidfile_without_authoritative_tag(tmp_path: Path) -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    command = _docker_build_command(
        plan,
        worker_asset_hashes(),
        stage=tmp_path / "context",
        iidfile=tmp_path / "image.id",
    )

    assert command[:2] == ("docker", "build")
    assert command[command.index("--iidfile") + 1] == str(tmp_path / "image.id")
    assert "--tag" not in command
    assert "-t" not in command


def test_iidfile_requires_one_exact_image_id(tmp_path: Path) -> None:
    iidfile = tmp_path / "image.id"
    iidfile.write_text("sha256:" + "a" * 64 + "\n", encoding="utf-8")
    assert _read_image_id(iidfile) == "sha256:" + "a" * 64

    iidfile.write_text("sha256:" + "a" * 64 + "\nextra\n", encoding="utf-8")
    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="one exact image ID"):
        _read_image_id(iidfile)


def test_base_environment_must_match_the_frozen_plan() -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    labels = {
        "org.autolean.ifem.parent-image": (
            "autolean/mathlib-worker@sha256:"
            "3237192cf627a05367c75d46e61ec9034fefe43a4fd0c06139e38c80358648d6"
        ),
        "org.autolean.ifem.profile-protocol": "autolean.ifem-pinned-profile-query.v1",
        "org.autolean.mathlib.revision": plan.environment.mathlib_revision,
        "org.autolean.mathlib.lake-manifest.sha256": plan.environment.lake_manifest_sha256,
    }
    inspected: dict[str, object] = {
        "Config": {"Labels": labels},
        "Id": ("sha256:6c54c3600b2572ddcabae024a3a8b6c533c3defa6d4bda31c90408cb4c61f0ab"),
    }

    _verify_base_environment(plan, inspected)
    labels["org.autolean.mathlib.revision"] = "0" * 40
    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="environment"):
        _verify_base_environment(plan, inspected)


def test_worker_receipt_loader_rejects_duplicate_keys(tmp_path: Path) -> None:
    receipt = _receipt()
    rendered = canonical_json_bytes(receipt) + b"\n"
    duplicate = b'{"base_image":"' + receipt.base_image.encode("ascii") + b'",' + rendered[1:]
    path = tmp_path / "receipt.json"
    path.write_bytes(duplicate)

    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="duplicate JSON key"):
        load_worker_receipt(path)


def test_docker_command_has_exact_21_node_plan_and_no_mount() -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    command = docker_query_command(plan, _receipt())

    assert command[:2] == ("docker", "run")
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert "--cap-drop" in command
    assert "--mount" not in command
    assert "--volume" not in command
    assert command[command.index("--protocol") + 1] == PROTOCOL
    raw_queries = command[command.index("--queries-json") + 1]
    queries = json.loads(raw_queries)
    assert len(queries) == 21
    assert tuple(item["nodeId"] for item in queries) == tuple(
        query.node_id for query in plan.queries
    )
    assert tuple(tuple(item["declarations"]) for item in queries) == tuple(
        query.candidate_declarations for query in plan.queries
    )


def test_worker_receipt_is_self_hashing_and_keeps_authority_closed() -> None:
    receipt = _receipt()
    assert receipt.computed_content_sha256() == receipt.content_sha256
    assert receipt.evidence_state == "Partial"
    assert receipt.builder_freeze == "forbidden"
    assert receipt.prover_handoff == "forbidden"
    assert receipt.semantic_classification == "not_authorized"

    payload = receipt.model_dump(mode="json")
    payload["helper_sha256"] = "c" * 64
    with pytest.raises(ValueError, match="content hash"):
        IFEMPrerequisiteCensusWorkerBuildReceiptV1.model_validate(payload)


def test_image_verifier_rejects_runtime_or_label_drift() -> None:
    receipt = _receipt()
    labels = {"org.autolean.ifem.census.protocol": PROTOCOL}
    inspected: dict[str, object] = {
        "Config": {"Labels": labels, "User": "65532:65532", "WorkingDir": "/work"},
        "Id": receipt.child_image,
    }
    _verify_image_configuration(inspected, child_image=receipt.child_image, labels=labels)

    inspected["Config"] = {"Labels": labels, "User": "0:0", "WorkingDir": "/work"}
    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="runtime identity"):
        _verify_image_configuration(inspected, child_image=receipt.child_image, labels=labels)


def test_base_layer_verifier_rejects_wrong_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "autolean_builder.ifem_prerequisite_census_oci._inspect_image",
        lambda _image: {"RootFS": {"Layers": ["base-a", "base-b"]}},
    )
    _verify_base_layer_prefix({"RootFS": {"Layers": ["base-a", "base-b", "child-c"]}})
    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="fixed base"):
        _verify_base_layer_prefix({"RootFS": {"Layers": ["base-a", "wrong", "child-c"]}})


def test_verifier_recomputes_staged_context_hash() -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    payload = _receipt().model_dump(mode="json")
    payload["staged_context_sha256"] = "c" * 64
    payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes({k: v for k, v in payload.items() if k != "content_sha256"})
    ).hexdigest()
    receipt = IFEMPrerequisiteCensusWorkerBuildReceiptV1.model_validate(payload)

    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="frozen plan"):
        verify_worker_image(plan, receipt)


def test_execution_envelope_is_self_hashing_and_closes_authority() -> None:
    payload: dict[str, object] = {
        "builder_freeze": "forbidden",
        "child_image": "sha256:" + "a" * 64,
        "evidence_state": "Partial",
        "observation_content_sha256": "b" * 64,
        "prover_handoff": "forbidden",
        "query_argv_sha256": "c" * 64,
        "raw_stdout_sha256": "d" * 64,
        "result_content_sha256": "e" * 64,
        "schema_version": "autolean.ifem-prerequisite-census-oci-execution-envelope.v1",
        "semantic_classification": "not_authorized",
        "worker_receipt_content_sha256": "f" * 64,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    envelope = IFEMPrerequisiteCensusOCIExecutionEnvelopeV1.model_validate(payload)
    assert envelope.evidence_state == "Partial"
    assert envelope.builder_freeze == "forbidden"
    assert envelope.prover_handoff == "forbidden"

    payload["raw_stdout_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="content hash"):
        IFEMPrerequisiteCensusOCIExecutionEnvelopeV1.model_validate(payload)


def test_execution_replay_binds_raw_observation_result_and_unknown_only_policy(
    tmp_path: Path,
) -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    receipt = _receipt()
    raw_stdout = _raw_observation()
    observation = normalize_query_observation(
        raw_stdout.decode("utf-8").strip(),
        plan=plan,
        query_source_sha256=receipt.helper_sha256,
    )
    result = completed_unreviewed_result(plan, observation, plan_path=DEFAULT_PLAN_PATH)
    execution = _build_execution_envelope(
        plan,
        receipt,
        raw_stdout=raw_stdout,
        observation=observation,
        result=result,
    )
    raw_path = tmp_path / "raw.jsonl"
    observation_path = tmp_path / "observation.json"
    result_path = tmp_path / "result.json"
    execution_path = tmp_path / "execution.json"
    raw_path.write_bytes(raw_stdout)
    _write_model(observation_path, observation)
    _write_model(result_path, result)
    _write_model(execution_path, execution)

    verify_execution_artifacts(
        plan,
        receipt,
        plan_path=DEFAULT_PLAN_PATH,
        raw_stdout_path=raw_path,
        observation_path=observation_path,
        result_path=result_path,
        execution_path=execution_path,
        verify_image=False,
    )

    result_payload = result.model_dump(mode="json")
    node_results = cast(list[dict[str, object]], result_payload["node_results"])
    first_evidence = cast(dict[str, object], node_results[0]["evidence"])
    first_declaration = plan.queries[0].candidate_declarations[0]
    first_evidence.update(
        {
            "canonical_type_sha256s": [hashlib.sha256(b"Type").hexdigest()],
            "classification": "direct",
            "explicit_unknown_reason": None,
            "mapped_declarations": [first_declaration],
            "query_observation_sha256": observation.content_sha256,
            "semantic_review_sha256": "a" * 64,
        }
    )
    result_payload.pop("content_sha256")
    result_payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(result_payload)
    ).hexdigest()
    classified = IFEMPrerequisiteCensusResultV1.model_validate(result_payload)
    classified_execution = _build_execution_envelope(
        plan,
        receipt,
        raw_stdout=raw_stdout,
        observation=observation,
        result=classified,
    )
    _write_model(result_path, classified)
    _write_model(execution_path, classified_execution)

    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="unknown-only"):
        verify_execution_artifacts(
            plan,
            receipt,
            plan_path=DEFAULT_PLAN_PATH,
            raw_stdout_path=raw_path,
            observation_path=observation_path,
            result_path=result_path,
            execution_path=execution_path,
            verify_image=False,
        )


def test_image_backed_execution_replay_requires_byte_identical_rerun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    receipt = _receipt()
    raw_stdout = _raw_observation()
    observation = normalize_query_observation(
        raw_stdout.decode("utf-8").strip(),
        plan=plan,
        query_source_sha256=receipt.helper_sha256,
    )
    result = completed_unreviewed_result(plan, observation, plan_path=DEFAULT_PLAN_PATH)
    execution = _build_execution_envelope(
        plan,
        receipt,
        raw_stdout=raw_stdout,
        observation=observation,
        result=result,
    )
    raw_path = tmp_path / "raw.jsonl"
    observation_path = tmp_path / "observation.json"
    result_path = tmp_path / "result.json"
    execution_path = tmp_path / "execution.json"
    raw_path.write_bytes(raw_stdout)
    _write_model(observation_path, observation)
    _write_model(result_path, result)
    _write_model(execution_path, execution)

    def fake_verify_worker_image(_plan: object, _receipt: object) -> None:
        return None

    def matching_run(
        _argv: Sequence[str],
        *,
        capture_output: bool = False,
        environment: dict[str, str] | None = None,
        timeout: int = 1800,
    ) -> subprocess.CompletedProcess[str]:
        del environment, timeout
        assert capture_output
        return subprocess.CompletedProcess([], 0, raw_stdout.decode("utf-8"), "")

    monkeypatch.setattr(census_oci, "verify_worker_image", fake_verify_worker_image)
    monkeypatch.setattr(census_oci, "_run_docker", matching_run)
    verify_execution_artifacts(
        plan,
        receipt,
        plan_path=DEFAULT_PLAN_PATH,
        raw_stdout_path=raw_path,
        observation_path=observation_path,
        result_path=result_path,
        execution_path=execution_path,
    )

    def drifted_run(
        _argv: Sequence[str],
        *,
        capture_output: bool = False,
        environment: dict[str, str] | None = None,
        timeout: int = 1800,
    ) -> subprocess.CompletedProcess[str]:
        del environment, timeout
        assert capture_output
        return subprocess.CompletedProcess([], 0, raw_stdout.decode("utf-8") + " ", "")

    monkeypatch.setattr(census_oci, "_run_docker", drifted_run)
    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="does not reproduce"):
        verify_execution_artifacts(
            plan,
            receipt,
            plan_path=DEFAULT_PLAN_PATH,
            raw_stdout_path=raw_path,
            observation_path=observation_path,
            result_path=result_path,
            execution_path=execution_path,
        )


def test_execution_replay_rejects_duplicate_envelope_keys(tmp_path: Path) -> None:
    plan = load_ifem_prerequisite_census_plan(DEFAULT_PLAN_PATH)
    receipt = _receipt()
    raw_stdout = _raw_observation()
    observation = normalize_query_observation(
        raw_stdout.decode("utf-8").strip(),
        plan=plan,
        query_source_sha256=receipt.helper_sha256,
    )
    result = completed_unreviewed_result(plan, observation, plan_path=DEFAULT_PLAN_PATH)
    execution = _build_execution_envelope(
        plan,
        receipt,
        raw_stdout=raw_stdout,
        observation=observation,
        result=result,
    )
    raw_path = tmp_path / "raw.jsonl"
    observation_path = tmp_path / "observation.json"
    result_path = tmp_path / "result.json"
    execution_path = tmp_path / "execution.json"
    raw_path.write_bytes(raw_stdout)
    _write_model(observation_path, observation)
    _write_model(result_path, result)
    rendered = canonical_json_bytes(execution) + b"\n"
    execution_path.write_bytes(b'{"builder_freeze":"forbidden",' + rendered[1:])

    with pytest.raises(IFEMPrerequisiteCensusOCIError, match="duplicate JSON key"):
        verify_execution_artifacts(
            plan,
            receipt,
            plan_path=DEFAULT_PLAN_PATH,
            raw_stdout_path=raw_path,
            observation_path=observation_path,
            result_path=result_path,
            execution_path=execution_path,
            verify_image=False,
        )
