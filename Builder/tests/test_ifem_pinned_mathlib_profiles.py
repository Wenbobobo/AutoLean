from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Sequence
from itertools import pairwise
from pathlib import Path

import autolean_builder.ifem_pinned_mathlib_profiles as profiles
import pytest
from autolean_builder.ifem_pinned_mathlib_profiles import (
    _BUILT_OLEAN_PATHS,
    DEFAULT_PLAN_PATH,
    PROTOCOL,
    WORKER_ROOT,
    IFEMPinnedMathlibProfileBuildReceiptV1,
    IFEMPinnedMathlibProfileObservationsV1,
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfilePublicSummaryV1,
    IFEMPinnedProfileError,
    _child_image_build_command,
    _child_image_tag,
    _expected_staged_context_sha256,
    _stage_child_build_context,
    build_ifem_pinned_mathlib_profile_plan,
    build_ifem_pinned_mathlib_profile_public_summary,
    completed_result,
    docker_query_command,
    load_ifem_pinned_mathlib_profile_plan,
    main,
    normalize_profile_observations,
    render_ifem_pinned_mathlib_profile_public_summary,
    validate_ifem_pinned_mathlib_profile_public_summary_bindings,
    validate_profile_observation_bindings,
    validate_profile_plan_bindings,
    write_model_once,
)
from autolean_contracts import canonical_json_bytes

CHILD_IMAGE = "sha256:" + "c" * 64


def _plan() -> IFEMPinnedMathlibProfilePlanV1:
    return load_ifem_pinned_mathlib_profile_plan(DEFAULT_PLAN_PATH)


def _receipt(plan: IFEMPinnedMathlibProfilePlanV1) -> IFEMPinnedMathlibProfileBuildReceiptV1:
    payload: dict[str, object] = {
        "authority": {
            "builder_freeze_authorized": False,
            "coverage_claim_authorized": False,
            "mathematical_mapping_authorized": False,
            "proof_submission_authorized": False,
            "prover_handoff_authorized": False,
            "semantic_classification_authorized": False,
        },
        "build_network": "none",
        "child_image": CHILD_IMAGE,
        "child_image_tag": _child_image_tag(plan),
        "dockerfile_sha256": plan.assets.dockerfile_sha256,
        "helper_sha256": plan.assets.helper_sha256,
        "parent_image": plan.environment.parent_image,
        "plan_content_sha256": plan.content_sha256,
        "protocol": PROTOCOL,
        "schema_version": "autolean.ifem-pinned-mathlib-profile-build-receipt.v1",
        "staged_context_sha256": _expected_staged_context_sha256(plan),
        "wrapper_sha256": plan.assets.wrapper_sha256,
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return IFEMPinnedMathlibProfileBuildReceiptV1.model_validate(payload)


def _raw_profile(plan: IFEMPinnedMathlibProfilePlanV1, profile_id: str) -> str:
    profile = next(item for item in plan.profiles if item.profile_id == profile_id)

    def absent(declaration: str) -> dict[str, object]:
        return {
            "canonical_type": None,
            "declaration": declaration,
            "declaration_kind": None,
            "observed_axioms": [],
            "origin_module": None,
            "present": False,
        }

    payload = {
        "built_olean_hashes": [
            {"path": path, "sha256": f"{index:x}" * 64}
            for index, path in enumerate(_BUILT_OLEAN_PATHS)
        ],
        "built_olean_manifest_sha256": "b" * 64,
        "declarations": [absent(name) for name in plan.candidate_declarations],
        "direct_imports": [profile.direct_import],
        "helper_sha256": plan.assets.helper_sha256,
        "loaded_module_closure": [profile.direct_import],
        "negative_control": absent(plan.negative_control),
        "profile_id": profile.profile_id,
        "schema_version": "autolean.ifem-pinned-profile-query-raw.v1",
        "type_format": "autolean.lean-pp-expr.v1",
        "wrapper_sha256": plan.assets.wrapper_sha256,
    }
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _image_inspect_payload(plan: IFEMPinnedMathlibProfilePlanV1) -> str:
    return json.dumps(
        [
            {
                "Config": {
                    "Labels": {
                        "org.autolean.ifem.parent-image": plan.environment.parent_image,
                        "org.autolean.ifem.profile-protocol": PROTOCOL,
                    },
                    "User": "65532:65532",
                    "WorkingDir": "/work",
                },
                "Id": CHILD_IMAGE,
            }
        ]
    )


def _completed_public_summary_sources(
    tmp_path: Path,
) -> tuple[
    IFEMPinnedMathlibProfilePlanV1,
    IFEMPinnedMathlibProfileBuildReceiptV1,
    IFEMPinnedMathlibProfileObservationsV1,
    profiles.IFEMPinnedMathlibProfileResultV1,
    Path,
    Path,
    Path,
    Path,
]:
    plan = _plan()
    receipt = _receipt(plan)
    raw = {profile.profile_id: _raw_profile(plan, profile.profile_id) for profile in plan.profiles}
    first_profile = plan.profiles[0]
    payload = json.loads(raw[first_profile.profile_id])
    payload["loaded_module_closure"] = ["Init.Prelude", first_profile.direct_import]
    payload["declarations"][0] = {
        "canonical_type": "P2-07 canonical type text must not leak",
        "declaration": plan.candidate_declarations[0],
        "declaration_kind": "theorem",
        "observed_axioms": ["Classical.choice"],
        "origin_module": first_profile.direct_import,
        "present": True,
    }
    raw[first_profile.profile_id] = json.dumps(payload, ensure_ascii=True, sort_keys=True)
    observation = normalize_profile_observations(raw, plan=plan, child_image=receipt.child_image)
    result = completed_result(plan, observation)
    plan_path = tmp_path / "plan.json"
    receipt_path = tmp_path / "receipt.json"
    observation_path = tmp_path / "observation.raw.json"
    result_path = tmp_path / "result.json"
    write_model_once(plan_path, plan)
    write_model_once(receipt_path, receipt)
    write_model_once(observation_path, observation)
    write_model_once(result_path, result)
    return (
        plan,
        receipt,
        observation,
        result,
        plan_path,
        receipt_path,
        observation_path,
        result_path,
    )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_materialized_plan_is_current_and_has_the_fixed_observation_contract() -> None:
    generated = build_ifem_pinned_mathlib_profile_plan()
    frozen = _plan()

    validate_profile_plan_bindings(frozen)
    assert frozen.model_dump(mode="json") == generated.model_dump(mode="json")
    assert len(frozen.candidate_declarations) <= 128
    assert frozen.observation_contract.declaration_origin == "required_if_present"
    assert frozen.observation_contract.canonical_type == "required_if_present"
    assert frozen.observation_contract.observed_axioms == "required_if_present"
    assert frozen.observation_contract.loaded_module_closure == "required"
    assert frozen.observation_contract.negative_control == "required_and_must_be_absent"
    assert frozen.authority.semantic_classification_authorized is False


def test_materialize_cli_writes_an_idempotent_plan(tmp_path: Path) -> None:
    output = tmp_path / "ifem-pinned-plan.json"

    assert main(["materialize-plan", "--out", str(output)]) == 0
    first = output.read_bytes()
    assert main(["materialize-plan", "--out", str(output)]) == 0
    assert output.read_bytes() == first


def test_rendered_run_is_default_denied_and_resource_bounded() -> None:
    plan = _plan()
    command = docker_query_command(
        plan,
        child_image=CHILD_IMAGE,
        profile=plan.profiles[0],
    )

    assert command[:3] == ("docker", "run", "--rm")
    assert command[3:5] == ("--network", "none")
    assert "--read-only" in command
    assert ("--cap-drop", "ALL") in pairwise(command)
    assert ("--security-opt", "no-new-privileges") in pairwise(command)
    assert ("--pids-limit", "128") in pairwise(command)
    assert ("--memory", "2g") in pairwise(command)
    assert ("--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m") in pairwise(command)
    assert "--privileged" not in command
    assert "--mount" not in command
    assert command[-(2 * len(plan.candidate_declarations)) :] == tuple(
        value
        for declaration in plan.candidate_declarations
        for value in ("--declaration", declaration)
    )


def test_staged_build_context_is_exact_and_build_command_has_no_network(tmp_path: Path) -> None:
    plan = _plan()
    stage = tmp_path / "stage"

    observed_context = _stage_child_build_context(plan, worker_root=WORKER_ROOT, stage=stage)
    command = _child_image_build_command(plan, tag=_child_image_tag(plan))

    assert (
        observed_context
        == hashlib.sha256(
            canonical_json_bytes(
                [
                    {
                        "path": "Dockerfile.ifem-pinned-profile-query",
                        "sha256": plan.assets.dockerfile_sha256,
                    },
                    {
                        "path": "AutoleanIFEMPinnedProfileQuery.lean",
                        "sha256": plan.assets.helper_sha256,
                    },
                    {
                        "path": "autolean-ifem-pinned-profile-query",
                        "sha256": plan.assets.wrapper_sha256,
                    },
                ]
            )
        ).hexdigest()
    )
    assert tuple(sorted(path.name for path in stage.iterdir())) == (
        "AutoleanIFEMPinnedProfileQuery.lean",
        "Dockerfile.ifem-pinned-profile-query",
        "autolean-ifem-pinned-profile-query",
    )
    assert command[:4] == ("docker", "build", "--network=none", "--pull=false")
    assert command[-1] == "."


def test_child_image_build_uses_the_staged_context_and_receipt_bound_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    calls: list[tuple[tuple[str, ...], Path | None, bool, bool]] = []

    def fake_docker(
        argv: Sequence[str],
        *,
        capture_output: bool,
        check: bool = True,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = tuple(argv)
        calls.append((arguments, cwd, capture_output, check))
        if arguments[:3] == ("docker", "image", "inspect") and not check:
            return subprocess.CompletedProcess(arguments, 1, "", "Error: No such image")
        if arguments[:2] == ("docker", "build"):
            assert cwd is not None
            assert tuple(sorted(path.name for path in cwd.iterdir())) == (
                "AutoleanIFEMPinnedProfileQuery.lean",
                "Dockerfile.ifem-pinned-profile-query",
                "autolean-ifem-pinned-profile-query",
            )
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if arguments[:3] == ("docker", "image", "inspect"):
            return subprocess.CompletedProcess(arguments, 0, _image_inspect_payload(plan), "")
        raise AssertionError(f"unexpected Docker call: {arguments!r}")

    monkeypatch.setattr(profiles, "_run_docker", fake_docker)
    receipt = profiles.build_ifem_pinned_mathlib_profile_child_image(plan)

    build_call = next(call for call in calls if call[0][:2] == ("docker", "build"))
    assert build_call[0][:4] == ("docker", "build", "--network=none", "--pull=false")
    assert build_call[1] is not None
    assert receipt.child_image == CHILD_IMAGE
    assert receipt.plan_content_sha256 == plan.content_sha256


def test_runner_uses_receipt_bound_isolation_for_every_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    receipt = _receipt(plan)
    runs: list[tuple[str, ...]] = []

    def fake_docker(
        argv: Sequence[str],
        *,
        capture_output: bool,
        check: bool = True,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        del cwd
        arguments = tuple(argv)
        if arguments[:3] == ("docker", "image", "inspect"):
            assert check is True
            return subprocess.CompletedProcess(arguments, 0, _image_inspect_payload(plan), "")
        if arguments[:2] == ("docker", "run"):
            assert capture_output is True
            runs.append(arguments)
            profile_id = arguments[arguments.index("--profile") + 1]
            return subprocess.CompletedProcess(arguments, 0, _raw_profile(plan, profile_id), "")
        raise AssertionError(f"unexpected Docker call: {arguments!r}")

    monkeypatch.setattr(profiles, "_run_docker", fake_docker)
    observation = profiles.run_ifem_pinned_mathlib_profile_queries(plan, receipt)

    assert observation.child_image == receipt.child_image
    assert tuple(run[run.index("--profile") + 1] for run in runs) == tuple(
        profile.profile_id for profile in plan.profiles
    )
    assert all(("--network", "none") in pairwise(run) for run in runs)
    assert all("--read-only" in run for run in runs)


def test_raw_observation_binds_all_image_owned_oleans_without_classifying() -> None:
    plan = _plan()
    receipt = _receipt(plan)
    raw = {profile.profile_id: _raw_profile(plan, profile.profile_id) for profile in plan.profiles}

    observation = normalize_profile_observations(raw, plan=plan, child_image=receipt.child_image)
    validate_profile_observation_bindings(plan, receipt, observation)
    result = completed_result(plan, observation)

    assert tuple(item.path for item in observation.built_olean_hashes) == _BUILT_OLEAN_PATHS
    assert all(not profile.negative_control.present for profile in observation.profiles)
    assert observation.authority.semantic_classification_authorized is False
    assert result.execution_state == "completed"


def test_raw_observation_rejects_a_tampered_olean_inventory() -> None:
    plan = _plan()
    raw = {profile.profile_id: _raw_profile(plan, profile.profile_id) for profile in plan.profiles}
    payload = json.loads(raw[plan.profiles[0].profile_id])
    payload["built_olean_hashes"][0]["path"] = "/tmp/unbound.olean"
    raw[plan.profiles[0].profile_id] = json.dumps(payload)

    with pytest.raises(IFEMPinnedProfileError, match="OLean inventory order drifted"):
        normalize_profile_observations(raw, plan=plan, child_image=CHILD_IMAGE)


def test_raw_observation_rejects_a_broad_or_wrong_direct_import_before_readiness() -> None:
    plan = _plan()
    raw = {profile.profile_id: _raw_profile(plan, profile.profile_id) for profile in plan.profiles}
    payload = json.loads(raw[plan.profiles[0].profile_id])
    payload["direct_imports"] = ["Mathlib"]
    raw[plan.profiles[0].profile_id] = json.dumps(payload)

    with pytest.raises(IFEMPinnedProfileError, match="planned singleton import"):
        normalize_profile_observations(raw, plan=plan, child_image=CHILD_IMAGE)


def test_public_summary_is_content_addressed_and_redacts_raw_type_and_closure_text(
    tmp_path: Path,
) -> None:
    (
        plan,
        receipt,
        observation,
        result,
        plan_path,
        receipt_path,
        observation_path,
        result_path,
    ) = _completed_public_summary_sources(tmp_path)

    summary = build_ifem_pinned_mathlib_profile_public_summary(
        plan,
        receipt,
        observation,
        result,
        plan_file_sha256=_file_sha256(plan_path),
        receipt_file_sha256=_file_sha256(receipt_path),
        observation_file_sha256=_file_sha256(observation_path),
        result_file_sha256=_file_sha256(result_path),
    )
    rendered = render_ifem_pinned_mathlib_profile_public_summary(summary)
    public_profile = summary.profiles[0]
    raw_profile = observation.profiles[0]
    public_record = public_profile.declarations[0]
    raw_record = raw_profile.declarations[0]

    assert summary.content_sha256 == summary.computed_content_sha256()
    assert summary.plan_content_sha256 == plan.content_sha256
    assert summary.receipt_content_sha256 == receipt.content_sha256
    assert summary.observation_content_sha256 == observation.content_sha256
    assert summary.result_content_sha256 == result.content_sha256
    assert summary.plan_file_sha256 == _file_sha256(plan_path)
    assert summary.receipt_file_sha256 == _file_sha256(receipt_path)
    assert summary.observation_file_sha256 == _file_sha256(observation_path)
    assert summary.result_file_sha256 == _file_sha256(result_path)
    assert summary.environment == plan.environment
    assert summary.assets == plan.assets
    assert summary.child_image == receipt.child_image
    assert summary.built_olean_hashes == observation.built_olean_hashes
    assert public_profile.direct_import == plan.profiles[0].direct_import
    assert public_profile.loaded_module_closure_count == len(raw_profile.loaded_module_closure)
    assert public_profile.loaded_module_closure_sha256 == raw_profile.loaded_module_closure_sha256
    assert public_record.canonical_type_sha256 == raw_record.canonical_type_sha256
    assert raw_record.canonical_type is not None
    assert public_record.canonical_type_utf8_byte_count == len(
        raw_record.canonical_type.encode("utf-8")
    )
    assert public_record.declaration_kind == raw_record.declaration_kind
    assert public_record.origin_module == raw_record.origin_module
    assert public_record.observed_axioms == raw_record.observed_axioms
    assert summary.authority.semantic_classification_authorized is False
    assert summary.replay_reloads_exact_source_artifacts is True
    assert b'"canonical_type"' not in rendered
    assert b'"loaded_module_closure"' not in rendered
    assert b"P2-07 canonical type text must not leak" not in rendered
    assert b"Init.Prelude" not in rendered
    assert "canonical_type" not in json.loads(rendered)
    assert "loaded_module_closure" not in json.loads(rendered)

    validate_ifem_pinned_mathlib_profile_public_summary_bindings(
        summary,
        plan,
        receipt,
        observation,
        result,
        plan_file_sha256=_file_sha256(plan_path),
        receipt_file_sha256=_file_sha256(receipt_path),
        observation_file_sha256=_file_sha256(observation_path),
        result_file_sha256=_file_sha256(result_path),
    )


def test_public_summary_rejects_tampering_and_non_replayable_source_bindings(
    tmp_path: Path,
) -> None:
    (
        plan,
        receipt,
        observation,
        result,
        plan_path,
        receipt_path,
        observation_path,
        result_path,
    ) = _completed_public_summary_sources(tmp_path)
    source_hashes = {
        "plan_file_sha256": _file_sha256(plan_path),
        "receipt_file_sha256": _file_sha256(receipt_path),
        "observation_file_sha256": _file_sha256(observation_path),
        "result_file_sha256": _file_sha256(result_path),
    }
    summary = build_ifem_pinned_mathlib_profile_public_summary(
        plan, receipt, observation, result, **source_hashes
    )
    tampered_payload = summary.model_dump(mode="json")
    tampered_payload["profiles"][0]["loaded_module_closure_sha256"] = "0" * 64
    tampered_payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in tampered_payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    tampered = IFEMPinnedMathlibProfilePublicSummaryV1.model_validate(tampered_payload)

    with pytest.raises(IFEMPinnedProfileError, match="exact source projection"):
        validate_ifem_pinned_mathlib_profile_public_summary_bindings(
            tampered, plan, receipt, observation, result, **source_hashes
        )
    with pytest.raises(IFEMPinnedProfileError, match="exact source projection"):
        validate_ifem_pinned_mathlib_profile_public_summary_bindings(
            summary,
            plan,
            receipt,
            observation,
            result,
            **(source_hashes | {"observation_file_sha256": "0" * 64}),
        )

    result_payload = result.model_dump(mode="json")
    result_payload["observation_content_sha256"] = "0" * 64
    result_payload["content_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {key: value for key, value in result_payload.items() if key != "content_sha256"}
        )
    ).hexdigest()
    tampered_result = profiles.IFEMPinnedMathlibProfileResultV1.model_validate(result_payload)
    with pytest.raises(IFEMPinnedProfileError, match="does not bind completed"):
        build_ifem_pinned_mathlib_profile_public_summary(
            plan, receipt, observation, tampered_result, **source_hashes
        )


def test_public_summary_cli_reloads_sources_and_is_write_once(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (
        _,
        _,
        _,
        _,
        plan_path,
        receipt_path,
        observation_path,
        result_path,
    ) = _completed_public_summary_sources(tmp_path)
    summary_path = tmp_path / "summary.public.json"
    arguments = [
        "--plan",
        str(plan_path),
        "public-summary",
        "--receipt",
        str(receipt_path),
        "--observation",
        str(observation_path),
        "--result",
        str(result_path),
        "--out",
        str(summary_path),
    ]

    assert main(arguments) == 0
    first = summary_path.read_bytes()
    first_stdout = capsys.readouterr().out.strip()
    assert main(arguments) == 0
    second_stdout = capsys.readouterr().out.strip()
    summary = IFEMPinnedMathlibProfilePublicSummaryV1.model_validate(
        json.loads(summary_path.read_text(encoding="utf-8"))
    )

    assert summary_path.read_bytes() == first
    assert first_stdout == summary.content_sha256 == second_stdout
    assert b"P2-07 canonical type text must not leak" not in first
    assert b"Init.Prelude" not in first


def test_persisted_observation_rejects_rehashed_profile_direct_import_mismatch() -> None:
    plan = _plan()
    receipt = _receipt(plan)
    raw = {profile.profile_id: _raw_profile(plan, profile.profile_id) for profile in plan.profiles}
    observation = normalize_profile_observations(raw, plan=plan, child_image=receipt.child_image)
    replacement_import = plan.profiles[1].direct_import

    payload = json.loads(observation.model_dump_json())
    first_profile = payload["profiles"][0]
    first_profile["direct_imports"] = [replacement_import]
    first_profile["loaded_module_closure"] = [replacement_import]
    first_profile["loaded_module_closure_sha256"] = hashlib.sha256(
        canonical_json_bytes([replacement_import])
    ).hexdigest()
    content_payload = dict(payload)
    del content_payload["content_sha256"]
    payload["content_sha256"] = hashlib.sha256(canonical_json_bytes(content_payload)).hexdigest()

    assert (
        payload["content_sha256"]
        == hashlib.sha256(canonical_json_bytes(content_payload)).hexdigest()
    )
    with pytest.raises(ValueError, match="direct imports differ from the frozen plan"):
        IFEMPinnedMathlibProfileObservationsV1.model_validate(payload)

    tampered_profile = observation.profiles[0].model_copy(
        update={
            "direct_imports": (replacement_import,),
            "loaded_module_closure": (replacement_import,),
            "loaded_module_closure_sha256": hashlib.sha256(
                canonical_json_bytes([replacement_import])
            ).hexdigest(),
        }
    )
    binding_payload = observation.model_dump(mode="python")
    binding_payload["profiles"] = (tampered_profile, *observation.profiles[1:])
    tampered_observation = IFEMPinnedMathlibProfileObservationsV1.model_construct(**binding_payload)
    with pytest.raises(IFEMPinnedProfileError, match="direct imports differ from the frozen plan"):
        validate_profile_observation_bindings(plan, receipt, tampered_observation)
