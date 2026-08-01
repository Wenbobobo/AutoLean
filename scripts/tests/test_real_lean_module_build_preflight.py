from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from autolean_control_plane import ArtifactRef

import scripts.real_lean_module_build_preflight as preflight
from benchmarks.real_lean_project_dag_module_build import OciPlatformV1


def test_preflight_cli_rejects_relative_artifact_root(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = preflight.main(
        (
            "--image",
            f"ghcr.io/autolean/library-substrate@sha256:{'a' * 64}",
            "--runner-policy-path",
            "/opt/autolean/policy.json",
            "--artifact-root",
            "relative",
            "--runner-identity",
            "operator:test",
        )
    )
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "must be absolute" in captured.err


def test_preflight_cli_reports_nonpromotable_capability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reference = ArtifactRef(digest="a" * 64, size=1)
    image = f"ghcr.io/autolean/library-substrate@sha256:{'b' * 64}"
    capability = SimpleNamespace(
        image_binding=SimpleNamespace(
            oci_repo_digest=image,
            oci_config_digest=f"sha256:{'c' * 64}",
            platform=OciPlatformV1(os="linux", architecture="amd64"),
            runner_policy_sha256="a" * 64,
            runner_policy_artifact=reference,
            image_verification_artifact=reference,
        ),
        preflight_artifact=reference,
        runtime_engine_version="28.3.3",
        runner_identity="operator:test",
        capability_class="operator_local_oci_without_trusted_gateway_v1",
    )
    monkeypatch.setattr(
        preflight,
        "operator_local_module_runner_preflight",
        lambda **_: capability,
    )
    exit_code = preflight.main(
        (
            "--image",
            image,
            "--runner-policy-path",
            "/opt/autolean/policy.json",
            "--artifact-root",
            str(tmp_path / "artifacts"),
            "--runner-identity",
            "operator:test",
        )
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["module_execution_enabled"] is False
    assert report["trusted_gateway_attestation"] is False
    assert report["promotion_eligible"] is False
    assert report["kernel_acceptance_eligible"] is False
