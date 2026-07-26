"""Run the operator-local T7 module capability preflight.

This command verifies the exact T6 RepoDigest and image-owned policy.  It does not
run a module, issue a trusted gateway attestation, or make any result eligible for
promotion or kernel acceptance.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_control_plane import ArtifactStore

from benchmarks.real_lean_project_dag_module_build import (
    LeanModuleBuildError,
    operator_local_module_runner_preflight,
)


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        required=True,
        help="Exact Docker-recorded OCI RepoDigest; mutable tags are rejected.",
    )
    parser.add_argument(
        "--runner-policy-path",
        required=True,
        help="Absolute path to the T7 runner policy inside the image.",
    )
    parser.add_argument(
        "--artifact-root",
        type=Path,
        required=True,
        help="Absolute operator-owned CAS directory for preflight artifacts.",
    )
    parser.add_argument(
        "--runner-identity",
        required=True,
        help="Public operator-local runner identity; never a credential.",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_arguments(arguments)
    artifact_root = parsed.artifact_root
    if not artifact_root.is_absolute():
        print(
            "real-lean-module-build-preflight: --artifact-root must be absolute",
            file=sys.stderr,
        )
        return 2
    try:
        artifacts = ArtifactStore(artifact_root)
        capability = operator_local_module_runner_preflight(
            oci_repo_digest=parsed.image,
            runner_policy_image_path=parsed.runner_policy_path,
            artifacts=artifacts,
            runner_identity=parsed.runner_identity,
        )
        result = {
            "schema_version": "autolean.t7-operator-module-preflight-cli.v1",
            "oci_repo_digest": capability.image_binding.oci_repo_digest,
            "oci_config_digest": capability.image_binding.oci_config_digest,
            "platform": capability.image_binding.platform.document(),
            "runner_policy_sha256": (capability.image_binding.runner_policy_sha256),
            "runner_policy_artifact": {
                "algorithm": (capability.image_binding.runner_policy_artifact.algorithm),
                "digest": capability.image_binding.runner_policy_artifact.digest,
                "size": capability.image_binding.runner_policy_artifact.size,
            },
            "image_verification_artifact": {
                "algorithm": (capability.image_binding.image_verification_artifact.algorithm),
                "digest": (capability.image_binding.image_verification_artifact.digest),
                "size": capability.image_binding.image_verification_artifact.size,
            },
            "preflight_artifact": {
                "algorithm": capability.preflight_artifact.algorithm,
                "digest": capability.preflight_artifact.digest,
                "size": capability.preflight_artifact.size,
            },
            "runtime_engine_version": capability.runtime_engine_version,
            "runner_identity": capability.runner_identity,
            "evidence_class": capability.capability_class,
            "module_execution_enabled": False,
            "trusted_gateway_attestation": False,
            "promotion_eligible": False,
            "kernel_acceptance_eligible": False,
        }
        print(
            json.dumps(
                result,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (LeanModuleBuildError, ValueError, OSError) as error:
        print(
            f"real-lean-module-build-preflight: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
