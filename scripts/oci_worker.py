"""Build and exercise the pinned Linux OCI Lean worker.

On Windows this short entry point delegates to Ubuntu-24.04. Build inputs are staged from an
explicit four-file allowlist, so Docker never receives the repository or a host credential tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Final

WSL_DISTRIBUTION: Final[str] = "Ubuntu-24.04"
IMAGE_TAG: Final[str] = "autolean/lean-worker:4.28.0-pure-v3"
LEAN_ARCHIVE: Final[str] = "lean-4.28.0-linux.tar.zst"
LEAN_ARCHIVE_URL: Final[str] = (
    "https://github.com/leanprover/lean4/releases/download/v4.28.0/lean-4.28.0-linux.tar.zst"
)
LEAN_ARCHIVE_SHA256: Final[str] = "ceb3a3f844f7aebf63245e2b51c28d5b0ed38942c19f93cf3febd520302160bd"
BASE_IMAGE_DIGEST: Final[str] = (
    "sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90"
)
WORKER_FILES: Final[tuple[str, ...]] = (
    "Dockerfile",
    "AutoleanLeanQuery.lean",
    "autolean-lean-wrapper",
)


def _run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=True,
        shell=False,
        text=True,
        capture_output=capture,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _image_owned_verifier_identity(worker_root: Path) -> dict[str, str]:
    payload = {
        "schema_version": "autolean.image-owned-verifier-identity.v2",
        "wrapper_path": "/opt/autolean/bin/autolean-lean-wrapper",
        "wrapper_sha256": _sha256(worker_root / "autolean-lean-wrapper"),
        "query_helper_path": "/opt/autolean/lib/AutoleanLeanQuery.lean",
        "query_helper_sha256": _sha256(worker_root / "AutoleanLeanQuery.lean"),
    }
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return {
        **payload,
        "identity_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _delegate_to_wsl(arguments: list[str], repo_root: Path) -> int:
    translated = _run(
        [
            "wsl.exe",
            "-d",
            WSL_DISTRIBUTION,
            "--",
            "wslpath",
            "-a",
            str(repo_root).replace("\\", "/"),
        ],
        capture=True,
    ).stdout.strip()
    script = f"{translated}/scripts/oci_worker.py"
    completed = subprocess.run(
        [
            "wsl.exe",
            "-d",
            WSL_DISTRIBUTION,
            "--",
            "python3",
            script,
            *arguments,
            "--native",
        ],
        check=False,
        shell=False,
    )
    return completed.returncode


def _archive(cache_root: Path) -> Path:
    archive = cache_root / LEAN_ARCHIVE
    if archive.exists():
        observed = _sha256(archive)
        if observed != LEAN_ARCHIVE_SHA256:
            raise RuntimeError(
                f"cached Lean archive digest mismatch: expected {LEAN_ARCHIVE_SHA256}, "
                f"observed {observed}; remove only {archive} after audit"
            )
        return archive

    cache_root.mkdir(parents=True, exist_ok=True)
    partial = cache_root / f"{LEAN_ARCHIVE}.part-{os.getpid()}"
    try:
        with (
            urllib.request.urlopen(LEAN_ARCHIVE_URL, timeout=60) as response,
            partial.open("xb") as destination,
        ):
            shutil.copyfileobj(response, destination, length=1024 * 1024)
        observed = _sha256(partial)
        if observed != LEAN_ARCHIVE_SHA256:
            raise RuntimeError(
                f"downloaded Lean archive digest mismatch: expected {LEAN_ARCHIVE_SHA256}, "
                f"observed {observed}"
            )
        os.replace(partial, archive)
    finally:
        partial.unlink(missing_ok=True)
    return archive


def _stage_archive(archive: Path, destination: Path) -> None:
    shutil.copyfile(archive, destination)
    observed = _sha256(destination)
    if observed != LEAN_ARCHIVE_SHA256:
        raise RuntimeError(
            f"staged Lean archive digest mismatch: expected {LEAN_ARCHIVE_SHA256}, "
            f"observed {observed}"
        )


def _build(repo_root: Path) -> dict[str, object]:
    worker_root = repo_root / "Prover" / "worker"
    cache_root = Path.home() / ".cache" / "autolean" / "oci-worker-sources"
    archive = _archive(cache_root)

    with tempfile.TemporaryDirectory(prefix="autolean-oci-build-") as raw_stage:
        stage = Path(raw_stage)
        staged_archive = stage / LEAN_ARCHIVE
        _stage_archive(archive, staged_archive)
        for name in WORKER_FILES:
            shutil.copy2(worker_root / name, stage / name)
        _run(
            [
                "docker",
                "build",
                "--pull=false",
                "--network=none",
                "--tag",
                IMAGE_TAG,
                str(stage),
            ],
            cwd=stage,
        )

    inspected = json.loads(
        _run(
            ["docker", "image", "inspect", IMAGE_TAG],
            capture=True,
        ).stdout
    )[0]
    image_id = inspected["Id"]
    repo_digests = sorted(inspected.get("RepoDigests") or [])
    image_identity = _image_owned_verifier_identity(worker_root)
    record: dict[str, object] = {
        "schema_version": "autolean.oci-worker-build.v1",
        "image_tag": IMAGE_TAG,
        "image_id": image_id,
        "repo_digests": repo_digests,
        "base_image_digest": BASE_IMAGE_DIGEST,
        "lean_archive_sha256": LEAN_ARCHIVE_SHA256,
        "dockerfile_sha256": _sha256(worker_root / "Dockerfile"),
        "wrapper_sha256": image_identity["wrapper_sha256"],
        "query_helper_source_sha256": image_identity["query_helper_sha256"],
        "image_owned_verifier_identity": image_identity,
    }
    evidence = repo_root / "release-evidence" / "oci-worker"
    evidence.mkdir(parents=True, exist_ok=True)
    output = evidence / "build.v1.json"
    output.write_text(
        json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(record, ensure_ascii=True, sort_keys=True))
    return record


def _canary(repo_root: Path, image: str | None) -> None:
    if image is None:
        inspected = json.loads(
            _run(["docker", "image", "inspect", IMAGE_TAG], capture=True).stdout
        )[0]
        repo_digests = sorted(inspected.get("RepoDigests") or [])
        if not repo_digests:
            raise RuntimeError(
                "the local worker has no repository digest; rebuild/import it before canary"
            )
        image = repo_digests[0]
    environment = os.environ.copy()
    environment["UV_PROJECT_ENVIRONMENT"] = str(
        Path.home() / ".cache" / "autolean" / "oci-worker-python"
    )
    uv = shutil.which("uv")
    if uv is None:
        candidate = Path.home() / ".local" / "bin" / "uv"
        if not candidate.is_file():
            raise RuntimeError("uv is unavailable in the WSL execution environment")
        uv = str(candidate)
    _run(
        [
            uv,
            "sync",
            "--frozen",
            "--package",
            "autolean-prover",
            "--package",
            "autolean-control-plane",
            "--no-dev",
        ],
        cwd=repo_root,
        environment=environment,
    )
    _run(
        [
            uv,
            "run",
            "--frozen",
            "--no-sync",
            "python",
            "scripts/oci_worker_canary.py",
            "--image",
            image,
        ],
        cwd=repo_root,
        environment=environment,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "canary", "all"))
    parser.add_argument("--image", help="digest-pinned image reference for canary")
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    if os.name == "nt" and not arguments.native:
        forwarded = [arguments.action]
        if arguments.image is not None:
            forwarded.extend(("--image", arguments.image))
        raise SystemExit(_delegate_to_wsl(forwarded, repo_root))

    record: dict[str, object] | None = None
    if arguments.action in {"build", "all"}:
        record = _build(repo_root)
    if arguments.action in {"canary", "all"}:
        selected = arguments.image
        if selected is None and record is not None:
            repo_digests = record["repo_digests"]
            if isinstance(repo_digests, list) and repo_digests:
                selected = str(repo_digests[0])
        _canary(repo_root, selected)


if __name__ == "__main__":
    main()
