"""Check authoritative-run prerequisites without running Lean, OCI proofs, or models."""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
from pathlib import Path

from benchmarks.fate_adapter import FateFixtureIntegrityError, FateLockedCheckout

_COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _host_system() -> str:
    return platform.system()


def _command_ok(argv: tuple[str, ...], *, cwd: Path) -> tuple[bool, bytes]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, b""
    return completed.returncode == 0, completed.stdout


def run_preflight(root: Path, fate_checkout: Path | None) -> tuple[dict[str, object], bool]:
    root = root.resolve()
    linux = _host_system() == "Linux"
    commit_ok, commit_output = _command_ok(
        ("git", "rev-parse", "--verify", "HEAD^{commit}"),
        cwd=root,
    )
    source_commit = commit_output.decode("ascii", errors="ignore").strip() if commit_ok else ""
    source_commit_ok = _COMMIT.fullmatch(source_commit) is not None
    clean_ok, clean_output = _command_ok(
        ("git", "status", "--porcelain=v1", "--untracked-files=no"),
        cwd=root,
    )
    clean_source = clean_ok and not clean_output
    docker_daemon, _ = _command_ok(
        ("docker", "version", "--format", "{{.Server.Version}}"),
        cwd=root,
    )

    fate_status = "not-requested"
    fate_ok = True
    if fate_checkout is not None:
        try:
            FateLockedCheckout.from_lock_file(fate_checkout.resolve()).build_manifest()
        except (FateFixtureIntegrityError, OSError, ValueError):
            fate_status = "blocked"
            fate_ok = False
        else:
            fate_status = "verified-source-only"

    checks = {
        "clean_tracked_source": clean_source,
        "container_daemon_available": docker_daemon,
        "fate_checkout": fate_status,
        "linux_host": linux,
        "source_commit_available": source_commit_ok,
    }
    passed = linux and source_commit_ok and clean_source and docker_daemon and fate_ok
    payload: dict[str, object] = {
        "authoritative_execution": "not-run",
        "checks": checks,
        "scope": "readiness-preflight-only",
        "status": "ready-for-authoritative-run" if passed else "blocked",
    }
    return payload, passed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--fate-checkout", type=Path)
    args = parser.parse_args()
    payload, passed = run_preflight(args.root, args.fate_checkout)
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
