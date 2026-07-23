"""Cross-platform development tasks kept intentionally short for Windows users."""

from __future__ import annotations

import argparse
import subprocess
from collections.abc import Sequence


def run(command: Sequence[str]) -> None:
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "task",
        choices=(
            "bootstrap",
            "test",
            "check",
            "ci",
            "format",
            "dashboard",
            "public-ready",
            "sbom",
            "chaos-process",
        ),
    )
    parser.add_argument(
        "--jobs",
        type=int,
        help="synthetic job count for chaos-process only; use 1000 for the bounded target",
    )
    args = parser.parse_args()

    commands: dict[str, tuple[str, ...]] = {
        "bootstrap": ("uv", "sync", "--all-packages", "--all-groups"),
        "test": ("uv", "run", "pytest"),
        "format": ("uv", "run", "ruff", "format", "."),
        "ci": ("uv", "run", "--frozen", "python", "scripts/ci.py"),
        "dashboard": (
            "uv",
            "run",
            "uvicorn",
            "autolean_dashboard.app:create_app",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            "8765",
        ),
        "public-ready": ("uv", "run", "python", "-m", "scripts.public_readiness"),
        "sbom": ("uv", "run", "python", "-m", "scripts.generate_sbom", "check"),
        "chaos-process": (
            "uv",
            "run",
            "python",
            "scripts/control_plane_process_chaos.py",
            "--jobs",
            "3" if args.jobs is None else str(args.jobs),
        ),
    }
    if args.jobs is not None and args.task != "chaos-process":
        parser.error("--jobs is only valid for chaos-process")
    if args.task == "check":
        run(("uv", "run", "ruff", "check", "."))
        for package in (
            "autolean_contracts",
            "autolean_control_plane",
            "autolean_builder",
            "autolean_prover",
            "autolean_dashboard",
        ):
            run(("uv", "run", "mypy", "-p", package))
        run(("uv", "run", "mypy", "benchmarks", "scripts"))
        run(("uv", "run", "pytest"))
        return
    run(commands[args.task])


if __name__ == "__main__":
    main()
