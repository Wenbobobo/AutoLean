"""Run the offline Python and repository-policy CI gate."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence


def run(command: Sequence[str]) -> None:
    completed = subprocess.run(command, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> None:
    run(("uv", "lock", "--check"))
    run(("ruff", "format", "--check", "."))
    run(("ruff", "check", "."))
    for package in (
        "autolean_contracts",
        "autolean_control_plane",
        "autolean_builder",
        "autolean_prover",
        "autolean_dashboard",
    ):
        run(("mypy", "-p", package))
    run(("mypy", "benchmarks", "scripts"))
    run(("pytest", "-q"))
    run((sys.executable, "-m", "scripts.secret_scan"))
    run((sys.executable, "-m", "scripts.provider_policy_guard"))
    run((sys.executable, "scripts/release_evidence.py", "check"))
    run((sys.executable, "-m", "scripts.generate_sbom", "check"))


if __name__ == "__main__":
    main()
