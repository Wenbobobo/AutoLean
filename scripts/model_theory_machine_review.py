"""Build or verify the public-safe, non-authoritative model-theory T3 machine packet."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from autolean_builder.model_theory_machine_review import (
    PACKET_RELATIVE_PATH,
    ModelTheoryMachineReviewError,
    build_model_theory_machine_review_packet,
    verify_tracked_model_theory_machine_review_packet,
    write_model_theory_machine_review_packet,
)

ROOT = Path(__file__).resolve().parents[1]


def _count(packet: dict[str, object], key: str) -> int:
    value = packet[key]
    if not isinstance(value, list):
        raise ModelTheoryMachineReviewError(f"{key} must be an array")
    return len(value)


def _summary(packet: dict[str, object], mode: str) -> dict[str, object]:
    return {
        "status": "ok",
        "mode": mode,
        "artifact": PACKET_RELATIVE_PATH.as_posix(),
        "ambiguity_count": _count(packet, "ambiguity_table"),
        "mutation_result_count": _count(packet, "mutation_results"),
        "successor_profile_count": _count(packet, "successor_formal_profile_alternatives"),
        "decision_disposition": "gap",
        "selection": "not_selected",
        "statement_contract": "not_frozen",
        "prover_handoff": "forbidden",
        "authority": "machine_advisory",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("command", choices=("build", "check"))
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "build":
            packet = build_model_theory_machine_review_packet(arguments.repo_root)
            write_model_theory_machine_review_packet(arguments.repo_root)
        else:
            packet = verify_tracked_model_theory_machine_review_packet(arguments.repo_root)
    except ModelTheoryMachineReviewError as error:
        parser.error(str(error))
    print(json.dumps(_summary(packet, arguments.command), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
