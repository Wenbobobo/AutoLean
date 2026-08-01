from __future__ import annotations

import json

from scripts import model_theory_machine_review as cli


def test_check_cli_reports_explicit_non_authority(capsys) -> None:  # type: ignore[no-untyped-def]
    assert cli.main(["check"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "status": "ok",
        "mode": "check",
        "artifact": "Builder/pilots/model-theory-admission/machine-review/packet.v1.json",
        "ambiguity_count": 9,
        "mutation_result_count": 3,
        "successor_profile_count": 3,
        "decision_disposition": "gap",
        "selection": "not_selected",
        "statement_contract": "not_frozen",
        "prover_handoff": "forbidden",
        "authority": "machine_advisory",
    }
