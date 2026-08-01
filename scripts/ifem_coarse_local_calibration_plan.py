"""Render or verify the fixed, text-free iFEM coarse local calibration plan."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from autolean_builder import (
    IFEMCoarseLocalCalibrationPlanError,
    build_current_ifem_coarse_local_calibration_plan,
    load_ifem_coarse_local_calibration_plan,
    materialize_ifem_coarse_local_calibration_plan_once,
    render_ifem_coarse_local_calibration_plan,
    verify_ifem_coarse_local_calibration_plan_against_current_inputs,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE_ROOT = ROOT / ".cache" / "references"
DEFAULT_DISCOVERY_MANIFEST_PATH = (
    ROOT / "Builder" / "pilots" / "discovery" / "phase-2-active-lanes.v1.json"
)
DEFAULT_PLAN_PATH = (
    ROOT
    / "Builder"
    / "pilots"
    / "ifem-source-alignment"
    / "ifem-coarse-local-calibration-plan.v1.json"
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("materialize", "render", "verify"))
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    action = _build_parser().parse_args(arguments).action
    try:
        if action == "materialize":
            plan = materialize_ifem_coarse_local_calibration_plan_once(
                DEFAULT_PLAN_PATH,
                cache_root=DEFAULT_CACHE_ROOT,
                discovery_manifest_path=DEFAULT_DISCOVERY_MANIFEST_PATH,
            )
        elif action == "render":
            plan = build_current_ifem_coarse_local_calibration_plan(
                cache_root=DEFAULT_CACHE_ROOT,
                discovery_manifest_path=DEFAULT_DISCOVERY_MANIFEST_PATH,
            )
        else:
            plan = load_ifem_coarse_local_calibration_plan(DEFAULT_PLAN_PATH)
            verify_ifem_coarse_local_calibration_plan_against_current_inputs(
                plan,
                cache_root=DEFAULT_CACHE_ROOT,
                discovery_manifest_path=DEFAULT_DISCOVERY_MANIFEST_PATH,
            )
    except IFEMCoarseLocalCalibrationPlanError as error:
        print(f"ifem-coarse-local-calibration-plan: {error}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(render_ifem_coarse_local_calibration_plan(plan))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
