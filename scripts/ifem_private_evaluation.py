"""Evaluate one settled private iFEM role run and emit only the D33 aggregate.

This command performs no model call. It reloads the protocol-pinned graph and corpus, then rebuilds
the fixture, oracle, request policy, witness report, and authenticated private manifest before
writing the public role/risk aggregate. Raw responses and private references never enter stdout
or the public file.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from autolean_builder.ifem_structural_witness_validation import (  # noqa: E402
    validate_ifem_structural_witnesses,
)
from autolean_contracts import canonical_json_bytes  # noqa: E402
from autolean_prover.providers import LocalPrivateModelOutputStore  # noqa: E402

from benchmarks.ifem_deepseek_preflight import build_ifem_deepseek_preflight  # noqa: E402
from benchmarks.ifem_private_evaluator import (  # noqa: E402
    IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME,
    IFEMPrivateEvaluatorPublicReportV1,
    build_ifem_private_evaluator_protocol_binding,
    evaluate_ifem_private_role_run,
    write_ifem_private_evaluator_public_report,
)
from benchmarks.ifem_synthetic_role_fixture import (  # noqa: E402
    build_ifem_synthetic_role_fixture,
    build_ifem_synthetic_role_oracle,
)
from benchmarks.ifem_synthetic_role_private_ledger import (  # noqa: E402
    LocalIFEMSyntheticRolePrivateLedger,
    TestOnlyIFEMSyntheticRoleHmacAuthenticator,
)
from scripts.ifem_deepseek_role_calibration import (  # noqa: E402
    IFEMDeepSeekRoleCalibrationProtocolIdV1,
    _is_link_or_reparse_point,
    _load_operator_material,
    _private_child_root,
    build_ifem_deepseek_role_calibration_plan,
    verify_ifem_deepseek_private_root_protocol,
)


class IFEMPrivateEvaluationOperatorError(ValueError):
    """The private evaluator operator boundary was not satisfied."""


def _physical_existing_directory(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise IFEMPrivateEvaluationOperatorError(f"{label} must be an absolute path")
    if _is_link_or_reparse_point(path) or not path.is_dir():
        raise IFEMPrivateEvaluationOperatorError(f"{label} must be a physical directory")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise IFEMPrivateEvaluationOperatorError(f"{label} is unavailable") from error


def _prepare_public_root(path: Path, *, private_roots: tuple[Path, ...]) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise IFEMPrivateEvaluationOperatorError("public output root must be an absolute path")
    try:
        path.mkdir(parents=False, exist_ok=True)
        root = path.resolve(strict=True)
    except OSError as error:
        raise IFEMPrivateEvaluationOperatorError("public output root is unavailable") from error
    if _is_link_or_reparse_point(path) or not root.is_dir():
        raise IFEMPrivateEvaluationOperatorError("public output root must be a physical directory")
    for private in private_roots:
        if root == private or root in private.parents or private in root.parents:
            raise IFEMPrivateEvaluationOperatorError(
                "public output root must be disjoint from private roots"
            )
    return root


def evaluate_settled_ifem_private_run(
    *,
    private_root: Path,
    operator_material_root: Path,
    public_output_root: Path,
    protocol_id: IFEMDeepSeekRoleCalibrationProtocolIdV1 | str,
) -> IFEMPrivateEvaluatorPublicReportV1:
    """Rebuild, authenticate, evaluate, and write one complete settled D32 run."""

    private = _physical_existing_directory(private_root, label="private run root")
    material = _physical_existing_directory(
        operator_material_root,
        label="operator material root",
    )
    seed, ledger_key = _load_operator_material(material)
    plan = build_ifem_deepseek_role_calibration_plan(protocol_id=protocol_id)
    graph = plan.graph
    fixture = build_ifem_synthetic_role_fixture(plan.corpus, operator_seed=seed)
    oracle = build_ifem_synthetic_role_oracle(plan.corpus, operator_seed=seed)
    preflight = build_ifem_deepseek_preflight(
        fixture,
        profile_bytes=plan.profile_bytes,
        request_policy=plan.request_policy,
        response_contract=plan.response_contract,
    )
    policy = plan.request_policy
    protocol_binding = build_ifem_private_evaluator_protocol_binding(
        protocol_id=plan.protocol.protocol_id.value,
        profile_bytes=plan.profile_bytes,
        request_policy=policy,
        response_contract=plan.response_contract,
    )
    verify_ifem_deepseek_private_root_protocol(
        private_root=private,
        plan=plan,
        fixture=fixture,
        authenticator=TestOnlyIFEMSyntheticRoleHmacAuthenticator(ledger_key.encode("utf-8")),
    )
    ledger = LocalIFEMSyntheticRolePrivateLedger(
        _private_child_root(private, "ledger-v1"),
        output_store=LocalPrivateModelOutputStore(_private_child_root(private, "responses-v1")),
        authenticator=TestOnlyIFEMSyntheticRoleHmacAuthenticator(ledger_key.encode("utf-8")),
    )
    public = _prepare_public_root(
        public_output_root,
        private_roots=(private, material),
    )
    witness_report = validate_ifem_structural_witnesses(corpus=plan.corpus, graph=graph)
    report = evaluate_ifem_private_role_run(
        fixture=fixture,
        oracle=oracle,
        corpus=plan.corpus,
        graph=graph,
        witness_report=witness_report,
        operator_seed=seed,
        ledger=ledger,
        preparation_executor=preflight.adapter,
        request_policy=policy,
        response_contract=plan.response_contract,
        profile_bytes=plan.profile_bytes,
        protocol_binding=protocol_binding,
    )
    write_ifem_private_evaluator_public_report(
        cache_root=public,
        output_path=public / IFEM_PRIVATE_EVALUATOR_PUBLIC_REPORT_FILENAME,
        report=report,
        fixture=fixture,
        oracle=oracle,
        corpus=plan.corpus,
        graph=graph,
        witness_report=witness_report,
        operator_seed=seed,
        ledger=ledger,
        preparation_executor=preflight.adapter,
        request_policy=policy,
        response_contract=plan.response_contract,
        profile_bytes=plan.profile_bytes,
        protocol_binding=protocol_binding,
    )
    return report


class _RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise IFEMPrivateEvaluationOperatorError("invalid CLI arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _RedactedArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--operator-material-root", required=True, type=Path)
    parser.add_argument("--public-output-root", required=True, type=Path)
    parser.add_argument(
        "--protocol",
        choices=tuple(item.value for item in IFEMDeepSeekRoleCalibrationProtocolIdV1),
        required=True,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        report = evaluate_settled_ifem_private_run(
            private_root=arguments.private_root,
            operator_material_root=arguments.operator_material_root,
            public_output_root=arguments.public_output_root,
            protocol_id=arguments.protocol,
        )
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        print("ifem-private-evaluation: evaluation_failed", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json_bytes(report.model_dump(mode="json")) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
