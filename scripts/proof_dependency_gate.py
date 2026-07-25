"""Run and validate the experimental ordinary-declaration proof dependency gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final, NoReturn, cast

from autolean_prover.proof_dependencies import (
    ProofDependencyEvidence,
    ProofDependencyEvidenceError,
    ProofDependencyPolicy,
    ProofDependencyRejected,
    evaluate_proof_dependency_policy,
)

WSL_DISTRIBUTION: Final[str] = "Ubuntu-24.04"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_TARGET = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_MAX_SOURCE_BYTES: Final[int] = 16 * 1024 * 1024
_QUERY_HELPER = _REPO_ROOT / "Prover" / "worker" / "spikes" / "AutoleanProofDependencyQuery.lean"
_QUERY_FIXTURE = (
    _REPO_ROOT / "Prover" / "worker" / "tests" / "fixtures" / "ProofDependencyClosure.lean"
)
_EVIDENCE_FIXTURES = _REPO_ROOT / "Prover" / "tests" / "fixtures" / "proof_dependencies"
_REPLAY_TARGETS: Final[tuple[tuple[str, str], ...]] = (
    ("nonalias.evidence.json", "AutoLean.ProofDependencyFixture.nonalias"),
    ("exact-type-alias.evidence.json", "AutoLean.ProofDependencyFixture.exactTypeAlias"),
    ("disguised.evidence.json", "AutoLean.ProofDependencyFixture.disguised"),
    ("quotient.evidence.json", "AutoLean.ProofDependencyFixture.quotientProbe"),
)


class ProofDependencySpikeError(RuntimeError):
    """The local, non-authoritative query could not complete safely."""


def _fail(message: str) -> NoReturn:
    raise ProofDependencySpikeError(message)


def _run(
    command: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ProofDependencySpikeError("proof dependency spike subprocess failed") from error


def _strict_json(raw: str, *, label: str) -> dict[str, object]:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"non-standard JSON constant: {value}")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ProofDependencyEvidenceError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise ProofDependencyEvidenceError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _load_json(path: Path, *, label: str) -> dict[str, object]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ProofDependencyEvidenceError(f"{label} is unreadable UTF-8") from error
    return _strict_json(raw, label=label)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise ProofDependencySpikeError("proof dependency input is unreadable") from error
    return digest.hexdigest()


def _docker_base() -> list[str]:
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    user = f"{getuid()}:{getgid()}" if callable(getuid) and callable(getgid) else "65532:65532"
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "2g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--user",
        user,
    ]


def _snapshot_candidate(source: Path, destination: Path) -> None:
    try:
        metadata = source.lstat()
    except OSError as error:
        raise ProofDependencySpikeError("candidate source is unavailable") from error
    if source.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        _fail("candidate source must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_SOURCE_BYTES:
        _fail("candidate source size is outside the spike limit")
    try:
        with source.open("rb") as source_stream:
            before = os.fstat(source_stream.fileno())
            if (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            ):
                _fail("candidate source changed before snapshot")
            with destination.open("xb") as destination_stream:
                while chunk := source_stream.read(1024 * 1024):
                    destination_stream.write(chunk)
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
            after = os.fstat(source_stream.fileno())
    except OSError as error:
        raise ProofDependencySpikeError("candidate source snapshot failed") from error
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        _fail("candidate source changed during snapshot")
    if destination.stat().st_size != metadata.st_size:
        _fail("candidate source snapshot size differs from source")
    destination.chmod(0o444)


def query_dependencies(
    *,
    image: str,
    candidate: Path,
    declaration: str,
) -> ProofDependencyEvidence:
    """Compile once with the frozen wrapper, then run the host-mounted query spike."""

    if _IMAGE.fullmatch(image) is None:
        _fail("query requires a digest-pinned worker image")
    if _TARGET.fullmatch(declaration) is None:
        _fail("query target must be a canonical dotted Lean declaration")
    if not _QUERY_HELPER.is_file():
        _fail("proof dependency query helper is unavailable")

    with tempfile.TemporaryDirectory(prefix="autolean-proof-dependency-") as raw_scratch:
        scratch = Path(raw_scratch)
        source_snapshot = scratch / "Candidate.lean"
        output = scratch / "output"
        output.mkdir(mode=0o777)
        _snapshot_candidate(candidate, source_snapshot)

        compile_command = [
            *_docker_base(),
            "--mount",
            f"type=bind,src={source_snapshot},dst=/input/Candidate.lean,readonly",
            "--mount",
            f"type=bind,src={output},dst=/output",
            image,
            "/opt/autolean/bin/autolean-lean-wrapper",
            "--protocol",
            "autolean.oci-lean-wrapper.v2",
            "--phase",
            "compile",
            "--candidate",
            "/input/Candidate.lean",
            "--output",
            "/output/Candidate.olean",
        ]
        _run(compile_command, timeout=120)
        compiled = output / "Candidate.olean"
        try:
            compiled_metadata = compiled.lstat()
        except OSError as error:
            raise ProofDependencySpikeError(
                "compile phase did not produce Candidate.olean"
            ) from error
        if compiled.is_symlink() or not stat.S_ISREG(compiled_metadata.st_mode):
            _fail("compiled candidate is not a regular file")
        if compiled_metadata.st_size <= 0:
            _fail("compiled candidate is empty")

        query_command = [
            *_docker_base(),
            "--mount",
            f"type=bind,src={compiled},dst=/compiled/Candidate.olean,readonly",
            "--mount",
            (
                f"type=bind,src={_QUERY_HELPER},"
                "dst=/query/AutoleanProofDependencyQuery.lean,readonly"
            ),
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            (
                'export LEAN_PATH="/compiled:$(cat /opt/autolean/environment/lean-path)"; '
                'exec lean --run /query/AutoleanProofDependencyQuery.lean "$1"'
            ),
            "autolean-proof-dependency-query-spike",
            declaration,
        ]
        completed = _run(query_command, timeout=120)
        lines = completed.stdout.splitlines()
        if len(lines) != 1:
            _fail("proof dependency query did not emit exactly one JSON record")
        return ProofDependencyEvidence.from_mapping(
            _strict_json(lines[0], label="proof dependency query output")
        )


def replay_fixture_evidence(*, image: str) -> tuple[dict[str, object], ...]:
    """Run the real helper and require exact agreement with every committed fixture."""

    observations: list[dict[str, object]] = []
    for fixture_name, declaration in _REPLAY_TARGETS:
        observed = query_dependencies(
            image=image,
            candidate=_QUERY_FIXTURE,
            declaration=declaration,
        )
        expected = ProofDependencyEvidence.from_mapping(
            _load_json(
                _EVIDENCE_FIXTURES / fixture_name,
                label=f"committed proof dependency fixture {fixture_name}",
            )
        )
        if observed != expected:
            _fail(f"proof dependency query drifted from committed fixture: {fixture_name}")
        observations.append(
            {
                "declaration": declaration,
                "fixture_path": (
                    Path("Prover") / "tests" / "fixtures" / "proof_dependencies" / fixture_name
                ).as_posix(),
                "query_output_sha256": observed.canonical_sha256(),
            }
        )
    return tuple(observations)


def write_operator_observation(*, image: str, output: Path) -> dict[str, object]:
    """Record a non-authoritative local replay below the ignored release-evidence root."""

    release_root = (_REPO_ROOT / "release-evidence").resolve()
    destination = (output if output.is_absolute() else _REPO_ROOT / output).resolve()
    if destination.suffix != ".json" or not destination.is_relative_to(release_root):
        _fail("operator observation must be a JSON file below release-evidence")
    observations = replay_fixture_evidence(image=image)
    output_hashes = tuple(cast(str, item["query_output_sha256"]) for item in observations)
    outputs_sha256 = hashlib.sha256(
        json.dumps(
            output_hashes,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    relative_output = destination.relative_to(_REPO_ROOT).as_posix()
    record: dict[str, object] = {
        "authority": "operator-local-observation-only",
        "candidate_sha256": _sha256_file(_QUERY_FIXTURE),
        "command": [
            "uv",
            "run",
            "python",
            "scripts/proof_dependency_gate.py",
            "observe-fixtures",
            "--image",
            image,
            "--output",
            relative_output,
        ],
        "fixture_replay_passed": True,
        "helper_identity": "host-mounted",
        "image": image,
        "observations": list(observations),
        "outputs_sha256": outputs_sha256,
        "promotion_state": "not-admission-evidence",
        "query_helper_sha256": _sha256_file(_QUERY_HELPER),
        "schema_version": "autolean.proof-dependency-operator-observation.v1",
    }
    encoded = (
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ProofDependencySpikeError(
            "operator observation could not be written exclusively"
        ) from error
    return record


def _wsl_path(path: Path) -> str:
    completed = _run(
        ["wsl.exe", "-d", WSL_DISTRIBUTION, "-e", "wslpath", "-a", str(path)],
        timeout=20,
    )
    translated = completed.stdout.strip()
    if not translated:
        _fail("WSL path translation returned an empty path")
    return translated


def _lexical_absolute(path: Path) -> Path:
    """Make a path absolute without dereferencing symlinks."""

    return Path(os.path.abspath(path))


def _delegate_query(arguments: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    command = [
        "wsl.exe",
        "-d",
        WSL_DISTRIBUTION,
        "--cd",
        _wsl_path(repo_root),
        "--",
        "env",
        f"PYTHONPATH={_wsl_path(repo_root / 'Prover' / 'src')}",
        "python3",
        "-m",
        "scripts.proof_dependency_gate",
        "query",
        "--native",
        "--image",
        cast(str, arguments.image),
        "--candidate",
        _wsl_path(_lexical_absolute(cast(Path, arguments.candidate))),
        "--declaration",
        cast(str, arguments.declaration),
    ]
    return subprocess.run(command, check=False).returncode


def _delegate_observation(arguments: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    command = [
        "wsl.exe",
        "-d",
        WSL_DISTRIBUTION,
        "--cd",
        _wsl_path(repo_root),
        "--",
        "env",
        f"PYTHONPATH={_wsl_path(repo_root / 'Prover' / 'src')}",
        "python3",
        "-m",
        "scripts.proof_dependency_gate",
        "observe-fixtures",
        "--native",
        "--image",
        cast(str, arguments.image),
        "--output",
        _wsl_path(cast(Path, arguments.output).resolve()),
    ]
    return subprocess.run(command, check=False).returncode


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    query = subparsers.add_parser("query")
    query.add_argument("--image", required=True)
    query.add_argument("--candidate", required=True, type=Path)
    query.add_argument("--declaration", required=True)
    query.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    observe = subparsers.add_parser("observe-fixtures")
    observe.add_argument("--image", required=True)
    observe.add_argument("--output", required=True, type=Path)
    observe.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--policy", required=True, type=Path)
    validate.add_argument("--evidence", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        if arguments.action == "query":
            if os.name == "nt" and not arguments.native:
                return _delegate_query(arguments)
            evidence = query_dependencies(
                image=cast(str, arguments.image),
                candidate=cast(Path, arguments.candidate),
                declaration=cast(str, arguments.declaration),
            )
            print(
                json.dumps(
                    evidence.to_mapping(),
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0

        if arguments.action == "observe-fixtures":
            if os.name == "nt" and not arguments.native:
                return _delegate_observation(arguments)
            observation = write_operator_observation(
                image=cast(str, arguments.image),
                output=cast(Path, arguments.output),
            )
            print(
                json.dumps(
                    observation,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return 0

        policy = ProofDependencyPolicy.from_mapping(
            _load_json(cast(Path, arguments.policy), label="proof dependency policy")
        )
        evidence = ProofDependencyEvidence.from_mapping(
            _load_json(cast(Path, arguments.evidence), label="proof dependency evidence")
        )
        decision = evaluate_proof_dependency_policy(evidence, policy)
        print(
            json.dumps(
                decision.to_mapping(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (
        ProofDependencyEvidenceError,
        ProofDependencyRejected,
        ProofDependencySpikeError,
    ) as error:
        print(f"proof-dependency-gate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
