"""OCI adapter for Builder's pre-freeze canonical elaborated-type gate.

The adapter renders a theorem or lemma header as an axiom solely so Lean can elaborate and store
its type without asking Builder to synthesize a proof.  The axiom carrier is temporary query input:
it is never a proof candidate, verification result, or promotion claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from autolean_builder import (
    CanonicalTypeEnvironmentFacts,
    CanonicalTypeGateBinding,
    CanonicalTypeGateError,
    CanonicalTypeQueryAssurance,
    CanonicalTypeQueryFacts,
    CanonicalTypeQueryRequest,
    CanonicalTypeQueryResult,
    run_canonical_type_gate,
)
from autolean_contracts import (
    HashKindV1,
    canonical_json_bytes,
    digest_bytes,
    digest_text,
)

from scripts import mathlib_build_resources, mathlib_source_lock, oci_mathlib_worker

_DECLARATION_HEADER_RE = re.compile(r"\A(?:theorem|lemma)\b")
_SOURCE_RENDERING_PROFILE = "autolean.declaration-type-observation.v1"
_ADAPTER_ID = "scripts.oci_mathlib_worker.query_declarations"
_LEAN_VERSION = "v4.28.0"
_TYPE_FORMAT = "autolean.lean-pp-expr.v1"
_CANARY_DECLARATION = "AutoLean.BuilderCanonicalTypeCanary.identity"
_CANARY_TYPE = "∀ (n : Nat), @Eq.{1} Nat n n"


@dataclass(frozen=True, slots=True)
class OciMathlibCanonicalTypeQuery:
    """Call the existing compile-seal-query boundary once per Builder request."""

    repo_root: Path
    source_cache: Path
    build_resource_cache: Path
    image: str

    def query(self, request: CanonicalTypeQueryRequest) -> CanonicalTypeQueryResult:
        rendered = _render_axiom_type_carrier(request)
        lake_manifest = self.repo_root / "Library" / "lake-manifest.json"
        before_manifest_sha256 = _file_sha256(lake_manifest)
        with tempfile.TemporaryDirectory(prefix="autolean-builder-canonical-type-") as raw_root:
            candidate = Path(raw_root) / "Candidate.lean"
            candidate.write_text(rendered, encoding="utf-8", newline="\n")
            document = oci_mathlib_worker.query_declarations(
                self.repo_root,
                self.source_cache,
                self.build_resource_cache,
                self.image,
                candidate,
                (request.declaration,),
            )
        after_manifest_sha256 = _file_sha256(lake_manifest)
        if after_manifest_sha256 != before_manifest_sha256:
            raise CanonicalTypeGateError(
                "Library lake manifest changed during the canonical type query"
            )
        return _normalize_query_result(
            document,
            declaration=request.declaration,
            expected_image=self.image,
            lake_manifest_sha256=before_manifest_sha256,
            rendered_source=rendered,
        )


def _render_axiom_type_carrier(request: CanonicalTypeQueryRequest) -> str:
    """Render complete source directly or turn one proofless header into an axiom carrier."""

    statement = request.statement_source.strip()
    if ":=" in statement:
        carrier = statement
    else:
        match = _DECLARATION_HEADER_RE.match(statement)
        if match is None:
            raise CanonicalTypeGateError(
                "canonical type query requires a theorem or lemma declaration"
            )
        carrier = f"axiom{statement[match.end() :]}"
    imports = [f"import {name}" for name in request.imports_allowlist]
    lines = [*imports]
    if imports:
        lines.append("")
    lines.extend((f"namespace {request.namespace}", "", carrier, ""))
    return "\n".join(lines)


def _normalize_query_result(
    document: dict[str, object],
    *,
    declaration: str,
    expected_image: str,
    lake_manifest_sha256: str,
    rendered_source: str,
) -> CanonicalTypeQueryResult:
    expected_keys = {
        "build_receipt_canonical_sha256",
        "execution_policy",
        "execution_policy_sha256",
        "image",
        "observation",
        "schema_version",
        "sealed_candidate_sha256",
        "source_inputs_sha256",
        "source_snapshot_sha256",
    }
    if set(document) != expected_keys:
        raise CanonicalTypeGateError(
            "mathlib declaration query result has unexpected or missing fields"
        )
    if (
        document.get("schema_version") != oci_mathlib_worker.DECLARATION_QUERY_EVIDENCE_SCHEMA
        or document.get("image") != expected_image
    ):
        raise CanonicalTypeGateError(
            "mathlib declaration query result differs from the requested profile"
        )
    observation = _object(document.get("observation"), label="observation")
    observation_keys = {
        "candidate_direct_imports",
        "candidate_direct_imports_sha256",
        "declarations",
        "image_identity",
        "module_import_closure",
        "module_import_closure_sha256",
    }
    if set(observation) != observation_keys:
        raise CanonicalTypeGateError(
            "mathlib declaration observation has unexpected or missing fields"
        )
    declarations = observation.get("declarations")
    if not isinstance(declarations, list) or len(declarations) != 1:
        raise CanonicalTypeGateError(
            "mathlib declaration observation must contain exactly one declaration"
        )
    declaration_record = _object(declarations[0], label="declaration")
    declaration_keys = {
        "canonical_type",
        "canonical_type_sha256",
        "declaration",
        "observed_axioms",
        "observed_axioms_sha256",
    }
    if set(declaration_record) != declaration_keys:
        raise CanonicalTypeGateError("mathlib declaration record has unexpected or missing fields")
    if declaration_record.get("declaration") != declaration:
        raise CanonicalTypeGateError(
            "mathlib declaration record differs from the requested declaration"
        )
    canonical_type = _text(declaration_record, "canonical_type")
    canonical_type_sha256 = _text(declaration_record, "canonical_type_sha256")
    observed_axioms = _string_tuple(
        declaration_record.get("observed_axioms"),
        label="observed_axioms",
    )
    observed_axioms_sha256 = _text(declaration_record, "observed_axioms_sha256")
    image_identity = _object(observation.get("image_identity"), label="image_identity")
    execution_policy = _object(document.get("execution_policy"), label="execution_policy")
    if execution_policy.get("image") != expected_image:
        raise CanonicalTypeGateError("mathlib declaration execution policy names another image")
    worker_image_digest = expected_image.rpartition("@")[2]
    source_snapshot_sha256 = _text(document, "source_snapshot_sha256")
    expected_snapshot_sha256 = hashlib.sha256(rendered_source.encode("utf-8")).hexdigest()
    if source_snapshot_sha256 != expected_snapshot_sha256:
        raise CanonicalTypeGateError(
            "mathlib declaration query snapshot differs from the axiom type carrier"
        )
    return CanonicalTypeQueryResult(
        declaration=declaration,
        canonical_type=canonical_type,
        canonical_type_sha256=canonical_type_sha256,
        environment=CanonicalTypeEnvironmentFacts(
            assurance=CanonicalTypeQueryAssurance.LOCAL_OCI_PREFREEZE,
            adapter_id=_ADAPTER_ID,
            image=expected_image,
            worker_image_digest=worker_image_digest,
            lean_version=_LEAN_VERSION,
            mathlib_revision=oci_mathlib_worker.MATHLIB_REVISION,
            lake_manifest_sha256=lake_manifest_sha256,
            type_format=_TYPE_FORMAT,
            query_schema_version=oci_mathlib_worker.DECLARATION_QUERY_EVIDENCE_SCHEMA,
            query_protocol=oci_mathlib_worker.DECLARATION_QUERY_PROTOCOL,
            query_identity_sha256=_sha256_json(image_identity),
            build_receipt_canonical_sha256=_text(
                document,
                "build_receipt_canonical_sha256",
            ),
            execution_policy_sha256=_text(document, "execution_policy_sha256"),
            source_inputs_sha256=_text(document, "source_inputs_sha256"),
            source_rendering_profile=_SOURCE_RENDERING_PROFILE,
        ),
        query=CanonicalTypeQueryFacts(
            query_output_sha256=_sha256_json(document),
            source_snapshot_sha256=source_snapshot_sha256,
            sealed_candidate_sha256=_text(document, "sealed_candidate_sha256"),
            candidate_direct_imports_sha256=_text(
                observation,
                "candidate_direct_imports_sha256",
            ),
            module_import_closure_sha256=_text(
                observation,
                "module_import_closure_sha256",
            ),
            observed_axioms=observed_axioms,
            observed_axioms_sha256=observed_axioms_sha256,
        ),
    )


def _object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise CanonicalTypeGateError(f"mathlib declaration query {label} is not an object")
    return cast(dict[str, object], value)


def _text(document: dict[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise CanonicalTypeGateError(f"mathlib declaration query {key} is not text")
    return value


def _string_tuple(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CanonicalTypeGateError(f"mathlib declaration query {label} is not a string list")
    return tuple(cast(list[str], value))


def _sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise CanonicalTypeGateError(f"canonical type query cannot read {path.name}") from error


def _canary_document(
    *,
    repo_root: Path,
    source_cache: Path,
    build_resource_cache: Path,
    image: str,
) -> dict[str, object]:
    worker_image_digest = image.rpartition("@")[2]
    reference_source = "theorem identity (n : Nat) : n = n"
    candidate_source = "lemma identity (n : Nat) : Eq n n"
    reference_hash = digest_text(HashKindV1.STATEMENT_SOURCE, reference_source)
    candidate_hash = digest_text(HashKindV1.STATEMENT_SOURCE, candidate_source)
    lake_manifest_sha256 = _file_sha256(repo_root / "Library" / "lake-manifest.json")
    query = OciMathlibCanonicalTypeQuery(
        repo_root=repo_root,
        source_cache=source_cache,
        build_resource_cache=build_resource_cache,
        image=image,
    )
    binding = CanonicalTypeGateBinding(
        contract_id="prefreeze-canary",
        revision=1,
        draft_contract_hash=digest_text(HashKindV1.CONTRACT, "prefreeze-canary"),
        source_hash=digest_text(HashKindV1.SOURCE_BYTES, "prefreeze-canary"),
        generation_task_hash=digest_text(HashKindV1.PROMPT, "prefreeze-canary"),
        selected_statement_hash=reference_hash,
        environment_hash=digest_text(HashKindV1.ENVIRONMENT, image),
        declaration=_CANARY_DECLARATION,
        lean_version=_LEAN_VERSION,
        mathlib_revision=oci_mathlib_worker.MATHLIB_REVISION,
        lake_manifest_sha256=lake_manifest_sha256,
        worker_image_digest=worker_image_digest,
        expected_elaborated_type=_CANARY_TYPE,
        expected_elaborated_type_hash=digest_text(
            HashKindV1.ELABORATED_TYPE,
            _CANARY_TYPE,
        ),
    )
    reference = CanonicalTypeQueryRequest(
        subject_id="contract-selected-reference",
        statement_source=reference_source,
        statement_source_hash=reference_hash,
        declaration=_CANARY_DECLARATION,
        namespace="AutoLean.BuilderCanonicalTypeCanary",
        imports_allowlist=("Mathlib.ModelTheory.Semantics",),
    )
    candidate = CanonicalTypeQueryRequest(
        subject_id="candidate-lemma-syntax",
        statement_source=candidate_source,
        statement_source_hash=candidate_hash,
        declaration=_CANARY_DECLARATION,
        namespace="AutoLean.BuilderCanonicalTypeCanary",
        imports_allowlist=("Mathlib.ModelTheory.Semantics",),
    )
    second_candidate = CanonicalTypeQueryRequest(
        subject_id="candidate-theorem-syntax",
        statement_source=reference_source,
        statement_source_hash=reference_hash,
        declaration=_CANARY_DECLARATION,
        namespace="AutoLean.BuilderCanonicalTypeCanary",
        imports_allowlist=("Mathlib.ModelTheory.Semantics",),
    )
    evidence = run_canonical_type_gate(
        query,
        binding=binding,
        reference=reference,
        candidates=(candidate, second_candidate),
    )
    evidence_payload = evidence.payload()
    return {
        "schema_version": "autolean.builder-canonical-type-canary.v1",
        "status": "passed",
        "assurance": CanonicalTypeQueryAssurance.LOCAL_OCI_PREFREEZE.value,
        "promotion_authority": False,
        "proof_or_axiom_admission": False,
        "image": image,
        "canonical_type_gate_sha256": digest_bytes(
            HashKindV1.FREEZE_EVIDENCE,
            canonical_json_bytes(evidence_payload),
        ).value,
        "canonical_type_gate": evidence_payload,
    }


def _image_available(image: str) -> bool:
    try:
        completed = subprocess.run(
            ("docker", "image", "inspect", image),
            check=False,
            capture_output=True,
            shell=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _wsl_home() -> str:
    try:
        completed = subprocess.run(
            (
                "wsl.exe",
                "-d",
                oci_mathlib_worker.WSL_DISTRIBUTION,
                "--",
                "/usr/bin/printenv",
                "HOME",
            ),
            check=False,
            capture_output=True,
            shell=False,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CanonicalTypeGateError("canonical type canary cannot resolve the WSL home") from error
    value = completed.stdout.strip()
    path = PurePosixPath(value)
    if (
        completed.returncode != 0
        or not value
        or not path.is_absolute()
        or ".." in path.parts
        or str(path) != value
    ):
        raise CanonicalTypeGateError("canonical type canary received an invalid WSL home")
    return value


def _delegate_to_wsl(arguments: argparse.Namespace) -> int:
    root = Path(arguments.repo_root).resolve()
    translated_root = oci_mathlib_worker._wsl_path(root)
    wsl_home = _wsl_home()
    python_path = ":".join(
        (
            f"{translated_root}/Builder/src",
            f"{translated_root}/packages/contracts/src",
            f"{translated_root}/packages/control_plane/src",
            f"{translated_root}/Prover/src",
        )
    )
    command = [
        "wsl.exe",
        "-d",
        oci_mathlib_worker.WSL_DISTRIBUTION,
        "--cd",
        translated_root,
        "--",
        "/usr/bin/env",
        f"PATH={wsl_home}/.local/bin:/usr/local/bin:/usr/bin:/bin",
        f"UV_PROJECT_ENVIRONMENT={wsl_home}/.cache/autolean/oci-worker-python",
        f"PYTHONPATH={python_path}",
        "uv",
        "run",
        "--frozen",
        "--no-sync",
        "python",
        "-m",
        "scripts.builder_canonical_type_gate",
        "--image",
        arguments.image,
        "--repo-root",
        oci_mathlib_worker._wsl_path(root),
        "--source-cache",
        oci_mathlib_worker._wsl_path(Path(arguments.source_cache).resolve()),
        "--build-resource-cache",
        oci_mathlib_worker._wsl_path(Path(arguments.build_resource_cache).resolve()),
        "--native",
    ]
    return subprocess.run(command, check=False, shell=False).returncode


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="digest-pinned local mathlib image")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-cache", type=Path, default=mathlib_source_lock.DEFAULT_CACHE)
    parser.add_argument(
        "--build-resource-cache",
        type=Path,
        default=mathlib_build_resources.DEFAULT_CACHE,
    )
    parser.add_argument("--native", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(argv)
    if os.name != "posix" and not arguments.native:
        return _delegate_to_wsl(arguments)
    if not _image_available(arguments.image):
        print(
            json.dumps(
                {
                    "schema_version": "autolean.builder-canonical-type-canary.v1",
                    "status": "skipped",
                    "reason": "digest-pinned local image is unavailable",
                    "assurance": "none",
                    "promotion_authority": False,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    document = _canary_document(
        repo_root=Path(arguments.repo_root).resolve(),
        source_cache=Path(arguments.source_cache).resolve(),
        build_resource_cache=Path(arguments.build_resource_cache).resolve(),
        image=arguments.image,
    )
    print(
        json.dumps(
            document,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
