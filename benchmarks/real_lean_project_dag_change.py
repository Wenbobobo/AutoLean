"""Validate the committed changed-source case for the T7 real-Lean preflight.

The case is intentionally curated.  It binds one known public API change, the exact
source edits needed by its successor, and the expected declaration/module reverse
closures.  It does not infer dependencies from Lean source and is not a general
incremental-build planner.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from benchmarks.real_lean_project_dag import (
    RealLeanProjectDagError,
    RealLeanProjectDagV1,
    load_real_lean_project_dag,
)


class RealLeanChangeCaseError(ValueError):
    """The T7 changed-source case or one of its bindings is malformed."""


_SCHEMA_VERSION = "autolean.real-lean-project-dag-change-case.v1"
_SHA256_LENGTH = 64
_EDIT_KINDS = frozenset({"upstream_api_change", "successor_compatibility"})


@dataclass(frozen=True, slots=True)
class SourceReplacementV1:
    """One exact UTF-8 replacement inside a byte-bound source edit."""

    old: str
    new: str
    expected_occurrences: int

    def __post_init__(self) -> None:
        if not self.old or self.old == self.new:
            raise RealLeanChangeCaseError("source replacement must change non-empty text")
        if self.expected_occurrences != 1:
            raise RealLeanChangeCaseError("each source replacement must match exactly once")


@dataclass(frozen=True, slots=True)
class SourceEditV1:
    """One successor source derived exactly from a baseline fixture module."""

    kind: str
    module: str
    file: str
    baseline_source_sha256: str
    successor_source_sha256: str
    replacements: tuple[SourceReplacementV1, ...]

    def __post_init__(self) -> None:
        if self.kind not in _EDIT_KINDS:
            raise RealLeanChangeCaseError("source edit kind is invalid")
        if not self.module or not self.file.endswith(".lean"):
            raise RealLeanChangeCaseError("source edit module or file is invalid")
        if not _is_sha256(self.baseline_source_sha256) or not _is_sha256(
            self.successor_source_sha256
        ):
            raise RealLeanChangeCaseError("source edit hash is invalid")
        if self.baseline_source_sha256 == self.successor_source_sha256:
            raise RealLeanChangeCaseError("source edit must change the source hash")
        if not self.replacements:
            raise RealLeanChangeCaseError("source edit must contain a replacement")

    def apply(self, source: bytes) -> bytes:
        """Apply the bound replacements and verify both endpoint hashes."""

        if hashlib.sha256(source).hexdigest() != self.baseline_source_sha256:
            raise RealLeanChangeCaseError("source edit baseline hash does not match")
        try:
            rendered = source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RealLeanChangeCaseError("source edit input is not UTF-8") from error
        for replacement in self.replacements:
            if rendered.count(replacement.old) != replacement.expected_occurrences:
                raise RealLeanChangeCaseError("source replacement occurrence count does not match")
            rendered = rendered.replace(replacement.old, replacement.new)
        result = rendered.encode("utf-8")
        if hashlib.sha256(result).hexdigest() != self.successor_source_sha256:
            raise RealLeanChangeCaseError("source edit successor hash does not match")
        return result


@dataclass(frozen=True, slots=True)
class RealLeanChangeCaseV1:
    """A fixed changed-source propagation case over the 20-declaration fixture."""

    name: str
    root: Path
    baseline_manifest_file: str
    baseline_manifest_sha256: str
    changed_declaration_ids: tuple[str, ...]
    expected_declaration_reverse_closure: tuple[str, ...]
    expected_module_reverse_import_closure: tuple[str, ...]
    failure_probe_module: str
    expected_baseline_canonical_type_sha256: str
    expected_successor_canonical_type_sha256: str
    edits: tuple[SourceEditV1, ...]
    manifest_path: Path
    loaded_manifest_sha256: str
    baseline: RealLeanProjectDagV1

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise RealLeanChangeCaseError("change case name is empty")
        if not _is_sha256(self.loaded_manifest_sha256):
            raise RealLeanChangeCaseError("loaded change-case manifest hash is invalid")
        if not _is_sha256(self.baseline_manifest_sha256):
            raise RealLeanChangeCaseError("baseline manifest hash is invalid")
        if self.baseline.manifest_sha256() != self.baseline_manifest_sha256:
            raise RealLeanChangeCaseError("baseline manifest hash does not match")
        if not self.changed_declaration_ids or len(set(self.changed_declaration_ids)) != len(
            self.changed_declaration_ids
        ):
            raise RealLeanChangeCaseError("changed declaration IDs are invalid")
        expected_declarations = tuple(
            item.node_id
            for item in self.baseline.affected_by(frozenset(self.changed_declaration_ids))
        )
        if self.expected_declaration_reverse_closure != expected_declarations:
            raise RealLeanChangeCaseError(
                "declaration reverse closure does not match baseline graph"
            )
        expected_modules = self._module_reverse_import_closure()
        if self.expected_module_reverse_import_closure != expected_modules:
            raise RealLeanChangeCaseError(
                "module reverse-import closure does not match baseline graph"
            )
        if self.failure_probe_module not in expected_modules:
            raise RealLeanChangeCaseError("failure probe is outside the affected module closure")
        if not _is_sha256(self.expected_baseline_canonical_type_sha256) or not _is_sha256(
            self.expected_successor_canonical_type_sha256
        ):
            raise RealLeanChangeCaseError("expected canonical type hash is invalid")
        if (
            self.expected_baseline_canonical_type_sha256
            == self.expected_successor_canonical_type_sha256
        ):
            raise RealLeanChangeCaseError("changed API must bind distinct canonical type hashes")
        changed_modules = {
            self.baseline.declarations_by_id[node_id].module
            for node_id in self.changed_declaration_ids
        }
        if len(changed_modules) != 1:
            raise RealLeanChangeCaseError("preflight change must originate in exactly one module")
        changed_module = next(iter(changed_modules))
        edits_by_module = {edit.module: edit for edit in self.edits}
        if len(edits_by_module) != len(self.edits):
            raise RealLeanChangeCaseError("source edit modules must be unique")
        if set(edits_by_module) != set(expected_modules):
            raise RealLeanChangeCaseError(
                "source edits must cover the module rebuild closure exactly"
            )
        if edits_by_module[changed_module].kind != "upstream_api_change":
            raise RealLeanChangeCaseError("changed module must contain the upstream API edit")
        if any(
            edit.kind != "successor_compatibility"
            for module, edit in edits_by_module.items()
            if module != changed_module
        ):
            raise RealLeanChangeCaseError("downstream edits must be successor compatibility edits")
        modules = self.baseline.modules_by_name
        for edit in self.edits:
            module = modules.get(edit.module)
            if module is None or module.file != edit.file:
                raise RealLeanChangeCaseError("source edit does not match a baseline module")
            if module.source_sha256 != edit.baseline_source_sha256:
                raise RealLeanChangeCaseError("source edit baseline binding does not match fixture")
            edit.apply(self.baseline.source_path(module).read_bytes())

    @property
    def edits_by_module(self) -> dict[str, SourceEditV1]:
        return {edit.module: edit for edit in self.edits}

    @property
    def changed_module(self) -> str:
        modules = {
            self.baseline.declarations_by_id[node_id].module
            for node_id in self.changed_declaration_ids
        }
        return next(iter(modules))

    def manifest_sha256(self) -> str:
        """Return the hash captured from the exact bytes parsed during loading."""

        return self.loaded_manifest_sha256

    def apply_to_module(self, module: str, *, successor: bool) -> bytes:
        """Render one upstream-only or full-successor source from the baseline."""

        baseline_module = self.baseline.modules_by_name[module]
        source = self.baseline.source_path(baseline_module).read_bytes()
        edit = self.edits_by_module.get(module)
        if edit is None:
            return source
        if successor or edit.kind == "upstream_api_change":
            return edit.apply(source)
        return source

    def _module_reverse_import_closure(self) -> tuple[str, ...]:
        modules = self.baseline.modules_by_name
        changed_modules = {
            self.baseline.declarations_by_id[node_id].module
            for node_id in self.changed_declaration_ids
        }
        reverse: dict[str, set[str]] = {name: set() for name in modules}
        for module in modules.values():
            for imported in module.imports:
                reverse[imported].add(module.module)
        affected = set(changed_modules)
        queue = deque(sorted(changed_modules))
        while queue:
            current = queue.popleft()
            for dependent in sorted(reverse[current]):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return tuple(
            module.module
            for module in self.baseline.module_topological_order()
            if module.module in affected
        )


def _is_sha256(value: str) -> bool:
    return len(value) == _SHA256_LENGTH and all(
        character in "0123456789abcdef" for character in value
    )


def _manifest_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    common = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )
    if os.name == "nt":
        return common
    return (*common, metadata.st_ctime_ns)


def _read_stable_manifest(path: Path) -> bytes:
    """Read one regular manifest without mixing bytes from different file identities."""

    try:
        initial = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(initial.st_mode):
            raise RealLeanChangeCaseError("change-case manifest must be a regular non-symlink file")
        with path.open("rb") as stream:
            opened_before = os.fstat(stream.fileno())
            if _manifest_fingerprint(initial) != _manifest_fingerprint(opened_before):
                raise RealLeanChangeCaseError("change-case manifest changed before reading")
            content = stream.read()
            opened_after = os.fstat(stream.fileno())
        final = path.lstat()
    except RealLeanChangeCaseError:
        raise
    except OSError as error:
        raise RealLeanChangeCaseError("change-case manifest could not be read") from error
    expected = _manifest_fingerprint(initial)
    if (
        _manifest_fingerprint(opened_before) != expected
        or _manifest_fingerprint(opened_after) != expected
        or _manifest_fingerprint(final) != expected
        or len(content) != initial.st_size
    ):
        raise RealLeanChangeCaseError("change-case manifest changed while reading")
    return content


def _load_json_object(path: Path) -> tuple[dict[str, object], str]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise RealLeanChangeCaseError("change-case JSON contains a duplicate key")
            document[key] = value
        return document

    content = _read_stable_manifest(path)
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RealLeanChangeCaseError("change-case manifest could not be parsed") from error
    if not isinstance(value, dict):
        raise RealLeanChangeCaseError("change-case manifest must be an object")
    return value, hashlib.sha256(content).hexdigest()


def _expect_str(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RealLeanChangeCaseError(f"{label} must be a string")
    return value


def _expect_str_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RealLeanChangeCaseError(f"{label} must be an array of strings")
    return tuple(value)


def _safe_manifest_reference(root: Path, value: str) -> Path:
    if not value or "\\" in value:
        raise RealLeanChangeCaseError("baseline manifest reference is invalid")
    candidate = root / Path(*value.split("/"))
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RealLeanChangeCaseError("baseline manifest reference escapes case root") from error
    if candidate.is_symlink() or not candidate.is_file():
        raise RealLeanChangeCaseError("baseline manifest reference is unavailable or linked")
    return candidate


def load_real_lean_change_case(path: str | Path) -> RealLeanChangeCaseV1:
    """Load and validate one committed changed-source propagation case."""

    manifest_path = Path(path)
    raw, loaded_manifest_sha256 = _load_json_object(manifest_path)
    expected_root = {
        "schema_version",
        "name",
        "baseline_manifest_file",
        "baseline_manifest_sha256",
        "changed_declaration_ids",
        "expected_declaration_reverse_closure",
        "expected_module_reverse_import_closure",
        "failure_probe_module",
        "expected_baseline_canonical_type_sha256",
        "expected_successor_canonical_type_sha256",
        "edits",
    }
    if set(raw) != expected_root:
        raise RealLeanChangeCaseError("change-case manifest has unexpected fields")
    if raw["schema_version"] != _SCHEMA_VERSION:
        raise RealLeanChangeCaseError("change-case schema version is not supported")
    root = manifest_path.parent
    baseline_file = _expect_str(raw["baseline_manifest_file"], "baseline manifest file")
    baseline_path = _safe_manifest_reference(root, baseline_file)
    try:
        baseline = load_real_lean_project_dag(baseline_path)
    except RealLeanProjectDagError as error:
        raise RealLeanChangeCaseError("baseline real-Lean fixture is invalid") from error
    edits_raw = raw["edits"]
    if not isinstance(edits_raw, list):
        raise RealLeanChangeCaseError("source edits must be an array")
    edits: list[SourceEditV1] = []
    for item in edits_raw:
        if not isinstance(item, dict) or set(item) != {
            "kind",
            "module",
            "file",
            "baseline_source_sha256",
            "successor_source_sha256",
            "replacements",
        }:
            raise RealLeanChangeCaseError("source edit has unexpected fields")
        replacements_raw = item["replacements"]
        if not isinstance(replacements_raw, list):
            raise RealLeanChangeCaseError("source replacements must be an array")
        replacements: list[SourceReplacementV1] = []
        for replacement in replacements_raw:
            if not isinstance(replacement, dict) or set(replacement) != {
                "old",
                "new",
                "expected_occurrences",
            }:
                raise RealLeanChangeCaseError("source replacement has unexpected fields")
            occurrences = replacement["expected_occurrences"]
            if not isinstance(occurrences, int) or isinstance(occurrences, bool):
                raise RealLeanChangeCaseError("source replacement count must be an integer")
            replacements.append(
                SourceReplacementV1(
                    old=_expect_str(replacement["old"], "source replacement old text"),
                    new=_expect_str(replacement["new"], "source replacement new text"),
                    expected_occurrences=occurrences,
                )
            )
        edits.append(
            SourceEditV1(
                kind=_expect_str(item["kind"], "source edit kind"),
                module=_expect_str(item["module"], "source edit module"),
                file=_expect_str(item["file"], "source edit file"),
                baseline_source_sha256=_expect_str(
                    item["baseline_source_sha256"], "baseline source hash"
                ),
                successor_source_sha256=_expect_str(
                    item["successor_source_sha256"], "successor source hash"
                ),
                replacements=tuple(replacements),
            )
        )
    return RealLeanChangeCaseV1(
        name=_expect_str(raw["name"], "change case name"),
        root=root,
        baseline_manifest_file=baseline_file,
        baseline_manifest_sha256=_expect_str(
            raw["baseline_manifest_sha256"], "baseline manifest hash"
        ),
        changed_declaration_ids=_expect_str_list(
            raw["changed_declaration_ids"], "changed declaration IDs"
        ),
        expected_declaration_reverse_closure=_expect_str_list(
            raw["expected_declaration_reverse_closure"],
            "expected declaration reverse closure",
        ),
        expected_module_reverse_import_closure=_expect_str_list(
            raw["expected_module_reverse_import_closure"],
            "expected module reverse-import closure",
        ),
        failure_probe_module=_expect_str(raw["failure_probe_module"], "failure probe module"),
        expected_baseline_canonical_type_sha256=_expect_str(
            raw["expected_baseline_canonical_type_sha256"],
            "expected baseline canonical type hash",
        ),
        expected_successor_canonical_type_sha256=_expect_str(
            raw["expected_successor_canonical_type_sha256"],
            "expected successor canonical type hash",
        ),
        edits=tuple(edits),
        manifest_path=manifest_path,
        loaded_manifest_sha256=loaded_manifest_sha256,
        baseline=baseline,
    )


def load_default_real_lean_change_case() -> RealLeanChangeCaseV1:
    """Load the committed Arithmetic.score changed-source propagation case."""

    return load_real_lean_change_case(
        Path(__file__).with_name("project_dag") / "real-lean-change-case.v1.json"
    )
