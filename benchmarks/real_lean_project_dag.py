"""Validate the side-by-side real Lean content fixture used for T7 preflight.

This is deliberately separate from :mod:`benchmarks.project_dag`.  The older v1
fixture models control-plane scheduling with synthetic node identifiers; this module
binds a small, actual Lean source tree to a declaration-level content graph.  It is
not a Builder contract, a proof-verification result, or a replacement for either
graph.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class RealLeanProjectDagError(ValueError):
    """The T7 preflight fixture or its content graph is malformed."""


_SCHEMA_VERSION = "autolean.real-lean-project-dag-preflight.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODULE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")
_NODE_ID = re.compile(r"^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$")
_IMPORT = re.compile(r"^import\s+([A-Za-z][A-Za-z0-9_.]*)\s*$", re.MULTILINE)
_NAMESPACE = re.compile(r"^namespace\s+([A-Za-z][A-Za-z0-9_.]*)\s*$", re.MULTILINE)
_DECLARATION = re.compile(r"^(?:def|theorem|lemma)\s+([A-Za-z][A-Za-z0-9_]*)\b", re.MULTILINE)


@dataclass(frozen=True, slots=True)
class LeanModuleV1:
    """An exact Lean module source binding inside the content fixture."""

    module: str
    file: str
    imports: tuple[str, ...]
    source_sha256: str

    def __post_init__(self) -> None:
        if _MODULE.fullmatch(self.module) is None:
            raise RealLeanProjectDagError("Lean module name is invalid")
        if not self.file.endswith(".lean") or not _safe_relative_file(self.file):
            raise RealLeanProjectDagError("Lean module file is invalid")
        if len(set(self.imports)) != len(self.imports) or any(
            _MODULE.fullmatch(value) is None for value in self.imports
        ):
            raise RealLeanProjectDagError("Lean module imports are invalid")
        if _SHA256.fullmatch(self.source_sha256) is None:
            raise RealLeanProjectDagError("Lean module source hash is invalid")


@dataclass(frozen=True, slots=True)
class LeanDeclarationV1:
    """One declaration identity and its explicitly curated content dependencies."""

    node_id: str
    declaration: str
    module: str
    depends_on: tuple[str, ...]

    def __post_init__(self) -> None:
        if _NODE_ID.fullmatch(self.node_id) is None:
            raise RealLeanProjectDagError("Lean declaration node ID is invalid")
        if _MODULE.fullmatch(self.declaration) is None:
            raise RealLeanProjectDagError("Lean declaration identity is invalid")
        if _MODULE.fullmatch(self.module) is None:
            raise RealLeanProjectDagError("Lean declaration module is invalid")
        if self.node_id in self.depends_on or len(set(self.depends_on)) != len(self.depends_on):
            raise RealLeanProjectDagError("Lean declaration dependencies are invalid")
        if any(_NODE_ID.fullmatch(value) is None for value in self.depends_on):
            raise RealLeanProjectDagError("Lean declaration dependency ID is invalid")


@dataclass(frozen=True, slots=True)
class RealLeanProjectDagV1:
    """A byte-bound, declaration-level Lean content fixture for T7 preflight only."""

    name: str
    root: Path
    source_root: str
    modules: tuple[LeanModuleV1, ...]
    declarations: tuple[LeanDeclarationV1, ...]
    manifest_path: Path
    loaded_manifest_sha256: str

    def __post_init__(self) -> None:
        if not self.name.strip() or not _safe_relative_directory(self.source_root):
            raise RealLeanProjectDagError("real Lean fixture metadata is invalid")
        if _SHA256.fullmatch(self.loaded_manifest_sha256) is None:
            raise RealLeanProjectDagError("real Lean fixture manifest hash is invalid")
        module_names = tuple(module.module for module in self.modules)
        module_files = tuple(module.file for module in self.modules)
        declaration_ids = tuple(item.node_id for item in self.declarations)
        declaration_names = tuple(item.declaration for item in self.declarations)
        if len(set(module_names)) != len(module_names) or len(set(module_files)) != len(
            module_files
        ):
            raise RealLeanProjectDagError("Lean fixture modules must be unique")
        if len(set(declaration_ids)) != len(declaration_ids) or len(set(declaration_names)) != len(
            declaration_names
        ):
            raise RealLeanProjectDagError("Lean fixture declarations must be unique")
        known_modules = set(module_names)
        known_nodes = set(declaration_ids)
        for module in self.modules:
            expected_file = (
                (PurePosixPath(self.source_root) / PurePosixPath(*module.module.split(".")))
                .with_suffix(".lean")
                .as_posix()
            )
            if module.file != expected_file:
                raise RealLeanProjectDagError("Lean module file does not match its module identity")
            if set(module.imports) - known_modules:
                raise RealLeanProjectDagError("Lean module imports an unknown fixture module")
        for declaration in self.declarations:
            if declaration.module not in known_modules:
                raise RealLeanProjectDagError("Lean declaration belongs to an unknown module")
            if not declaration.declaration.startswith(f"{declaration.module}."):
                raise RealLeanProjectDagError("Lean declaration identity does not match its module")
            if set(declaration.depends_on) - known_nodes:
                raise RealLeanProjectDagError("Lean declaration depends on an unknown node")
        self.module_topological_order()
        self.declaration_topological_order()
        self._validate_cross_module_edges()
        self._validate_source_bindings()

    @property
    def modules_by_name(self) -> dict[str, LeanModuleV1]:
        return {module.module: module for module in self.modules}

    @property
    def declarations_by_id(self) -> dict[str, LeanDeclarationV1]:
        return {item.node_id: item for item in self.declarations}

    def module_topological_order(self) -> tuple[LeanModuleV1, ...]:
        modules = self.modules_by_name
        reverse: dict[str, list[str]] = {name: [] for name in modules}
        indegree = {name: len(module.imports) for name, module in modules.items()}
        for module in modules.values():
            for imported in module.imports:
                reverse[imported].append(module.module)
        ready = deque(sorted(name for name, degree in indegree.items() if degree == 0))
        ordered: list[LeanModuleV1] = []
        while ready:
            current = ready.popleft()
            ordered.append(modules[current])
            for dependent in sorted(reverse[current]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    ready.append(dependent)
        if len(ordered) != len(modules):
            raise RealLeanProjectDagError("Lean module imports must be acyclic")
        return tuple(ordered)

    def declaration_topological_order(self) -> tuple[LeanDeclarationV1, ...]:
        declarations = self.declarations_by_id
        reverse: dict[str, list[str]] = {node_id: [] for node_id in declarations}
        indegree = {node_id: len(item.depends_on) for node_id, item in declarations.items()}
        for item in declarations.values():
            for dependency in item.depends_on:
                reverse[dependency].append(item.node_id)
        ready = deque(sorted(node_id for node_id, degree in indegree.items() if degree == 0))
        ordered: list[LeanDeclarationV1] = []
        while ready:
            current = ready.popleft()
            ordered.append(declarations[current])
            for dependent in sorted(reverse[current]):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    ready.append(dependent)
        if len(ordered) != len(declarations):
            raise RealLeanProjectDagError("Lean declaration graph must be acyclic")
        return tuple(ordered)

    def dependency_closure(self, node_ids: frozenset[str]) -> tuple[LeanDeclarationV1, ...]:
        """Return a deterministic transitive dependency closure, including requested nodes."""

        declarations = self.declarations_by_id
        unknown = node_ids - set(declarations)
        if unknown:
            raise RealLeanProjectDagError("dependency closure contains an unknown declaration")
        closure = set(node_ids)
        queue = deque(sorted(node_ids))
        while queue:
            current = queue.popleft()
            for dependency in declarations[current].depends_on:
                if dependency not in closure:
                    closure.add(dependency)
                    queue.append(dependency)
        return tuple(
            item for item in self.declaration_topological_order() if item.node_id in closure
        )

    def affected_by(self, changed: frozenset[str]) -> tuple[LeanDeclarationV1, ...]:
        """Return the exact reverse declaration closure for an API change."""

        declarations = self.declarations_by_id
        unknown = changed - set(declarations)
        if unknown:
            raise RealLeanProjectDagError("API change contains an unknown declaration")
        reverse: dict[str, set[str]] = {node_id: set() for node_id in declarations}
        for item in declarations.values():
            for dependency in item.depends_on:
                reverse[dependency].add(item.node_id)
        affected = set(changed)
        queue = deque(sorted(changed))
        while queue:
            current = queue.popleft()
            for dependent in sorted(reverse[current]):
                if dependent not in affected:
                    affected.add(dependent)
                    queue.append(dependent)
        return tuple(
            item for item in self.declaration_topological_order() if item.node_id in affected
        )

    def manifest_sha256(self) -> str:
        """Return the digest of the exact manifest bytes parsed by the loader."""

        return self.loaded_manifest_sha256

    def source_path(self, module: LeanModuleV1) -> Path:
        root = self.root.resolve()
        raw_candidate = root / PurePosixPath(module.file)
        if raw_candidate.is_symlink() or not raw_candidate.is_file():
            raise RealLeanProjectDagError("Lean source file is unavailable or linked")
        candidate = raw_candidate.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise RealLeanProjectDagError("Lean source file escapes fixture root") from error
        return candidate

    def _validate_cross_module_edges(self) -> None:
        modules = self.modules_by_name
        declarations = self.declarations_by_id
        for item in self.declarations:
            imported_modules = set(modules[item.module].imports)
            for dependency_id in item.depends_on:
                dependency_module = declarations[dependency_id].module
                if dependency_module != item.module and dependency_module not in imported_modules:
                    raise RealLeanProjectDagError(
                        "cross-module declaration dependency lacks a matching Lean import"
                    )
        for module in self.modules:
            required_imports = {
                declarations[dependency].module
                for item in self.declarations
                if item.module == module.module
                for dependency in item.depends_on
                if declarations[dependency].module != module.module
            }
            if set(module.imports) != required_imports:
                raise RealLeanProjectDagError(
                    "Lean module imports do not match cross-module content dependencies"
                )

    def _validate_source_bindings(self) -> None:
        declarations_by_module: dict[str, set[str]] = {
            module.module: set() for module in self.modules
        }
        for item in self.declarations:
            declarations_by_module[item.module].add(item.declaration)
        for module in self.modules:
            source = self.source_path(module)
            raw = source.read_bytes()
            if hashlib.sha256(raw).hexdigest() != module.source_sha256:
                raise RealLeanProjectDagError("Lean source hash does not match the manifest")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RealLeanProjectDagError("Lean source is not UTF-8") from error
            source_imports = tuple(_IMPORT.findall(text))
            if source_imports != module.imports:
                raise RealLeanProjectDagError("Lean source imports do not match the manifest")
            namespaces = tuple(_NAMESPACE.findall(text))
            if namespaces != (module.module,):
                raise RealLeanProjectDagError(
                    "Lean source namespace does not match module identity"
                )
            source_declarations = {
                f"{module.module}.{short_name}" for short_name in _DECLARATION.findall(text)
            }
            if len(source_declarations) != len(_DECLARATION.findall(text)):
                raise RealLeanProjectDagError("Lean source declares a duplicate identity")
            if source_declarations != declarations_by_module[module.module]:
                raise RealLeanProjectDagError("Lean source declarations do not match the manifest")


def _safe_relative_file(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value) and not path.is_absolute() and ".." not in path.parts and "." not in path.parts
    )


def _safe_relative_directory(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value) and not path.is_absolute() and ".." not in path.parts and "." not in path.parts
    )


def _load_json_object(path: Path) -> tuple[dict[str, object], str]:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise RealLeanProjectDagError("real Lean fixture JSON contains a duplicate key")
            document[key] = value
        return document

    try:
        content = path.read_bytes()
        value = json.loads(content.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RealLeanProjectDagError("real Lean fixture manifest could not be parsed") from error
    if not isinstance(value, dict):
        raise RealLeanProjectDagError("real Lean fixture manifest must be an object")
    return value, hashlib.sha256(content).hexdigest()


def _expect_str(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise RealLeanProjectDagError(f"{label} must be a string")
    return value


def _expect_str_list(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RealLeanProjectDagError(f"{label} must be an array of strings")
    return tuple(value)


def load_real_lean_project_dag(path: str | Path) -> RealLeanProjectDagV1:
    """Load and byte-validate the isolated real Lean content fixture."""

    manifest_path = Path(path)
    raw, loaded_manifest_sha256 = _load_json_object(manifest_path)
    expected_root = {"schema_version", "name", "source_root", "modules", "declarations"}
    if set(raw) != expected_root:
        raise RealLeanProjectDagError("real Lean fixture manifest has unexpected fields")
    if raw["schema_version"] != _SCHEMA_VERSION:
        raise RealLeanProjectDagError("real Lean fixture schema version is not supported")
    modules_raw = raw["modules"]
    declarations_raw = raw["declarations"]
    if not isinstance(modules_raw, list) or not isinstance(declarations_raw, list):
        raise RealLeanProjectDagError("real Lean fixture arrays are invalid")
    modules: list[LeanModuleV1] = []
    for item in modules_raw:
        if not isinstance(item, dict) or set(item) != {
            "module",
            "file",
            "imports",
            "source_sha256",
        }:
            raise RealLeanProjectDagError("Lean module manifest entry has unexpected fields")
        modules.append(
            LeanModuleV1(
                module=_expect_str(item["module"], "Lean module"),
                file=_expect_str(item["file"], "Lean module file"),
                imports=_expect_str_list(item["imports"], "Lean module imports"),
                source_sha256=_expect_str(item["source_sha256"], "Lean source hash"),
            )
        )
    declarations: list[LeanDeclarationV1] = []
    for item in declarations_raw:
        if not isinstance(item, dict) or set(item) != {"id", "declaration", "module", "depends_on"}:
            raise RealLeanProjectDagError("Lean declaration manifest entry has unexpected fields")
        declarations.append(
            LeanDeclarationV1(
                node_id=_expect_str(item["id"], "Lean declaration ID"),
                declaration=_expect_str(item["declaration"], "Lean declaration identity"),
                module=_expect_str(item["module"], "Lean declaration module"),
                depends_on=_expect_str_list(item["depends_on"], "Lean declaration dependencies"),
            )
        )
    return RealLeanProjectDagV1(
        name=_expect_str(raw["name"], "real Lean fixture name"),
        root=manifest_path.parent,
        source_root=_expect_str(raw["source_root"], "real Lean source root"),
        modules=tuple(modules),
        declarations=tuple(declarations),
        manifest_path=manifest_path,
        loaded_manifest_sha256=loaded_manifest_sha256,
    )


def load_default_real_lean_project_dag() -> RealLeanProjectDagV1:
    """Load the committed 20-declaration Lean content preflight fixture."""

    return load_real_lean_project_dag(
        Path(__file__).with_name("project_dag") / "real-lean-content-manifest.v1.json"
    )
