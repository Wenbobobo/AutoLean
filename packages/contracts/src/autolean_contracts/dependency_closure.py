from __future__ import annotations

import json
import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal, NoReturn

from pydantic import Field, model_validator

from .base import ContractModel
from .hashing import (
    DigestV1,
    HashKindV1,
    StableIdentifierV1,
    canonical_json_bytes,
    digest_bytes,
    digest_model,
    require_digest_kind,
)

DEPENDENCY_CLOSURE_MANIFEST_MEDIA_TYPE = (
    "application/vnd.autolean.dependency-closure-manifest.v1+json"
)
LEAN_OLEAN_MEDIA_TYPE = "application/vnd.lean.olean"
VERIFICATION_EVIDENCE_MEDIA_TYPE = "application/vnd.autolean.verification-evidence-artifact+json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LEAN_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_LEAN_MODULE = re.compile(r"^[A-Z][A-Za-z0-9_]*(?:\.[A-Z][A-Za-z0-9_]*)+$")
_SAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class DependencyClosureFileRoleV1(StrEnum):
    OLEAN = "lean_olean"


class DependencyDeclarationKindV1(StrEnum):
    """Stage A inventory classification.

    THEOREM covers every proof-bearing theorem, opaque, or axiom-like declaration.
    DEFINITION is reserved for transparent, non-proposition-bearing helpers; Stage B must observe
    that property independently before the manifest can gain authority.
    """

    DEFINITION = "definition"
    THEOREM = "theorem"
    INSTANCE = "instance"
    NOTATION = "notation"


class DependencyClosureArtifactRefV1(ContractModel):
    """A storage-neutral reference to one exact blob.

    No URI or host path is included. Stage B may resolve the content identity through a
    claim-scoped artifact reader, but the contract never grants arbitrary store access.
    """

    schema_version: Literal["1.0"] = "1.0"
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(gt=0)
    media_type: str = Field(min_length=1, max_length=160)


class DependencyClosureFileV1(ContractModel):
    relative_path: str = Field(min_length=1, max_length=1024)
    artifact: DependencyClosureArtifactRefV1
    role: DependencyClosureFileRoleV1 = DependencyClosureFileRoleV1.OLEAN

    @model_validator(mode="after")
    def validate_path_and_media_type(self) -> DependencyClosureFileV1:
        _validate_runtime_path(self.relative_path)
        if self.artifact.media_type != LEAN_OLEAN_MEDIA_TYPE:
            raise ValueError("dependency runtime files must use the Lean OLean media type")
        return self


class DependencyClosureModuleV1(ContractModel):
    module_name: str = Field(min_length=1, max_length=512)
    olean_path: str = Field(min_length=1, max_length=1024)
    direct_imports: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_module(self) -> DependencyClosureModuleV1:
        _validate_module_name(self.module_name)
        _validate_runtime_path(self.olean_path)
        expected_path = self.module_name.replace(".", "/") + ".olean"
        if self.olean_path != expected_path:
            raise ValueError("dependency module name does not match its OLean path")
        _require_sorted_unique(self.direct_imports, label="dependency module direct imports")
        for imported in self.direct_imports:
            _validate_module_name(imported, require_autolean=False)
        if self.module_name in self.direct_imports:
            raise ValueError("dependency module cannot directly import itself")
        return self


class DependencyDeclarationInventoryV1(ContractModel):
    declaration_name: str = Field(min_length=1, max_length=1024)
    kind: DependencyDeclarationKindV1
    canonical_type_hash: DigestV1
    observed_axioms: tuple[str, ...] = ()
    module_name: str = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_declaration(self) -> DependencyDeclarationInventoryV1:
        _validate_owned_declaration_name(self.declaration_name)
        _validate_module_name(self.module_name)
        require_digest_kind(
            self.canonical_type_hash,
            HashKindV1.ELABORATED_TYPE,
            "canonical_type_hash",
        )
        _validate_axioms(self.observed_axioms)
        return self


class AcceptedDependencyV1(ContractModel):
    dependency_id: StableIdentifierV1
    formal_node_id: StableIdentifierV1
    contract_id: StableIdentifierV1
    revision: int = Field(ge=1)
    contract_hash: DigestV1
    declaration_name: str = Field(min_length=1, max_length=1024)
    canonical_type_hash: DigestV1
    observed_axioms: tuple[str, ...] = ()
    module_name: str = Field(min_length=1, max_length=512)
    verification_evidence: DependencyClosureArtifactRefV1

    @model_validator(mode="after")
    def validate_dependency(self) -> AcceptedDependencyV1:
        require_digest_kind(self.contract_hash, HashKindV1.CONTRACT, "contract_hash")
        require_digest_kind(
            self.canonical_type_hash,
            HashKindV1.ELABORATED_TYPE,
            "canonical_type_hash",
        )
        _validate_owned_declaration_name(self.declaration_name)
        _validate_module_name(self.module_name)
        _validate_axioms(self.observed_axioms)
        if self.verification_evidence.media_type != VERIFICATION_EVIDENCE_MEDIA_TYPE:
            raise ValueError(
                "accepted dependency evidence must use the verification-evidence media type"
            )
        return self


class DependencyClosureManifestV1(ContractModel):
    """Canonical, content-addressed description of one external AutoLean runtime closure."""

    schema_version: Literal["autolean.dependency-closure-manifest.v1"] = (
        "autolean.dependency-closure-manifest.v1"
    )
    closure_id: StableIdentifierV1
    environment_hash: DigestV1
    tree_hash: DigestV1
    target_contract_id: StableIdentifierV1
    target_revision: int = Field(ge=1)
    target_contract_hash: DigestV1
    target_declaration: str = Field(min_length=1, max_length=1024)
    target_canonical_type_hash: DigestV1
    entry_modules: tuple[str, ...] = ()
    files: tuple[DependencyClosureFileV1, ...] = ()
    modules: tuple[DependencyClosureModuleV1, ...] = ()
    declaration_inventory: tuple[DependencyDeclarationInventoryV1, ...] = ()
    accepted_dependencies: tuple[AcceptedDependencyV1, ...] = ()

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def manifest_hash(self) -> DigestV1:
        return digest_bytes(HashKindV1.DEPENDENCY_CLOSURE, self.canonical_bytes())

    @model_validator(mode="after")
    def validate_manifest(self) -> DependencyClosureManifestV1:
        if self.closure_id.namespace != "dependency-closure":
            raise ValueError("closure_id must use the dependency-closure namespace")
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        require_digest_kind(self.tree_hash, HashKindV1.DEPENDENCY_TREE, "tree_hash")
        require_digest_kind(
            self.target_contract_hash,
            HashKindV1.CONTRACT,
            "target_contract_hash",
        )
        require_digest_kind(
            self.target_canonical_type_hash,
            HashKindV1.ELABORATED_TYPE,
            "target_canonical_type_hash",
        )
        _validate_owned_declaration_name(self.target_declaration)
        _require_sorted_unique(self.entry_modules, label="dependency entry modules")
        for module_name in self.entry_modules:
            _validate_module_name(module_name)

        file_paths = tuple(item.relative_path for item in self.files)
        module_names = tuple(item.module_name for item in self.modules)
        declaration_names = tuple(item.declaration_name for item in self.declaration_inventory)
        dependency_ids = tuple(item.dependency_id.value for item in self.accepted_dependencies)
        formal_node_ids = tuple(item.formal_node_id.value for item in self.accepted_dependencies)
        _require_sorted_unique(file_paths, label="dependency runtime file paths")
        _require_sorted_unique(module_names, label="dependency module names")
        _require_sorted_unique(declaration_names, label="dependency declaration names")
        _require_sorted_unique(dependency_ids, label="accepted dependency identifiers")
        if len(formal_node_ids) != len(set(formal_node_ids)):
            raise ValueError("accepted dependency formal node identifiers must be unique")

        known_modules = set(module_names)
        if not set(self.entry_modules) <= known_modules:
            raise ValueError("dependency entry module is absent from the module closure")
        _validate_module_closure(self.modules, self.entry_modules)
        module_paths = tuple(item.olean_path for item in self.modules)
        if set(file_paths) != set(module_paths) or len(file_paths) != len(module_paths):
            raise ValueError("dependency files must exactly match the module OLean paths")

        declarations = {item.declaration_name: item for item in self.declaration_inventory}
        accepted_declarations = tuple(item.declaration_name for item in self.accepted_dependencies)
        if len(accepted_declarations) != len(set(accepted_declarations)):
            raise ValueError("accepted dependency declarations must be unique")
        for declaration in self.declaration_inventory:
            if declaration.module_name not in known_modules:
                raise ValueError("dependency declaration refers to an unknown module")
            if declaration.declaration_name == self.target_declaration:
                raise ValueError("dependency closure contains the target declaration")
            if declaration.canonical_type_hash == self.target_canonical_type_hash:
                raise ValueError("dependency closure contains an exact-type target alias")

        unsupported_kinds = {
            item.kind
            for item in self.declaration_inventory
            if item.kind
            not in {
                DependencyDeclarationKindV1.DEFINITION,
                DependencyDeclarationKindV1.THEOREM,
            }
        }
        if unsupported_kinds:
            raise ValueError(
                "dependency inventory permits only definitions and theorem declarations"
            )
        theorem_declarations = {
            item.declaration_name
            for item in self.declaration_inventory
            if item.kind is DependencyDeclarationKindV1.THEOREM
        }
        if theorem_declarations != set(accepted_declarations):
            raise ValueError(
                "every dependency theorem must have exactly one accepted dependency binding"
            )

        for dependency in self.accepted_dependencies:
            if dependency.contract_id == self.target_contract_id:
                raise ValueError("dependency closure refers to the target contract itself")
            inventory_declaration = declarations.get(dependency.declaration_name)
            if inventory_declaration is None:
                raise ValueError("accepted dependency is absent from the declaration inventory")
            if inventory_declaration.kind is not DependencyDeclarationKindV1.THEOREM:
                raise ValueError("accepted ordinary dependencies must be theorem declarations")
            if (
                inventory_declaration.canonical_type_hash != dependency.canonical_type_hash
                or inventory_declaration.observed_axioms != dependency.observed_axioms
                or inventory_declaration.module_name != dependency.module_name
            ):
                raise ValueError(
                    "accepted dependency differs from its declaration inventory record"
                )

        expected_tree_hash = dependency_tree_hash(self.files)
        if self.tree_hash != expected_tree_hash:
            raise ValueError("dependency tree hash does not match the runtime file index")
        return self


class DependencyClosureRefV1(ContractModel):
    """Small Builder-to-Prover root for a canonical dependency closure manifest."""

    schema_version: Literal["1.0"] = "1.0"
    closure_id: StableIdentifierV1
    closure_manifest_ref: DependencyClosureArtifactRefV1
    closure_manifest_hash: DigestV1
    environment_hash: DigestV1
    tree_hash: DigestV1
    entry_modules: tuple[str, ...] = ()
    formal_body_dependency_ids: tuple[StableIdentifierV1, ...] = ()

    @model_validator(mode="after")
    def validate_reference(self) -> DependencyClosureRefV1:
        if self.closure_id.namespace != "dependency-closure":
            raise ValueError("closure_id must use the dependency-closure namespace")
        require_digest_kind(
            self.closure_manifest_hash,
            HashKindV1.DEPENDENCY_CLOSURE,
            "closure_manifest_hash",
        )
        require_digest_kind(self.environment_hash, HashKindV1.ENVIRONMENT, "environment_hash")
        require_digest_kind(self.tree_hash, HashKindV1.DEPENDENCY_TREE, "tree_hash")
        if self.closure_manifest_ref.media_type != DEPENDENCY_CLOSURE_MANIFEST_MEDIA_TYPE:
            raise ValueError("closure manifest reference has an unsupported media type")
        if self.closure_manifest_ref.sha256 != self.closure_manifest_hash.value:
            raise ValueError("closure manifest artifact does not match closure_manifest_hash")
        _require_sorted_unique(self.entry_modules, label="dependency entry modules")
        for module_name in self.entry_modules:
            _validate_module_name(module_name)
        dependency_ids = tuple(item.value for item in self.formal_body_dependency_ids)
        _require_sorted_unique(
            dependency_ids,
            label="formal-body dependency identifiers",
        )
        return self


def dependency_tree_hash(files: tuple[DependencyClosureFileV1, ...]) -> DigestV1:
    payload = {
        "schema_version": "autolean.dependency-tree.v1",
        "files": [
            {
                "relative_path": item.relative_path,
                "sha256": item.artifact.sha256,
                "size": item.artifact.size,
                "role": item.role.value,
            }
            for item in files
        ],
    }
    return digest_model(HashKindV1.DEPENDENCY_TREE, payload)


def build_dependency_closure_ref(manifest: DependencyClosureManifestV1) -> DependencyClosureRefV1:
    raw = manifest.canonical_bytes()
    manifest_hash = digest_bytes(HashKindV1.DEPENDENCY_CLOSURE, raw)
    return DependencyClosureRefV1(
        closure_id=manifest.closure_id,
        closure_manifest_ref=DependencyClosureArtifactRefV1(
            sha256=manifest_hash.value,
            size=len(raw),
            media_type=DEPENDENCY_CLOSURE_MANIFEST_MEDIA_TYPE,
        ),
        closure_manifest_hash=manifest_hash,
        environment_hash=manifest.environment_hash,
        tree_hash=manifest.tree_hash,
        entry_modules=manifest.entry_modules,
        formal_body_dependency_ids=tuple(
            item.dependency_id for item in manifest.accepted_dependencies
        ),
    )


def parse_dependency_closure_manifest(raw: bytes) -> DependencyClosureManifestV1:
    """Parse exact canonical JSON while rejecting duplicate keys and non-standard constants."""

    try:
        decoded = raw.decode("utf-8")
        payload = json.loads(
            decoded,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("dependency closure manifest is not canonical UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("dependency closure manifest must be a JSON object")
    manifest = DependencyClosureManifestV1.model_validate(payload)
    if raw != manifest.canonical_bytes():
        raise ValueError("dependency closure manifest bytes are not canonical")
    return manifest


def validate_dependency_closure_ref(
    reference: DependencyClosureRefV1,
    raw_manifest: bytes,
) -> DependencyClosureManifestV1:
    if len(raw_manifest) != reference.closure_manifest_ref.size:
        raise ValueError("dependency closure manifest size differs from its reference")
    actual_hash = digest_bytes(HashKindV1.DEPENDENCY_CLOSURE, raw_manifest)
    if actual_hash != reference.closure_manifest_hash:
        raise ValueError("dependency closure manifest differs from closure_manifest_hash")
    manifest = parse_dependency_closure_manifest(raw_manifest)
    expected_dependency_ids = tuple(item.dependency_id for item in manifest.accepted_dependencies)
    if (
        manifest.closure_id != reference.closure_id
        or manifest.environment_hash != reference.environment_hash
        or manifest.tree_hash != reference.tree_hash
        or manifest.entry_modules != reference.entry_modules
        or expected_dependency_ids != reference.formal_body_dependency_ids
    ):
        raise ValueError("dependency closure reference differs from its canonical manifest")
    return manifest


def _validate_runtime_path(value: str) -> None:
    if "\\" in value or "\x00" in value or ":" in value:
        raise ValueError("dependency runtime path is not safe POSIX syntax")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or ".." in path.parts or "." in path.parts:
        raise ValueError("dependency runtime path must be canonical and relative")
    if path.suffix != ".olean" or len(path.parts) < 2:
        raise ValueError("dependency runtime path must identify a namespaced OLean file")
    for segment in path.parts[:-1]:
        if _SAFE_PATH_SEGMENT.fullmatch(segment) is None:
            raise ValueError("dependency runtime path contains an unsafe segment")
    stem = path.name.removesuffix(".olean")
    if _SAFE_PATH_SEGMENT.fullmatch(stem) is None:
        raise ValueError("dependency runtime OLean filename is unsafe")
    if not path.parts[0].startswith("AutoLean"):
        raise ValueError("dependency runtime files must use an AutoLean-owned root")


def _validate_module_name(value: str, *, require_autolean: bool = True) -> None:
    if _LEAN_MODULE.fullmatch(value) is None:
        raise ValueError("dependency module name is not canonical")
    if require_autolean and not value.partition(".")[0].startswith("AutoLean"):
        raise ValueError("dependency modules must use an AutoLean-owned namespace")


def _validate_declaration_name(value: str) -> None:
    if _LEAN_NAME.fullmatch(value) is None:
        raise ValueError("dependency declaration name is not canonical")


def _validate_owned_declaration_name(value: str) -> None:
    _validate_declaration_name(value)
    if not value.partition(".")[0].startswith("AutoLean"):
        raise ValueError("dependency declarations must use an AutoLean-owned namespace")


def _validate_module_closure(
    modules: tuple[DependencyClosureModuleV1, ...],
    entry_modules: tuple[str, ...],
) -> None:
    known_modules = {item.module_name for item in modules}
    internal_imports: dict[str, tuple[str, ...]] = {}
    for module in modules:
        selected_imports = tuple(
            imported
            for imported in module.direct_imports
            if imported.partition(".")[0].startswith("AutoLean")
        )
        missing = set(selected_imports) - known_modules
        if missing:
            raise ValueError("dependency module imports an absent AutoLean module")
        internal_imports[module.module_name] = selected_imports

    visiting: set[str] = set()
    visited: set[str] = set()
    for root in known_modules:
        if root in visited:
            continue
        stack = [(root, False)]
        while stack:
            module_name, exiting = stack.pop()
            if exiting:
                visiting.remove(module_name)
                visited.add(module_name)
                continue
            if module_name in visited:
                continue
            if module_name in visiting:
                raise ValueError("dependency module closure contains an import cycle")
            visiting.add(module_name)
            stack.append((module_name, True))
            for imported in reversed(internal_imports[module_name]):
                if imported in visiting:
                    raise ValueError("dependency module closure contains an import cycle")
                if imported not in visited:
                    stack.append((imported, False))

    reachable: set[str] = set()
    pending = list(entry_modules)
    while pending:
        module_name = pending.pop()
        if module_name in reachable:
            continue
        reachable.add(module_name)
        pending.extend(internal_imports[module_name])
    if reachable != known_modules:
        raise ValueError("dependency module closure contains an unreachable module")


def _validate_axioms(values: tuple[str, ...]) -> None:
    _require_sorted_unique(values, label="observed dependency axioms")
    if "sorryAx" in values:
        raise ValueError("dependency closure cannot contain sorryAx")
    for value in values:
        if _LEAN_NAME.fullmatch(value) is None:
            raise ValueError("observed dependency axiom name is not canonical")


def _require_sorted_unique(values: tuple[str, ...], *, label: str) -> None:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{label} must be sorted and unique")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("dependency closure manifest contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> NoReturn:
    raise ValueError(f"dependency closure manifest contains unsupported JSON constant: {value}")
