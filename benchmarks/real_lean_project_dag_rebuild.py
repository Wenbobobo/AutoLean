"""Create immutable changed-source rebuild bundles for the real Lean DAG fixture.

The bundle is deliberately a planning artifact, not an incremental Lean build engine.
It compares a complete source snapshot against a byte-bound baseline, binds explicit
changed declaration IDs, derives the two corresponding reverse closures in stable
topological order, and records exactly which modules and declaration nodes are rebuilt
or reused.  A control-plane lease and fencing token remain an external execution
precondition.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from benchmarks.real_lean_project_dag import RealLeanProjectDagV1

REBUILD_BUNDLE_SCHEMA: Final[str] = "autolean.real-lean-project-dag-rebuild-bundle.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REBUILD = "rebuild"
_REUSE = "reuse"
_LEASE_PRECONDITION = "control_plane_lease_and_fencing_token_required"


class RealLeanRebuildPlanError(ValueError):
    """A source snapshot cannot be converted into a safe rebuild bundle."""


@dataclass(frozen=True, slots=True)
class RebuildSourceBindingV1:
    """The baseline and candidate bytes for one fixture module source."""

    module: str
    file: str
    baseline_source_sha256: str
    snapshot_source_sha256: str

    def __post_init__(self) -> None:
        if (
            not self.module
            or not self.file.endswith(".lean")
            or _SHA256.fullmatch(self.baseline_source_sha256) is None
            or _SHA256.fullmatch(self.snapshot_source_sha256) is None
        ):
            raise RealLeanRebuildPlanError("rebuild source binding is invalid")

    @property
    def source_changed(self) -> bool:
        return self.snapshot_source_sha256 != self.baseline_source_sha256


@dataclass(frozen=True, slots=True)
class RebuildModuleActionV1:
    """One module-granularity action; Lean OLean artifacts are reused only by module."""

    module: str
    action: str
    reason: str

    def __post_init__(self) -> None:
        if self.action not in {_REBUILD, _REUSE}:
            raise RealLeanRebuildPlanError("rebuild module action is invalid")
        expected_reasons = {
            _REBUILD: {"changed_source", "reverse_import_closure"},
            _REUSE: {"unchanged_source_reuse"},
        }
        if not self.module or self.reason not in expected_reasons[self.action]:
            raise RealLeanRebuildPlanError("rebuild module action reason is invalid")


@dataclass(frozen=True, slots=True)
class RebuildDeclarationActionV1:
    """One declaration-level projection of the module-granularity rebuild decision."""

    node_id: str
    module: str
    action: str

    def __post_init__(self) -> None:
        if not self.node_id or not self.module or self.action not in {_REBUILD, _REUSE}:
            raise RealLeanRebuildPlanError("rebuild declaration action is invalid")


@dataclass(frozen=True, slots=True)
class RealLeanRebuildBundleV1:
    """A deterministic, content-addressed rebuild plan awaiting control-plane lease binding."""

    fixture_manifest_sha256: str
    source_bindings: tuple[RebuildSourceBindingV1, ...]
    changed_declaration_ids: tuple[str, ...]
    declaration_invalidation_plan: tuple[str, ...]
    module_actions: tuple[RebuildModuleActionV1, ...]
    declaration_actions: tuple[RebuildDeclarationActionV1, ...]
    execution_precondition: str = _LEASE_PRECONDITION

    def __post_init__(self) -> None:
        if _SHA256.fullmatch(self.fixture_manifest_sha256) is None:
            raise RealLeanRebuildPlanError("rebuild bundle fixture manifest hash is invalid")
        modules = tuple(binding.module for binding in self.source_bindings)
        if not modules or len(set(modules)) != len(modules):
            raise RealLeanRebuildPlanError("rebuild bundle source modules are invalid")
        if tuple(action.module for action in self.module_actions) != modules:
            raise RealLeanRebuildPlanError("rebuild bundle module action order is invalid")
        node_ids = tuple(action.node_id for action in self.declaration_actions)
        if len(set(node_ids)) != len(node_ids):
            raise RealLeanRebuildPlanError("rebuild bundle declaration actions are invalid")
        if len(set(self.changed_declaration_ids)) != len(self.changed_declaration_ids):
            raise RealLeanRebuildPlanError("rebuild bundle changed declarations are invalid")
        if set(self.changed_declaration_ids) - set(node_ids):
            raise RealLeanRebuildPlanError("rebuild bundle changed declaration is unknown")
        if len(set(self.declaration_invalidation_plan)) != len(self.declaration_invalidation_plan):
            raise RealLeanRebuildPlanError("rebuild bundle declaration invalidation is invalid")
        if set(self.declaration_invalidation_plan) - set(node_ids):
            raise RealLeanRebuildPlanError("rebuild bundle invalidation references an unknown node")
        if set(self.changed_declaration_ids) - set(self.declaration_invalidation_plan):
            raise RealLeanRebuildPlanError(
                "rebuild bundle invalidation omits a changed declaration"
            )
        if self.execution_precondition != _LEASE_PRECONDITION:
            raise RealLeanRebuildPlanError("rebuild bundle execution precondition is invalid")

    @property
    def changed_modules(self) -> tuple[str, ...]:
        return tuple(binding.module for binding in self.source_bindings if binding.source_changed)

    @property
    def module_rebuild_plan(self) -> tuple[str, ...]:
        return tuple(action.module for action in self.module_actions if action.action == _REBUILD)

    @property
    def module_reuse_plan(self) -> tuple[str, ...]:
        return tuple(action.module for action in self.module_actions if action.action == _REUSE)

    @property
    def execution_status(self) -> str:
        """Prevent callers from mistaking a plan for a leased execution authorization."""

        return "refused_pending_control_plane_lease"

    def _content_document(self) -> dict[str, object]:
        return {
            "schema_version": REBUILD_BUNDLE_SCHEMA,
            "fixture_manifest_sha256": self.fixture_manifest_sha256,
            "source_bindings": [
                {
                    "module": item.module,
                    "file": item.file,
                    "baseline_source_sha256": item.baseline_source_sha256,
                    "snapshot_source_sha256": item.snapshot_source_sha256,
                    "source_changed": item.source_changed,
                }
                for item in self.source_bindings
            ],
            "changed_modules": list(self.changed_modules),
            "changed_declaration_ids": list(self.changed_declaration_ids),
            "declaration_invalidation_plan": list(self.declaration_invalidation_plan),
            "module_actions": [
                {"module": item.module, "action": item.action, "reason": item.reason}
                for item in self.module_actions
            ],
            "declaration_actions": [
                {"node_id": item.node_id, "module": item.module, "action": item.action}
                for item in self.declaration_actions
            ],
            "module_rebuild_plan": list(self.module_rebuild_plan),
            "module_reuse_plan": list(self.module_reuse_plan),
            "execution_status": self.execution_status,
            "execution_precondition": self.execution_precondition,
        }

    def canonical_bytes(self) -> bytes:
        """Return stable content bytes for an immutable artifact store or manifest exchange."""

        rendered = json.dumps(
            self._content_document(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        return (rendered + "\n").encode("utf-8")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Render the exchange manifest with its content address appended, never self-hashed."""

        document = self._content_document()
        document["content_sha256"] = self.content_sha256
        return document


def _module_reverse_import_closure(
    fixture: RealLeanProjectDagV1, changed_modules: frozenset[str]
) -> tuple[str, ...]:
    modules = fixture.modules_by_name
    reverse: dict[str, set[str]] = {module: set() for module in modules}
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
        module.module for module in fixture.module_topological_order() if module.module in affected
    )


def plan_real_lean_rebuild(
    fixture: RealLeanProjectDagV1,
    source_snapshot_sha256: Mapping[str, str],
    *,
    changed_declaration_ids: tuple[str, ...],
) -> RealLeanRebuildBundleV1:
    """Derive a complete rebuild/reuse manifest from a full candidate source snapshot.

    Every fixture module must be present.  This avoids treating omitted observations as
    unchanged sources.  Any changed source invalidates its entire module at the Lean
    compilation boundary.  Only the separately supplied declaration IDs seed the
    formal/content-graph invalidation closure.
    """

    modules = fixture.modules_by_name
    if set(source_snapshot_sha256) != set(modules):
        raise RealLeanRebuildPlanError("source snapshot must bind exactly every fixture module")
    if any(
        not isinstance(value, str) or _SHA256.fullmatch(value) is None
        for value in source_snapshot_sha256.values()
    ):
        raise RealLeanRebuildPlanError("source snapshot hash is invalid")
    declarations = fixture.declarations_by_id
    if (
        not all(isinstance(node_id, str) for node_id in changed_declaration_ids)
        or len(set(changed_declaration_ids)) != len(changed_declaration_ids)
        or set(changed_declaration_ids) - set(declarations)
    ):
        raise RealLeanRebuildPlanError("changed declaration IDs are invalid")

    bindings = tuple(
        RebuildSourceBindingV1(
            module=module.module,
            file=module.file,
            baseline_source_sha256=module.source_sha256,
            snapshot_source_sha256=source_snapshot_sha256[module.module],
        )
        for module in fixture.module_topological_order()
    )
    changed_modules = frozenset(binding.module for binding in bindings if binding.source_changed)
    changed_declaration_modules = {
        declarations[node_id].module for node_id in changed_declaration_ids
    }
    if changed_declaration_modules - changed_modules:
        raise RealLeanRebuildPlanError("changed declaration must belong to a changed source module")
    rebuild_modules = frozenset(_module_reverse_import_closure(fixture, changed_modules))
    changed_declaration_set = frozenset(changed_declaration_ids)
    normalized_changed_declarations = tuple(
        declaration.node_id
        for declaration in fixture.declaration_topological_order()
        if declaration.node_id in changed_declaration_set
    )
    invalidated = tuple(
        declaration.node_id for declaration in fixture.affected_by(changed_declaration_set)
    )
    module_actions = tuple(
        RebuildModuleActionV1(
            module=module.module,
            action=_REBUILD if module.module in rebuild_modules else _REUSE,
            reason=(
                "changed_source"
                if module.module in changed_modules
                else "reverse_import_closure"
                if module.module in rebuild_modules
                else "unchanged_source_reuse"
            ),
        )
        for module in fixture.module_topological_order()
    )
    declaration_actions = tuple(
        RebuildDeclarationActionV1(
            node_id=declaration.node_id,
            module=declaration.module,
            action=_REBUILD if declaration.module in rebuild_modules else _REUSE,
        )
        for declaration in fixture.declaration_topological_order()
    )
    return RealLeanRebuildBundleV1(
        fixture_manifest_sha256=fixture.manifest_sha256(),
        source_bindings=bindings,
        changed_declaration_ids=normalized_changed_declarations,
        declaration_invalidation_plan=invalidated,
        module_actions=module_actions,
        declaration_actions=declaration_actions,
    )
