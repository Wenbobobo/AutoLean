"""Strict, source-authoritative adapter for the pinned FATE v4.28.0 fixture.

The adapter deliberately does *not* know how to download FATE, invoke Lean, or load
solutions.  An operator supplies a clean, pinned checkout; this module validates that
checkout and makes an immutable manifest with one byte-level proof slot per task.  A
submission is a tactic fragment for that slot, never a replacement Lean file.

FATE-Eval is intentionally not imported or reused here.  Its mutable statement boundary is
incompatible with AutoLean's contract model; see ``docs/audits/fate-audit.md``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import unicodedata
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Final, Literal, cast

from .fate import TIER_COUNTS, FateProblemId, Tier


class FateAdapterError(ValueError):
    """Base error for a malformed FATE fixture or an invalid adapter request."""


class FateFixtureIntegrityError(FateAdapterError):
    """The operator-provided checkout or manifest differs from the pinned fixture."""


class FatePatchRejected(FateAdapterError):
    """A proposed proof is outside the one-slot proof boundary."""


FATE_FIXTURE_SCHEMA_V1: Final = "FateFixtureManifestV1"
FATE_RELEASE_V428: Final = "v4.28.0"
FATE_TIERS: Final[tuple[Tier, ...]] = ("M", "H", "X")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SOURCE_PATH = re.compile(r"^FATE-[MHX]/FATE[MHX]/[1-9][0-9]*\.lean$")
_SORRY_TOKEN = re.compile(rb"(?<![A-Za-z0-9_'])sorry(?![A-Za-z0-9_'])")
_DECLARATION = re.compile(
    rb"(?m)^[ \t]*(?:protected[ \t]+)?(?:theorem|lemma)[ \t]+"
    rb"([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)\b"
)
_NAMESPACE = re.compile(rb"^[ \t]*namespace[ \t]+([A-Za-z_][A-Za-z0-9_'.]*)\b")
_SECTION = re.compile(rb"^[ \t]*section(?:[ \t]+[A-Za-z_][A-Za-z0-9_'.]*)?\b")
_END = re.compile(rb"^[ \t]*end(?:[ \t]+[A-Za-z_][A-Za-z0-9_'.]*)?\b")
_FORBIDDEN_COMMAND = re.compile(
    rb"(?m)^[ \t]*(?:"
    rb"import|open|namespace|section|end|theorem|lemma|example|def|abbrev|opaque|"
    rb"axiom|class|instance|inductive|structure|macro|syntax|elab|scoped|"
    rb"private|protected|noncomputable|attribute|set_option|variable|universe|include|omit|"
    rb"export|mutual|run_elab|run_tac|local|unsafe|partial|initialize|"
    rb"builtin_initialize|builtin_simproc|command|elab_rules|macro_rules|syntax_cat|"
    rb"declare_syntax_cat|term_elab|tactic|notation|infix|prefix|postfix|#"
    rb")\b"
)
_TRUE_DECLARATION = re.compile(rb"(?m)^[ \t]*(?:theorem|lemma|example)[^\n]*:[ \t]*True[ \t]*:=")
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_GIT_TREE_RECORD = re.compile(
    rb"^(100644|100755|120000|160000) (blob|commit) ([0-9a-f]{40})\t(.+)$"
)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_lf_bytes(payload: bytes, artifact: str) -> bytes:
    """Normalize portable text artifacts to the LF bytes committed by Git.

    FATE task files and metadata are read from Git objects.  ``lake-manifest.json`` is
    an ignored Lake-generated input, so it must have the same explicit line-ending
    contract instead of inheriting the host checkout's CRLF conversion.
    """

    canonical = payload.replace(b"\r\n", b"\n")
    if b"\r" in canonical:
        raise FateFixtureIntegrityError(f"{artifact} contains a bare carriage return")
    return canonical


def _require_sha256(value: str, field_name: str) -> None:
    if not _HEX_SHA256.fullmatch(value):
        raise FateFixtureIntegrityError(f"{field_name} must be a lowercase SHA-256 digest")


def _freeze_tier_mapping(mapping: Mapping[Tier, str]) -> Mapping[Tier, str]:
    """Defend manifest and lock hashes from shallow mutation through a frozen dataclass."""

    return MappingProxyType(dict(mapping))


def _safe_source_path(value: str) -> PurePosixPath:
    if not _SAFE_SOURCE_PATH.fullmatch(value):
        raise FateFixtureIntegrityError(f"unsafe or unsupported FATE source path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or "." in path.parts or ".." in path.parts:
        raise FateFixtureIntegrityError(f"FATE source path escapes its checkout: {value!r}")
    return path


def _safe_git_tree_path(value: str) -> PurePosixPath:
    """Validate a Git tree path before mapping it onto the local checkout."""

    if not value or "\\" in value or "\x00" in value:
        raise FateFixtureIntegrityError("Git tree contains an unsafe path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise FateFixtureIntegrityError("Git tree contains a traversal path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise FateFixtureIntegrityError("Git tree contains an absolute path")
    return path


def _is_link_or_junction(path: Path) -> bool:
    """Treat Windows junctions like symlinks at checkout trust boundaries."""

    is_junction = getattr(os.path, "isjunction", None)
    return path.is_symlink() or bool(is_junction is not None and is_junction(path))


def _has_linked_ancestor(path: Path) -> bool:
    """Reject a write target whose existing path chain crosses a link or junction."""

    candidate = path.absolute()
    while True:
        if _is_link_or_junction(candidate):
            return True
        parent = candidate.parent
        if parent == candidate:
            return False
        candidate = parent


def _read_tracked_blob(root: Path, relative: PurePosixPath, expected_oid: str) -> bytes:
    """Read one regular checkout file only after every path component is checked."""

    payload = _read_regular_checkout_file(root, relative)
    blob_header = f"blob {len(payload)}\0".encode("ascii")
    if hashlib.sha1(blob_header + payload).hexdigest() != expected_oid:
        raise FateFixtureIntegrityError("FATE checkout bytes differ from their locked Git blob")
    return payload


def _read_regular_checkout_file(root: Path, relative: PurePosixPath) -> bytes:
    """Read a regular path below a checkout without following links or junctions."""

    candidate = root
    for component in relative.parts:
        candidate = candidate / component
        if _is_link_or_junction(candidate):
            raise FateFixtureIntegrityError("FATE checkout contains a link in its tracked tree")
    try:
        metadata = candidate.stat()
    except OSError as error:
        raise FateFixtureIntegrityError("FATE checkout is missing a tracked file") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise FateFixtureIntegrityError("FATE checkout tracked path is not a regular file")
    try:
        payload = candidate.read_bytes()
    except OSError as error:
        raise FateFixtureIntegrityError("cannot read a tracked FATE checkout file") from error
    return payload


def _task_id(value: str) -> FateProblemId:
    matched = re.fullmatch(r"FATE-([MHX])-([1-9][0-9]*)", value)
    if matched is None:
        raise FateFixtureIntegrityError(f"invalid FATE task id: {value!r}")
    tier = cast(Tier, matched.group(1))
    return FateProblemId(tier, int(matched.group(2)))


def _mask_non_code(source: bytes) -> bytes:
    """Replace comments and quoted strings with spaces while retaining every byte offset.

    This is deliberately a small lexical guard, not a Lean parser.  It is only used to locate
    the one existing ``sorry`` token and target declaration in already-pinned FATE source.
    The immutable whole-source and prefix/suffix hashes remain the real security boundary.
    """

    masked = bytearray(source)
    index = 0
    block_depth = 0
    line_comment = False
    in_string = False
    escaped = False
    length = len(source)

    while index < length:
        current = source[index]
        next_byte = source[index + 1] if index + 1 < length else None

        if line_comment:
            if current == 0x0A:
                line_comment = False
            else:
                masked[index] = 0x20
            index += 1
            continue

        if block_depth:
            if current == ord("/") and next_byte == ord("-"):
                masked[index] = masked[index + 1] = 0x20
                block_depth += 1
                index += 2
                continue
            if current == ord("-") and next_byte == ord("/"):
                masked[index] = masked[index + 1] = 0x20
                block_depth -= 1
                index += 2
                continue
            if current != 0x0A:
                masked[index] = 0x20
            index += 1
            continue

        if in_string:
            if current != 0x0A:
                masked[index] = 0x20
            if escaped:
                escaped = False
            elif current == ord("\\"):
                escaped = True
            elif current == ord('"'):
                in_string = False
            index += 1
            continue

        if current == ord("-") and next_byte == ord("-"):
            masked[index] = masked[index + 1] = 0x20
            line_comment = True
            index += 2
            continue
        if current == ord("/") and next_byte == ord("-"):
            masked[index] = masked[index + 1] = 0x20
            block_depth = 1
            index += 2
            continue
        if current == ord('"'):
            masked[index] = 0x20
            in_string = True
        index += 1

    if block_depth or in_string:
        raise FateFixtureIntegrityError("FATE source has an unterminated comment or string")
    return bytes(masked)


def _find_sorry_slots(masked_source: bytes) -> tuple[int, ...]:
    return tuple(match.start() for match in _SORRY_TOKEN.finditer(masked_source))


def _proof_slot_layout(source: bytes, offset: int) -> tuple[Literal["tactic", "term"], bytes]:
    """Determine whether ``sorry`` is an existing tactic or an existing term proof hole."""

    before_slot = source[:offset]
    if re.search(rb":=\s*by\s*$", before_slot) is not None:
        return "tactic", _line_indentation(source, offset)
    if re.search(rb":=\s*$", before_slot) is not None:
        return "term", b""
    raise FateFixtureIntegrityError("FATE sorry must be inside an existing proof assignment")


def _line_indentation(source: bytes, offset: int) -> bytes:
    line_start = source.rfind(b"\n", 0, offset) + 1
    prefix = source[line_start:offset]
    if prefix.strip(b" \t"):
        raise FateFixtureIntegrityError("tactic proof slot must be first on its source line")
    return prefix


def _declaration_indentation(source: bytes, declaration_start: int) -> bytes:
    """Return the physical indentation of the target declaration's source line."""

    line_start = source.rfind(b"\n", 0, declaration_start) + 1
    line_end = source.find(b"\n", declaration_start)
    if line_end == -1:
        line_end = len(source)
    line = source[line_start:line_end]
    if _DECLARATION.match(line) is None:
        raise FateFixtureIntegrityError("FATE target declaration is not at a source-line boundary")
    return line[: len(line) - len(line.lstrip(b" \t"))]


def _namespace_at(masked_source: bytes, offset: int) -> str:
    """Return the enclosing namespace at a declaration offset in pinned source."""

    scopes: list[tuple[Literal["namespace", "section"], str | None]] = []
    position = 0
    for line in masked_source.splitlines(keepends=True):
        if position >= offset:
            break
        namespace = _NAMESPACE.match(line)
        if namespace is not None:
            scopes.append(("namespace", namespace.group(1).decode("ascii")))
        elif _SECTION.match(line) is not None:
            scopes.append(("section", None))
        elif _END.match(line) is not None:
            if not scopes:
                raise FateFixtureIntegrityError("unmatched end before target declaration")
            scopes.pop()
        position += len(line)
    names: list[str] = []
    for kind, name in scopes:
        if kind == "namespace" and name is not None:
            names.extend(name.split("."))
    return ".".join(names)


@dataclass(frozen=True, slots=True)
class FateProofSlotV1:
    """The exact byte span that an agent may replace in a FATE source file."""

    original_token: Literal["sorry"]
    byte_start: int
    byte_end: int
    token_sha256: str
    prefix_sha256: str
    suffix_sha256: str
    mode: Literal["tactic", "term"]
    indentation: str

    def __post_init__(self) -> None:
        if self.original_token != "sorry":
            raise FateFixtureIntegrityError("FATE proof slots must originate from exactly 'sorry'")
        if (
            not isinstance(self.byte_start, int)
            or isinstance(self.byte_start, bool)
            or not isinstance(self.byte_end, int)
            or isinstance(self.byte_end, bool)
        ):
            raise FateFixtureIntegrityError("FATE proof slot offsets must be integers")
        if self.byte_start < 0 or self.byte_end != self.byte_start + len(self.original_token):
            raise FateFixtureIntegrityError(
                "FATE proof slot offsets do not delimit the original token"
            )
        for name in ("token_sha256", "prefix_sha256", "suffix_sha256"):
            _require_sha256(getattr(self, name), name)
        if self.mode not in ("tactic", "term"):
            raise FateFixtureIntegrityError("FATE proof slot mode is unsupported")
        if self.indentation.strip(" \t"):
            raise FateFixtureIntegrityError(
                "FATE proof slot indentation must contain only spaces or tabs"
            )
        if self.mode == "term" and self.indentation:
            raise FateFixtureIntegrityError(
                "term FATE proof slots must not record tactic indentation"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "original_token": self.original_token,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "token_sha256": self.token_sha256,
            "prefix_sha256": self.prefix_sha256,
            "suffix_sha256": self.suffix_sha256,
            "mode": self.mode,
            "indentation": self.indentation,
        }

    @classmethod
    def from_dict(cls, raw: object) -> FateProofSlotV1:
        if not isinstance(raw, dict):
            raise FateFixtureIntegrityError("proof_slot must be an object")
        required = (
            "original_token",
            "byte_start",
            "byte_end",
            "token_sha256",
            "prefix_sha256",
            "suffix_sha256",
            "mode",
            "indentation",
        )
        if any(name not in raw for name in required):
            raise FateFixtureIntegrityError("proof_slot is missing required fields")
        token = raw["original_token"]
        start = raw["byte_start"]
        end = raw["byte_end"]
        hashes = (raw["token_sha256"], raw["prefix_sha256"], raw["suffix_sha256"])
        mode = raw["mode"]
        indentation = raw["indentation"]
        if (
            not isinstance(token, str)
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or not all(isinstance(value, str) for value in hashes)
            or mode not in ("tactic", "term")
            or not isinstance(indentation, str)
        ):
            raise FateFixtureIntegrityError("proof_slot fields have invalid types")
        return cls(
            original_token=cast(Literal["sorry"], token),
            byte_start=start,
            byte_end=end,
            token_sha256=cast(str, hashes[0]),
            prefix_sha256=cast(str, hashes[1]),
            suffix_sha256=cast(str, hashes[2]),
            mode=cast(Literal["tactic", "term"], mode),
            indentation=indentation,
        )

    def validate_source(self, source: bytes) -> None:
        if self.byte_end > len(source):
            raise FateFixtureIntegrityError("proof slot is outside its source file")
        token = source[self.byte_start : self.byte_end]
        if token != self.original_token.encode("ascii") or _sha256(token) != self.token_sha256:
            raise FateFixtureIntegrityError("proof slot no longer contains its pinned sorry token")
        if _sha256(source[: self.byte_start]) != self.prefix_sha256:
            raise FateFixtureIntegrityError("source bytes before FATE proof slot changed")
        if _sha256(source[self.byte_end :]) != self.suffix_sha256:
            raise FateFixtureIntegrityError("source bytes after FATE proof slot changed")
        mode, indentation = _proof_slot_layout(source, self.byte_start)
        try:
            indentation_text = indentation.decode("ascii")
        except UnicodeDecodeError as error:
            raise FateFixtureIntegrityError(
                "FATE tactic proof indentation must use ASCII spaces or tabs"
            ) from error
        if mode != self.mode or indentation_text != self.indentation:
            raise FateFixtureIntegrityError("FATE proof slot layout changed")
        slots = _find_sorry_slots(_mask_non_code(source))
        if slots != (self.byte_start,):
            raise FateFixtureIntegrityError("FATE source must contain exactly one code-level sorry")


@dataclass(frozen=True, slots=True)
class FateTargetV1:
    """Identity of the existing declaration, independent of a submitted proof."""

    qualified_name: str
    declaration_start: int
    signature_sha256: str

    def __post_init__(self) -> None:
        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*", self.qualified_name
        ):
            raise FateFixtureIntegrityError("FATE target has an unsafe Lean declaration name")
        if not isinstance(self.declaration_start, int) or isinstance(self.declaration_start, bool):
            raise FateFixtureIntegrityError("FATE target declaration offset must be an integer")
        if self.declaration_start < 0:
            raise FateFixtureIntegrityError("FATE target declaration offset is negative")
        _require_sha256(self.signature_sha256, "signature_sha256")

    def to_dict(self) -> dict[str, object]:
        return {
            "qualified_name": self.qualified_name,
            "declaration_start": self.declaration_start,
            "signature_sha256": self.signature_sha256,
        }

    @classmethod
    def from_dict(cls, raw: object) -> FateTargetV1:
        if not isinstance(raw, dict):
            raise FateFixtureIntegrityError("target must be an object")
        name = raw.get("qualified_name")
        start = raw.get("declaration_start")
        signature = raw.get("signature_sha256")
        if (
            not isinstance(name, str)
            or not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(signature, str)
        ):
            raise FateFixtureIntegrityError("target fields have invalid types")
        return cls(qualified_name=name, declaration_start=start, signature_sha256=signature)

    def validate_source(self, source: bytes, slot: FateProofSlotV1) -> None:
        if self.declaration_start >= slot.byte_start:
            raise FateFixtureIntegrityError("FATE target must precede its proof slot")
        if _sha256(source[self.declaration_start : slot.byte_start]) != self.signature_sha256:
            raise FateFixtureIntegrityError("FATE declaration signature changed")
        target = _extract_target(source, slot.byte_start)
        if target != self:
            raise FateFixtureIntegrityError("FATE target declaration identity changed")


def _extract_target(source: bytes, slot_start: int) -> FateTargetV1:
    masked = _mask_non_code(source)
    declarations = tuple(_DECLARATION.finditer(masked[:slot_start]))
    if len(declarations) != 1:
        raise FateFixtureIntegrityError(
            "FATE source must expose exactly one named theorem or lemma"
        )
    declaration = declarations[0]
    raw_name = declaration.group(1).decode("ascii")
    namespace = _namespace_at(masked, declaration.start())
    qualified_name = raw_name if "." in raw_name or not namespace else f"{namespace}.{raw_name}"
    return FateTargetV1(
        qualified_name=qualified_name,
        declaration_start=declaration.start(),
        signature_sha256=_sha256(source[declaration.start() : slot_start]),
    )


@dataclass(frozen=True, slots=True)
class FateFixtureTaskV1:
    """One immutable FATE source task, including its unique proof slot."""

    task_id: str
    split: Tier
    source_path: str
    source_sha256: str
    proof_slot: FateProofSlotV1
    target: FateTargetV1

    def __post_init__(self) -> None:
        problem = _task_id(self.task_id)
        if problem.tier != self.split:
            raise FateFixtureIntegrityError("FATE task ID and split disagree")
        expected_path = f"FATE-{self.split}/FATE{self.split}/{problem.number}.lean"
        if self.source_path != expected_path:
            raise FateFixtureIntegrityError(
                "FATE task source path does not match its stable task ID"
            )
        _safe_source_path(self.source_path)
        _require_sha256(self.source_sha256, "source_sha256")

    @classmethod
    def from_source(
        cls,
        problem_id: FateProblemId,
        source_path: str,
        source: bytes,
    ) -> FateFixtureTaskV1:
        _safe_source_path(source_path)
        expected_path = f"FATE-{problem_id.tier}/FATE{problem_id.tier}/{problem_id.number}.lean"
        if source_path != expected_path:
            raise FateFixtureIntegrityError("FATE source path does not match its stable task ID")
        try:
            source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise FateFixtureIntegrityError("FATE Lean source must be UTF-8") from error
        masked = _mask_non_code(source)
        slots = _find_sorry_slots(masked)
        if len(slots) != 1:
            raise FateFixtureIntegrityError("FATE source must contain exactly one code-level sorry")
        start = slots[0]
        end = start + len("sorry")
        mode, indentation = _proof_slot_layout(source, start)
        try:
            indentation_text = indentation.decode("ascii")
        except UnicodeDecodeError as error:
            raise FateFixtureIntegrityError(
                "FATE tactic proof indentation must use ASCII spaces or tabs"
            ) from error
        slot = FateProofSlotV1(
            original_token="sorry",
            byte_start=start,
            byte_end=end,
            token_sha256=_sha256(source[start:end]),
            prefix_sha256=_sha256(source[:start]),
            suffix_sha256=_sha256(source[end:]),
            mode=mode,
            indentation=indentation_text,
        )
        slot.validate_source(source)
        return cls(
            task_id=problem_id.canonical,
            split=problem_id.tier,
            source_path=source_path,
            source_sha256=_sha256(source),
            proof_slot=slot,
            target=_extract_target(source, start),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.task_id,
            "split": self.split,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
            "proof_slot": self.proof_slot.to_dict(),
            "target": self.target.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: object) -> FateFixtureTaskV1:
        if not isinstance(raw, dict):
            raise FateFixtureIntegrityError("FATE task must be an object")
        task_id = raw.get("id")
        split = raw.get("split")
        source_path = raw.get("source_path")
        source_hash = raw.get("source_sha256")
        if (
            not isinstance(task_id, str)
            or split not in ("M", "H", "X")
            or not isinstance(source_path, str)
            or not isinstance(source_hash, str)
        ):
            raise FateFixtureIntegrityError("FATE task fields have invalid types")
        return cls(
            task_id=task_id,
            split=cast(Tier, split),
            source_path=source_path,
            source_sha256=source_hash,
            proof_slot=FateProofSlotV1.from_dict(raw.get("proof_slot")),
            target=FateTargetV1.from_dict(raw.get("target")),
        )

    def validate_source(self, source: bytes) -> None:
        if _sha256(source) != self.source_sha256:
            raise FateFixtureIntegrityError(
                "FATE source hash does not match the immutable manifest"
            )
        self.proof_slot.validate_source(source)
        self.target.validate_source(source, self.proof_slot)


@dataclass(frozen=True, slots=True)
class FateFixtureLockV1:
    """Release-wide FATE lock loaded from the repository-owned answer-free JSON file."""

    root_commit: str
    lean_version: str
    mathlib_revision: str
    submodules: Mapping[Tier, str]
    metadata_json_sha256: Mapping[Tier, str]
    lake_manifest_sha256: Mapping[Tier, str]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.root_commit):
            raise FateFixtureIntegrityError("FATE root commit is not a full Git SHA")
        if self.lean_version not in ("v4.28.0", "leanprover/lean4:v4.28.0"):
            raise FateFixtureIntegrityError("AutoLean only supports the pinned FATE Lean v4.28.0")
        if not re.fullmatch(r"[0-9a-f]{40}", self.mathlib_revision):
            raise FateFixtureIntegrityError("FATE mathlib revision is not a full Git SHA")
        expected = {"M", "H", "X"}
        if set(self.submodules) != expected:
            raise FateFixtureIntegrityError("FATE lock must declare M, H, and X submodules")
        if set(self.metadata_json_sha256) != expected or set(self.lake_manifest_sha256) != expected:
            raise FateFixtureIntegrityError(
                "FATE lock must hash metadata and lake manifests for every split"
            )
        for name, mapping in (
            ("submodule", self.submodules),
            ("metadata JSON", self.metadata_json_sha256),
            ("lake manifest", self.lake_manifest_sha256),
        ):
            for tier, value in mapping.items():
                pattern = r"[0-9a-f]{40}" if name == "submodule" else r"[0-9a-f]{64}"
                if not re.fullmatch(pattern, value):
                    raise FateFixtureIntegrityError(f"FATE {tier} {name} has an invalid hash")
        object.__setattr__(self, "submodules", _freeze_tier_mapping(self.submodules))
        object.__setattr__(
            self,
            "metadata_json_sha256",
            _freeze_tier_mapping(self.metadata_json_sha256),
        )
        object.__setattr__(
            self,
            "lake_manifest_sha256",
            _freeze_tier_mapping(self.lake_manifest_sha256),
        )

    @property
    def toolchain(self) -> str:
        """Canonical full toolchain spelling, including the legacy compact lock spelling."""

        return "leanprover/lean4:v4.28.0"

    @classmethod
    def load(cls, path: str | Path | None = None) -> FateFixtureLockV1:
        lock_path = Path(path) if path is not None else Path(__file__).with_name("fate.lock.json")
        try:
            raw = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise FateFixtureIntegrityError(f"cannot read FATE lock: {lock_path}") from error
        if not isinstance(raw, dict):
            raise FateFixtureIntegrityError("FATE lock root must be an object")
        root_commit = raw.get("revision")
        lean_version = raw.get("lean_version")
        mathlib_revision = raw.get("mathlib_revision")
        tiers = raw.get("tiers")
        if (
            raw.get("schema_version") != "autolean.fate-lock.v1"
            or raw.get("suite") != "FATE"
            or not isinstance(root_commit, str)
            or not isinstance(lean_version, str)
            or not isinstance(mathlib_revision, str)
            or not isinstance(tiers, dict)
        ):
            raise FateFixtureIntegrityError("FATE lock has an unsupported schema")
        submodules: dict[Tier, str] = {}
        metadata_hashes: dict[Tier, str] = {}
        lake_hashes: dict[Tier, str] = {}
        for tier in FATE_TIERS:
            entry = tiers.get(tier)
            if not isinstance(entry, dict):
                raise FateFixtureIntegrityError(f"FATE lock is missing split {tier}")
            revision = entry.get("revision")
            metadata_hash = entry.get("metadata_json_sha256")
            lake_hash = entry.get("lake_manifest_sha256")
            if (
                not isinstance(revision, str)
                or not isinstance(metadata_hash, str)
                or not isinstance(lake_hash, str)
            ):
                raise FateFixtureIntegrityError(f"FATE lock split {tier} is incomplete")
            submodules[tier] = revision
            metadata_hashes[tier] = metadata_hash
            lake_hashes[tier] = lake_hash
        return cls(
            root_commit=root_commit,
            lean_version=lean_version,
            mathlib_revision=mathlib_revision,
            submodules=submodules,
            metadata_json_sha256=metadata_hashes,
            lake_manifest_sha256=lake_hashes,
        )


@dataclass(frozen=True, slots=True)
class FateFixtureManifestV1:
    """Content-addressed, source-level task manifest generated from a verified checkout."""

    root_commit: str
    submodules: Mapping[Tier, str]
    toolchain: str
    mathlib_commit: str
    lake_manifest_sha256: Mapping[Tier, str]
    metadata_json_sha256: Mapping[Tier, str]
    tasks: tuple[FateFixtureTaskV1, ...]
    schema_version: Literal["FateFixtureManifestV1"] = FATE_FIXTURE_SCHEMA_V1
    benchmark: Literal["FATE"] = "FATE"
    release: Literal["v4.28.0"] = FATE_RELEASE_V428

    def __post_init__(self) -> None:
        lock = FateFixtureLockV1(
            root_commit=self.root_commit,
            lean_version=self.toolchain,
            mathlib_revision=self.mathlib_commit,
            submodules=self.submodules,
            metadata_json_sha256=self.metadata_json_sha256,
            lake_manifest_sha256=self.lake_manifest_sha256,
        )
        del lock
        if self.schema_version != FATE_FIXTURE_SCHEMA_V1 or self.benchmark != "FATE":
            raise FateFixtureIntegrityError("unsupported FATE fixture manifest schema")
        if self.release != FATE_RELEASE_V428:
            raise FateFixtureIntegrityError("FATE fixture manifest release must be v4.28.0")
        expected_ids = {
            FateProblemId(tier, number).canonical
            for tier in FATE_TIERS
            for number in range(1, TIER_COUNTS[tier] + 1)
        }
        task_ids = {task.task_id for task in self.tasks}
        if task_ids != expected_ids or len(self.tasks) != len(expected_ids):
            raise FateFixtureIntegrityError(
                "FATE fixture manifest must contain all 350 unique tasks"
            )
        object.__setattr__(self, "submodules", _freeze_tier_mapping(self.submodules))
        object.__setattr__(
            self,
            "lake_manifest_sha256",
            _freeze_tier_mapping(self.lake_manifest_sha256),
        )
        object.__setattr__(
            self,
            "metadata_json_sha256",
            _freeze_tier_mapping(self.metadata_json_sha256),
        )

    @property
    def content_hash(self) -> str:
        return _sha256(self.to_json().encode("utf-8"))

    def task(self, task_id: str | FateProblemId) -> FateFixtureTaskV1:
        canonical = (
            task_id.canonical if isinstance(task_id, FateProblemId) else _task_id(task_id).canonical
        )
        for task in self.tasks:
            if task.task_id == canonical:
                return task
        raise FateFixtureIntegrityError(
            f"FATE task is absent from the immutable manifest: {canonical}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "benchmark": self.benchmark,
            "release": self.release,
            "root_commit": self.root_commit,
            "submodules": dict(sorted(self.submodules.items())),
            "toolchain": self.toolchain,
            "mathlib_commit": self.mathlib_commit,
            "lake_manifest_sha256": dict(sorted(self.lake_manifest_sha256.items())),
            "metadata_json_sha256": dict(sorted(self.metadata_json_sha256.items())),
            "tasks": [task.to_dict() for task in sorted(self.tasks, key=lambda item: item.task_id)],
        }

    def to_json(self) -> str:
        return (
            json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n"
        )

    def write(self, path: str | Path) -> Path:
        requested = Path(path).absolute()
        if requested.exists() or _has_linked_ancestor(requested):
            raise FateFixtureIntegrityError(
                "FATE fixture manifests are immutable and may not overwrite"
            )
        destination = requested.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.parent.is_dir() or _is_link_or_junction(destination.parent):
            raise FateFixtureIntegrityError("FATE fixture manifest output parent is unsafe")
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        payload = self.to_json().encode("utf-8")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError as error:
                raise FateFixtureIntegrityError(
                    "FATE fixture manifest destination was created concurrently"
                ) from error
        finally:
            temporary.unlink(missing_ok=True)
        return destination

    @classmethod
    def from_dict(cls, raw: object) -> FateFixtureManifestV1:
        if not isinstance(raw, dict):
            raise FateFixtureIntegrityError("FATE fixture manifest root must be an object")
        expected_fields = {
            "schema_version",
            "benchmark",
            "release",
            "root_commit",
            "submodules",
            "toolchain",
            "mathlib_commit",
            "lake_manifest_sha256",
            "metadata_json_sha256",
            "tasks",
        }
        if set(raw) != expected_fields:
            raise FateFixtureIntegrityError("FATE fixture manifest has unexpected fields")
        required_strings = (
            "schema_version",
            "benchmark",
            "release",
            "root_commit",
            "toolchain",
            "mathlib_commit",
        )
        if any(not isinstance(raw.get(name), str) for name in required_strings):
            raise FateFixtureIntegrityError("FATE fixture manifest has missing scalar fields")
        mappings: dict[str, dict[Tier, str]] = {}
        for name in ("submodules", "lake_manifest_sha256", "metadata_json_sha256"):
            value = raw.get(name)
            if not isinstance(value, dict) or set(value) != {"M", "H", "X"}:
                raise FateFixtureIntegrityError(f"FATE fixture manifest has invalid {name}")
            typed: dict[Tier, str] = {}
            for tier in FATE_TIERS:
                item = value[tier]
                if not isinstance(item, str):
                    raise FateFixtureIntegrityError(
                        f"FATE fixture manifest {name}.{tier} must be text"
                    )
                typed[tier] = item
            mappings[name] = typed
        tasks_raw = raw.get("tasks")
        if not isinstance(tasks_raw, list):
            raise FateFixtureIntegrityError("FATE fixture manifest tasks must be a list")
        return cls(
            schema_version=cast(Literal["FateFixtureManifestV1"], raw["schema_version"]),
            benchmark=cast(Literal["FATE"], raw["benchmark"]),
            release=cast(Literal["v4.28.0"], raw["release"]),
            root_commit=cast(str, raw["root_commit"]),
            submodules=mappings["submodules"],
            toolchain=cast(str, raw["toolchain"]),
            mathlib_commit=cast(str, raw["mathlib_commit"]),
            lake_manifest_sha256=mappings["lake_manifest_sha256"],
            metadata_json_sha256=mappings["metadata_json_sha256"],
            tasks=tuple(FateFixtureTaskV1.from_dict(item) for item in tasks_raw),
        )

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        expected_content_hash: str | None = None,
    ) -> FateFixtureManifestV1:
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise FateFixtureIntegrityError(
                f"cannot read FATE fixture manifest: {source}"
            ) from error
        manifest = cls.from_dict(raw)
        if expected_content_hash is not None:
            _require_sha256(expected_content_hash, "expected FATE manifest content hash")
            if manifest.content_hash != expected_content_hash:
                raise FateFixtureIntegrityError("FATE fixture manifest content hash does not match")
        return manifest

    def validate_against_lock(self, lock: FateFixtureLockV1) -> None:
        if (
            self.root_commit != lock.root_commit
            or self.submodules != lock.submodules
            or self.toolchain != lock.toolchain
            or self.mathlib_commit != lock.mathlib_revision
            or self.lake_manifest_sha256 != lock.lake_manifest_sha256
            or self.metadata_json_sha256 != lock.metadata_json_sha256
        ):
            raise FateFixtureIntegrityError(
                "FATE fixture manifest does not match the repository lock"
            )


def _git_environment() -> dict[str, str]:
    """Remove ambient Git redirection before inspecting an operator checkout."""

    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_git(cwd: Path, *args: str) -> bytes:
    """Run only non-mutating Git plumbing with hostile output kept out of diagnostics."""

    try:
        completed = subprocess.run(
            (
                "git",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=",
                "-c",
                "core.autocrlf=false",
                "-C",
                str(cwd),
                *args,
            ),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise FateFixtureIntegrityError("cannot inspect the pinned FATE checkout") from error
    if completed.returncode:
        raise FateFixtureIntegrityError("cannot inspect the pinned FATE checkout")
    return completed.stdout


def _git_commit(cwd: Path) -> str:
    output = _run_git(cwd, "rev-parse", "--verify", "HEAD^{commit}")
    try:
        value = output.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise FateFixtureIntegrityError("Git returned a non-ASCII checkout revision") from error
    if not _GIT_SHA1.fullmatch(value):
        raise FateFixtureIntegrityError("Git returned an invalid checkout revision")
    return value


def _git_tree(cwd: Path, commit: str) -> dict[PurePosixPath, tuple[str, str, str]]:
    """Parse an exact recursive Git tree without treating its paths as shell input."""

    raw = _run_git(cwd, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries: dict[PurePosixPath, tuple[str, str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        matched = _GIT_TREE_RECORD.fullmatch(record)
        if matched is None:
            raise FateFixtureIntegrityError("Git returned an unsupported tree record")
        mode = matched.group(1).decode("ascii")
        object_type = matched.group(2).decode("ascii")
        object_id = matched.group(3).decode("ascii")
        try:
            path_text = matched.group(4).decode("utf-8")
        except UnicodeDecodeError as error:
            raise FateFixtureIntegrityError("Git tree path is not valid UTF-8") from error
        path = _safe_git_tree_path(path_text)
        if path in entries:
            raise FateFixtureIntegrityError("Git tree contains duplicate paths")
        entries[path] = (mode, object_type, object_id)
    if not entries:
        raise FateFixtureIntegrityError("Git returned an empty checkout tree")
    return entries


def _verify_tracked_tree(
    root: Path,
    commit: str,
    *,
    expected_gitlinks: Mapping[PurePosixPath, str],
) -> dict[PurePosixPath, bytes]:
    """Byte-compare every tracked regular file with the exact locked commit tree."""

    entries = _git_tree(root, commit)
    seen_gitlinks: dict[PurePosixPath, str] = {}
    files: dict[PurePosixPath, bytes] = {}
    for path, (mode, object_type, object_id) in entries.items():
        if object_type == "commit":
            if mode != "160000":
                raise FateFixtureIntegrityError("Git tree has an invalid submodule mode")
            seen_gitlinks[path] = object_id
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise FateFixtureIntegrityError("FATE tracked tree contains an unsupported file type")
        files[path] = _read_tracked_blob(root, path, object_id)
    if seen_gitlinks != dict(expected_gitlinks):
        raise FateFixtureIntegrityError("FATE checkout submodule graph does not match the lock")
    return files


def _read_git_blob(cwd: Path, expected_oid: str) -> bytes:
    """Read the canonical Git object, never a line-ending-transformed worktree file."""

    payload = _run_git(cwd, "cat-file", "blob", expected_oid)
    blob_header = f"blob {len(payload)}\0".encode("ascii")
    if hashlib.sha1(blob_header + payload).hexdigest() != expected_oid:
        raise FateFixtureIntegrityError("Git blob payload does not match its advertised object ID")
    return payload


def _read_verified_git_tree(
    root: Path,
    commit: str,
    *,
    expected_gitlinks: Mapping[PurePosixPath, str],
) -> dict[PurePosixPath, bytes]:
    """Read the immutable source snapshot from the verified commit's object database."""

    entries = _git_tree(root, commit)
    seen_gitlinks: dict[PurePosixPath, str] = {}
    files: dict[PurePosixPath, bytes] = {}
    for path, (mode, object_type, object_id) in entries.items():
        if object_type == "commit":
            if mode != "160000":
                raise FateFixtureIntegrityError("Git tree has an invalid submodule mode")
            seen_gitlinks[path] = object_id
            continue
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise FateFixtureIntegrityError("FATE tracked tree contains an unsupported file type")
        files[path] = _read_git_blob(root, object_id)
    if seen_gitlinks != dict(expected_gitlinks):
        raise FateFixtureIntegrityError("FATE checkout submodule graph does not match the lock")
    return files


def _required_tracked_file(
    files: Mapping[PurePosixPath, bytes],
    relative: str,
) -> bytes:
    try:
        return files[PurePosixPath(relative)]
    except KeyError as error:
        raise FateFixtureIntegrityError(
            "FATE checkout is missing a required tracked file"
        ) from error


def _verify_task_directory_entries(task_directory: Path, tier: Tier) -> None:
    if not task_directory.is_dir() or _is_link_or_junction(task_directory):
        raise FateFixtureIntegrityError("FATE task directory is missing or linked")
    expected = {f"{number}.lean" for number in range(1, TIER_COUNTS[tier] + 1)}
    try:
        entries = tuple(task_directory.iterdir())
    except OSError as error:
        raise FateFixtureIntegrityError("cannot inspect FATE task directory") from error
    if {entry.name for entry in entries} != expected:
        raise FateFixtureIntegrityError("FATE task directory has missing or extra entries")
    for entry in entries:
        if _is_link_or_junction(entry):
            raise FateFixtureIntegrityError("FATE task directory contains a link")
        try:
            metadata = entry.stat()
        except OSError as error:
            raise FateFixtureIntegrityError("cannot inspect a FATE task file") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise FateFixtureIntegrityError("FATE task directory contains a non-file entry")


@dataclass(frozen=True, slots=True)
class FateLockedCheckout:
    """Read-only validator and manifest builder for an operator-provided FATE checkout."""

    root: Path
    lock: FateFixtureLockV1

    @classmethod
    def from_lock_file(
        cls,
        root: str | Path,
        lock_path: str | Path | None = None,
    ) -> FateLockedCheckout:
        return cls(root=Path(root).resolve(), lock=FateFixtureLockV1.load(lock_path))

    def verify(self) -> None:
        self._verified_task_sources()

    def _verified_task_sources(self) -> dict[str, bytes]:
        if not self.root.is_dir():
            raise FateFixtureIntegrityError(f"FATE checkout root does not exist: {self.root}")
        if _git_commit(self.root) != self.lock.root_commit:
            raise FateFixtureIntegrityError("FATE root commit does not match fate.lock.json")
        expected_gitlinks = {
            PurePosixPath(f"FATE-{tier}"): self.lock.submodules[tier] for tier in FATE_TIERS
        }
        _read_verified_git_tree(
            self.root,
            self.lock.root_commit,
            expected_gitlinks=expected_gitlinks,
        )

        sources: dict[str, bytes] = {}
        for tier in FATE_TIERS:
            split_root = self.root / f"FATE-{tier}"
            if not split_root.is_dir() or _is_link_or_junction(split_root):
                raise FateFixtureIntegrityError(f"FATE checkout is missing FATE-{tier}")
            if _git_commit(split_root) != self.lock.submodules[tier]:
                raise FateFixtureIntegrityError(f"FATE-{tier} commit does not match fate.lock.json")
            files = _read_verified_git_tree(
                split_root,
                self.lock.submodules[tier],
                expected_gitlinks={},
            )
            try:
                toolchain = _required_tracked_file(files, "lean-toolchain").decode("utf-8").strip()
            except UnicodeDecodeError as error:
                raise FateFixtureIntegrityError(
                    f"FATE-{tier} Lean toolchain is not valid UTF-8"
                ) from error
            if toolchain != self.lock.toolchain:
                raise FateFixtureIntegrityError(
                    f"FATE-{tier} Lean toolchain does not match the lock"
                )
            # FATE intentionally ignores this generated resolution file.  Normalize only
            # CRLF-versus-LF presentation before applying its separately pinned hash.
            lake_manifest = _canonical_lf_bytes(
                _read_regular_checkout_file(
                    split_root,
                    PurePosixPath("lake-manifest.json"),
                ),
                f"FATE-{tier} lake manifest",
            )
            if _sha256(lake_manifest) != self.lock.lake_manifest_sha256[tier]:
                raise FateFixtureIntegrityError(
                    f"FATE-{tier} lake manifest does not match the lock"
                )
            metadata = _canonical_lf_bytes(
                _required_tracked_file(files, f"FATE-{tier}.json"),
                f"FATE-{tier} metadata JSON",
            )
            if _sha256(metadata) != self.lock.metadata_json_sha256[tier]:
                raise FateFixtureIntegrityError(
                    f"FATE-{tier} metadata JSON does not match the lock"
                )
            task_directory = split_root / f"FATE{tier}"
            _verify_task_directory_entries(task_directory, tier)
            for number in range(1, TIER_COUNTS[tier] + 1):
                source_path = f"FATE-{tier}/FATE{tier}/{number}.lean"
                sources[source_path] = _required_tracked_file(files, f"FATE{tier}/{number}.lean")
        return sources

    def build_manifest(self) -> FateFixtureManifestV1:
        sources = self._verified_task_sources()
        return self._manifest_from_sources(sources)

    def _manifest_from_sources(self, sources: Mapping[str, bytes]) -> FateFixtureManifestV1:
        tasks: list[FateFixtureTaskV1] = []
        for tier in FATE_TIERS:
            for number in range(1, TIER_COUNTS[tier] + 1):
                problem_id = FateProblemId(tier, number)
                source_path = f"FATE-{tier}/FATE{tier}/{number}.lean"
                source = sources[source_path]
                tasks.append(FateFixtureTaskV1.from_source(problem_id, source_path, source))
        return FateFixtureManifestV1(
            root_commit=self.lock.root_commit,
            submodules=dict(self.lock.submodules),
            toolchain=self.lock.toolchain,
            mathlib_commit=self.lock.mathlib_revision,
            lake_manifest_sha256=dict(self.lock.lake_manifest_sha256),
            metadata_json_sha256=dict(self.lock.metadata_json_sha256),
            tasks=tuple(tasks),
        )


@dataclass(frozen=True, slots=True)
class FatePatchedSourceV1:
    """A candidate made by replacing only one immutable FATE proof slot."""

    task: FateFixtureTaskV1
    proof_body_sha256: str
    candidate_sha256: str
    source: bytes


class FateAdapter:
    """Resolve tasks from a checked manifest and materialize proof-body-only candidates."""

    def __init__(
        self,
        checkout_root: str | Path,
        manifest: FateFixtureManifestV1,
        *,
        canonical_sources: Mapping[str, bytes],
    ) -> None:
        self._root = Path(checkout_root).resolve()
        manifest.validate_against_lock(FateFixtureLockV1.load())
        self._manifest = manifest
        expected_paths = {task.source_path for task in manifest.tasks}
        if set(canonical_sources) != expected_paths:
            raise FateFixtureIntegrityError(
                "canonical FATE source snapshot does not cover the manifest"
            )
        snapshot = dict(canonical_sources)
        for task in manifest.tasks:
            task.validate_source(snapshot[task.source_path])
        self._canonical_sources: Mapping[str, bytes] = MappingProxyType(snapshot)

    @property
    def manifest(self) -> FateFixtureManifestV1:
        return self._manifest

    @classmethod
    def from_manifest_file(
        cls,
        checkout_root: str | Path,
        manifest_path: str | Path,
        *,
        expected_manifest_content_hash: str,
    ) -> FateAdapter:
        checkout = FateLockedCheckout.from_lock_file(checkout_root)
        canonical_sources = checkout._verified_task_sources()
        manifest = FateFixtureManifestV1.load(
            manifest_path,
            expected_content_hash=expected_manifest_content_hash,
        )
        manifest.validate_against_lock(checkout.lock)
        adapter = cls(checkout.root, manifest, canonical_sources=canonical_sources)
        adapter.verify_all_sources()
        return adapter

    @classmethod
    def build_from_checkout(
        cls,
        checkout_root: str | Path,
    ) -> FateAdapter:
        checkout = FateLockedCheckout.from_lock_file(checkout_root)
        canonical_sources = checkout._verified_task_sources()
        manifest = checkout._manifest_from_sources(canonical_sources)
        return cls(checkout.root, manifest, canonical_sources=canonical_sources)

    def task(self, task_id: str | FateProblemId) -> FateFixtureTaskV1:
        return self._manifest.task(task_id)

    def verify_all_sources(self) -> None:
        for task in self._manifest.tasks:
            task.validate_source(self._read_source(task))

    def materialize_proof(
        self, task_id: str | FateProblemId, proof_body: str
    ) -> FatePatchedSourceV1:
        """Return source bytes with only the pinned ``sorry`` token replaced.

        ``proof_body`` is the tactic fragment after the existing ``:= by``.  It is not a Lean
        file and cannot carry imports, declarations, namespaces, or a new theorem type.
        """

        task = self.task(task_id)
        original = self._read_source(task)
        task.validate_source(original)
        proof = self._validate_proof_body(
            proof_body,
            task.proof_slot,
            task.target,
            original,
        )
        slot = task.proof_slot
        candidate = original[: slot.byte_start] + proof + original[slot.byte_end :]
        if (
            candidate[: slot.byte_start] != original[: slot.byte_start]
            or candidate[slot.byte_start + len(proof) :] != original[slot.byte_end :]
        ):
            raise FatePatchRejected("proof materialization modified protected FATE source bytes")
        if _find_sorry_slots(_mask_non_code(candidate)):
            raise FatePatchRejected("candidate still contains a sorry token")
        if task.target.signature_sha256 != _sha256(
            original[task.target.declaration_start : slot.byte_start]
        ):
            raise FateFixtureIntegrityError(
                "FATE target signature changed before proof materialization"
            )
        return FatePatchedSourceV1(
            task=task,
            proof_body_sha256=_sha256(proof),
            candidate_sha256=_sha256(candidate),
            source=candidate,
        )

    def write_candidate(
        self,
        task_id: str | FateProblemId,
        proof_body: str,
        attempt_root: str | Path,
    ) -> Path:
        """Write a generated candidate outside the immutable checkout, never in-place."""

        candidate = self.materialize_proof(task_id, proof_body)
        requested_root = Path(attempt_root).absolute()
        if _has_linked_ancestor(requested_root):
            raise FatePatchRejected("candidate workspace path crosses a link or junction")
        destination_root = requested_root.resolve()
        if destination_root.is_relative_to(self._root):
            raise FatePatchRejected(
                "candidate workspace must not be inside the pinned FATE checkout"
            )
        destination_root.mkdir(parents=True, exist_ok=True)
        if not destination_root.is_dir() or _is_link_or_junction(destination_root):
            raise FatePatchRejected("candidate workspace is not a safe directory")
        destination = destination_root / f"{candidate.task.task_id}.lean"
        if destination.exists() or _is_link_or_junction(destination):
            raise FatePatchRejected("candidate destination already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(destination, flags, 0o600)
        except FileExistsError as error:
            raise FatePatchRejected("candidate destination was created concurrently") from error
        except OSError as error:
            raise FatePatchRejected("cannot create candidate proof source") from error
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(candidate.source)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as error:
            destination.unlink(missing_ok=True)
            raise FatePatchRejected("cannot write candidate proof source") from error
        return destination

    def _read_source(self, task: FateFixtureTaskV1) -> bytes:
        try:
            return self._canonical_sources[task.source_path]
        except KeyError as error:
            raise FateFixtureIntegrityError(
                f"canonical source snapshot is missing {task.task_id}"
            ) from error

    @staticmethod
    def _validate_proof_body(
        proof_body: str,
        slot: FateProofSlotV1,
        target: FateTargetV1,
        source: bytes,
    ) -> bytes:
        if not isinstance(proof_body, str) or not proof_body.strip():
            raise FatePatchRejected("FATE proof body must be non-empty text")
        if "\x00" in proof_body or "\r" in proof_body:
            raise FatePatchRejected("FATE proof body must use non-NUL LF text")
        if any(
            (character.isspace() and character not in " \t\n")
            or (
                character not in "\t\n"
                and unicodedata.category(character) in {"Cc", "Cf", "Cs", "Co", "Cn"}
            )
            for character in proof_body
        ):
            raise FatePatchRejected("FATE proof body contains invisible or non-LF whitespace")
        if proof_body.startswith("\n") or proof_body.endswith("\n"):
            raise FatePatchRejected(
                "FATE proof body must replace only the token, not its line breaks"
            )
        try:
            encoded = proof_body.encode("utf-8")
        except UnicodeEncodeError as error:
            raise FatePatchRejected("FATE proof body is not valid UTF-8") from error
        if _SORRY_TOKEN.search(encoded) or re.search(
            rb"(?<![A-Za-z0-9_'])admit(?![A-Za-z0-9_'])", encoded
        ):
            raise FatePatchRejected("FATE proof body may not contain sorry or admit")
        masked = _mask_non_code(encoded)
        if _FORBIDDEN_COMMAND.search(masked) or _TRUE_DECLARATION.search(masked):
            raise FatePatchRejected(
                "FATE proof body may not contain a top-level declaration or command"
            )
        lines = encoded.split(b"\n")
        continuation_indentation = slot.indentation.encode("ascii")
        if slot.mode == "term":
            continuation_indentation = (
                _declaration_indentation(
                    source,
                    target.declaration_start,
                )
                + b"  "
            )
        if slot.mode == "tactic" and not continuation_indentation:
            if any(line and line[:1] not in (b" ", b"\t") for line in lines[1:]):
                raise FatePatchRejected(
                    "multiline column-zero FATE tactics must indent continuation lines"
                )
        elif any(line and not line.startswith(continuation_indentation) for line in lines[1:]):
            raise FatePatchRejected(
                "multiline FATE proof bodies must remain indented inside the proof"
            )
        return encoded


def build_fate_manifest(
    checkout_root: str | Path,
    output_path: str | Path,
) -> FateFixtureManifestV1:
    """Verify a clean pinned checkout and atomically write its immutable source manifest."""

    checkout = FateLockedCheckout.from_lock_file(checkout_root)
    output = Path(output_path).resolve()
    if output.is_relative_to(checkout.root):
        raise FateFixtureIntegrityError(
            "FATE fixture manifests must be written outside the pinned checkout"
        )
    manifest = checkout.build_manifest()
    manifest.write(output)
    return manifest
