"""Safely decrypt and inspect the quarantined AutoArchon backup.

This script is deliberately a recovery boundary, not a migration tool.  It never
prints recovered contents, file names, passphrases, prompts, logs, or secrets.
Everything it creates remains below ``.quarantine``.  The large Codex session
archive is excluded by default because it is neither source material nor safe
to place in an engineering workspace.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_QUARANTINE_WARNING = (
    "Quarantine only. Recovered content must not be added to a repository, prompt, "
    "artifact store, or model context."
)
_GPG_CANDIDATES = (
    "gpg",
    r"C:\Program Files\Git\usr\bin\gpg.exe",
)
_WSL_GPG_DECRYPT = """
import os
import pathlib
import subprocess
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
partial = destination.with_name(destination.name + '.partial')
partial.unlink(missing_ok=True)
try:
    completed = subprocess.run(
        [
            'gpg', '--batch', '--yes', '--pinentry-mode', 'loopback',
            '--passphrase-fd', '0', '--output', str(partial), '--decrypt', str(source),
        ],
        input=sys.stdin.buffer.read(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode:
        raise SystemExit(completed.returncode)
    os.replace(partial, destination)
finally:
    partial.unlink(missing_ok=True)
"""
_SESSION_MARKERS = ("codex-session", "codex-sessions", "session-backup")
_PASSPHRASE_PATTERNS = (
    re.compile(
        r"^\s*(?:archive[ _-]?passphrase|restore[ _-]?passphrase|passphrase|password)"
        r"\s*:\s*\`([^\`\r\n]+)\`\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^\s*AUTOARCHON_ARCHIVE_PASSPHRASE\s*=\s*([^\r\n#]+?)\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"\b(?:archive[ _-]?passphrase|restore[ _-]?passphrase|passphrase|password)"
        r"\s*\`([^\`\r\n]+)\`\s*:?\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
)


@dataclass(frozen=True, slots=True)
class DecryptResult:
    archive_count: int
    skipped_session_archives: int
    checksum_entries: int
    checksum_matches: int


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(4 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_child(root: Path, relative: PurePosixPath) -> Path:
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise RuntimeError("unsafe archive path")
    candidate = (root / Path(*relative.parts)).resolve()
    if os.path.commonpath((str(root.resolve()), str(candidate))) != str(root.resolve()):
        raise RuntimeError("archive path escapes the quarantine directory")
    return candidate


def _find_gpg(explicit: str | None) -> str:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise RuntimeError("the requested GPG executable does not exist")
        return str(path)
    for candidate in _GPG_CANDIDATES:
        resolved = shutil.which(candidate) if candidate == "gpg" else candidate
        if resolved and Path(resolved).is_file():
            return str(resolved)
    raise RuntimeError("GPG is unavailable; install it or pass --gpg")


def _read_documented_passphrase(root: Path) -> str:
    instructions = root / "RESTORE_PRIVATE.md"
    if not instructions.is_file():
        raise RuntimeError("quarantine is missing its recovery instructions")
    text = instructions.read_text(encoding="utf-8")
    values = [
        match.group(1).strip()
        for pattern in _PASSPHRASE_PATTERNS
        for match in pattern.finditer(text)
    ]
    values = [value for value in values if value]
    if len(set(values)) != 1:
        raise RuntimeError(
            "recovery instructions do not contain exactly one supported passphrase directive"
        )
    return values[0]


def _parse_checksums(root: Path) -> dict[str, str]:
    checksum_file = root / "SHA256SUMS"
    if not checksum_file.is_file():
        raise RuntimeError("quarantine is missing SHA256SUMS")
    entries: dict[str, str] = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+[* ](.+)", line.strip())
        if match is None:
            raise RuntimeError("SHA256SUMS has an unsupported entry")
        name = match.group(2)
        _safe_child(root, PurePosixPath(name))
        if name in entries:
            raise RuntimeError("SHA256SUMS contains duplicate archive entries")
        entries[name] = match.group(1).lower()
    return entries


def _is_session_archive(path: Path) -> bool:
    lowered = path.name.lower()
    return any(marker in lowered for marker in _SESSION_MARKERS)


def _decrypted_name(encrypted: Path) -> str:
    if encrypted.suffix != ".gpg":
        raise RuntimeError("expected a .gpg archive")
    return encrypted.name.removesuffix(".gpg")


def _verify_encrypted_archives(archive_dir: Path, checksum_entries: dict[str, str]) -> int:
    encrypted_archives = tuple(sorted(archive_dir.glob("*.gpg")))
    if not encrypted_archives:
        raise RuntimeError("quarantine does not contain encrypted archives")
    if len(encrypted_archives) != len(checksum_entries):
        raise RuntimeError("archive inventory does not match SHA256SUMS")
    for encrypted in encrypted_archives:
        expected = checksum_entries.get(f"archives/{encrypted.name}")
        if expected is None:
            raise RuntimeError("encrypted archive is absent from SHA256SUMS")
        if _hash_file(encrypted) != expected:
            raise RuntimeError("encrypted archive failed the published SHA-256 check")
    return len(encrypted_archives)


def _run_gpg(*, executable: str, encrypted: Path, destination: Path, passphrase: str) -> None:
    partial = destination.with_name(destination.name + ".partial")
    partial.unlink(missing_ok=True)
    try:
        completed = subprocess.run(
            [
                executable,
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--output",
                str(partial),
                "--decrypt",
                str(encrypted),
            ],
            input=(passphrase + "\\n").encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").lower()
            if "bad session key" in message or "decryption failed" in message:
                category = "bad-passphrase-or-corrupted-ciphertext"
            elif "no secret key" in message:
                category = "missing-private-key"
            elif "invalid option" in message:
                category = "unsupported-gpg-option"
            elif "can\u0027t open" in message or "cannot open" in message:
                category = "archive-or-output-unavailable"
            else:
                category = "unclassified-gpg-failure"
            raise RuntimeError(
                f"GPG rejected an archive ({category}; exit code {completed.returncode})"
            )
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)


def _wsl_path(path: Path) -> str:
    completed = subprocess.run(
        ["wsl.exe", "-e", "wslpath", "-a", str(path.resolve())],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        raise RuntimeError("WSL could not resolve a quarantine path")
    return value


def _run_wsl_gpg(*, encrypted: Path, destination: Path, passphrase: str) -> None:
    """Use the Linux authority path without exposing the passphrase in process arguments."""

    completed = subprocess.run(
        [
            "wsl.exe",
            "-e",
            "python3",
            "-c",
            _WSL_GPG_DECRYPT,
            _wsl_path(encrypted),
            _wsl_path(destination),
        ],
        input=(passphrase + "\n").encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"WSL GPG rejected an archive (exit code {completed.returncode})")


def decrypt(
    root: Path,
    *,
    gpg: str | None,
    backend: str,
    include_sessions: bool,
) -> DecryptResult:
    root = root.resolve()
    archive_dir = root / "archives"
    if not archive_dir.is_dir():
        raise RuntimeError("quarantine is missing its archive directory")
    checksum_entries = _parse_checksums(root)
    verified_archives = _verify_encrypted_archives(archive_dir, checksum_entries)
    decrypted_root = root / "decrypted"
    decrypted_root.mkdir(parents=True, exist_ok=True)
    executable = _find_gpg(gpg) if backend == "native" else None
    passphrase = _read_documented_passphrase(root)
    decrypted_archives = 0
    skipped = 0
    try:
        for encrypted in sorted(archive_dir.glob("*.gpg")):
            if _is_session_archive(encrypted) and not include_sessions:
                skipped += 1
                continue
            output = decrypted_root / _decrypted_name(encrypted)
            if not output.is_file():
                if backend == "native":
                    if executable is None:
                        raise RuntimeError(
                            "native recovery backend did not resolve a GPG executable"
                        )
                    _run_gpg(
                        executable=executable,
                        encrypted=encrypted,
                        destination=output,
                        passphrase=passphrase,
                    )
                else:
                    _run_wsl_gpg(
                        encrypted=encrypted,
                        destination=output,
                        passphrase=passphrase,
                    )
            decrypted_archives += 1
    finally:
        # Do not retain secret-bearing data in a module-level object after recovery work.
        passphrase = ""
    return DecryptResult(decrypted_archives, skipped, len(checksum_entries), verified_archives)


def _write_report(root: Path, name: str, payload: dict[str, object]) -> None:
    report_dir = root / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    target = report_dir / name
    temporary = target.with_name(target.name + ".partial")
    report = {
        "schema_version": "autolean.quarantine-unpack.v1",
        "warning": _QUARANTINE_WARNING,
        **payload,
    }
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def _archive_class(path: Path) -> str:
    name = path.name.lower()
    if "workspace" in name:
        return "workspace"
    if "metadata" in name or "campaign" in name:
        return "campaign_metadata"
    if "config" in name:
        return "configuration"
    return "other"


def _member_class(path: PurePosixPath) -> str:
    lowered = "/".join(path.parts).lower()
    suffix = path.suffix.lower()
    if any(token in lowered for token in ("session", "prompt", "transcript", "conversation")):
        return "session_or_prompt"
    if any(token in lowered for token in (".env", "credential", "secret", "token", "config")):
        return "sensitive_configuration"
    if any(token in lowered for token in ("log", "trace", "journal")):
        return "log_or_trace"
    if suffix in {".py", ".lean", ".ts", ".tsx", ".js", ".sh", ".toml", ".yaml", ".yml"}:
        return "source_or_build"
    if suffix in {".md", ".rst", ".txt"}:
        return "documentation"
    if suffix in {".json", ".jsonl", ".csv"}:
        return "structured_data"
    return "other"


def _safe_tar_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts:
        raise RuntimeError("decrypted archive contains an unsafe member path")
    return path


def inspect_decrypted_archives(root: Path) -> dict[str, object]:
    """Read compressed tar headers only and return a redacted inventory summary."""

    try:
        import zstandard
    except ModuleNotFoundError as exc:
        raise RuntimeError("zstandard is required for no-extract archive inspection") from exc

    decrypted = root / "decrypted"
    archives = tuple(sorted(decrypted.glob("*.tar.zst")))
    if not archives:
        raise RuntimeError("no decrypted .tar.zst archives are available for inspection")
    members = Counter[str]()
    archive_classes = Counter[str]()
    unsafe_members = Counter[str]()
    total_members = 0
    total_regular_bytes = 0
    for archive in archives:
        classification = _archive_class(archive)
        archive_classes[classification] += 1
        with (
            archive.open("rb") as compressed,
            zstandard.ZstdDecompressor().stream_reader(compressed) as stream,
            tarfile.open(fileobj=stream, mode="r|") as tar,
        ):
            for member in tar:
                safe_path = _safe_tar_path(member.name)
                if member.issym():
                    unsafe_members[f"{classification}:symbolic_link"] += 1
                    continue
                if member.islnk():
                    unsafe_members[f"{classification}:hard_link"] += 1
                    continue
                if member.isdev():
                    unsafe_members[f"{classification}:device"] += 1
                    continue
                if member.isfile():
                    members[_member_class(safe_path)] += 1
                    total_members += 1
                    total_regular_bytes += member.size
    return {
        "status": "complete",
        "archive_count": len(archives),
        "archive_classes": dict(sorted(archive_classes.items())),
        "regular_member_count": total_members,
        "regular_member_bytes": total_regular_bytes,
        "member_classes": dict(sorted(members.items())),
        "unsafe_member_types": dict(sorted(unsafe_members.items())),
        "safe_for_automatic_extraction": not unsafe_members,
        "archive_content_was_not_extracted": True,
        "session_archive_was_not_decrypted": True,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quarantine",
        type=Path,
        default=Path(".quarantine") / "hf-autoarchon-private",
    )
    parser.add_argument("--gpg", default=None, help="absolute GPG executable path")
    parser.add_argument(
        "--backend",
        choices=("wsl", "native"),
        default="wsl",
        help="decryption engine; WSL is the authoritative AutoLean execution boundary",
    )
    parser.add_argument(
        "--include-sessions",
        action="store_true",
        help="decrypt the Codex session archive too (disabled by default)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help=(
            "verify encrypted archive inventory and checksums without reading recovery instructions"
        ),
    )
    parser.add_argument(
        "--inspect-decrypted",
        action="store_true",
        help="inspect non-session archive headers without extracting any recovered content",
    )
    args = parser.parse_args(tuple(argv) if argv is not None else None)
    if args.verify_only:
        root = args.quarantine.resolve()
        checksums = _parse_checksums(root)
        verified = _verify_encrypted_archives(root / "archives", checksums)
        _write_report(
            root,
            "integrity-report.json",
            {
                "status": "complete",
                "published_checksum_entry_count": len(checksums),
                "verified_encrypted_archive_count": verified,
                "session_archive_was_not_decrypted": True,
            },
        )
        print(json.dumps({"status": "complete", "verified_encrypted_archives": verified}))
        return 0
    if args.inspect_decrypted:
        root = args.quarantine.resolve()
        report = inspect_decrypted_archives(root)
        _write_report(root, "decrypted-inventory.json", report)
        print(json.dumps(report, sort_keys=True))
        return 0
    result = decrypt(
        args.quarantine,
        gpg=args.gpg,
        backend=args.backend,
        include_sessions=args.include_sessions,
    )
    _write_report(
        args.quarantine.resolve(),
        "decrypt-report.json",
        {
            "status": "complete",
            "decrypted_archive_count": result.archive_count,
            "skipped_session_archive_count": result.skipped_session_archives,
            "published_checksum_entry_count": result.checksum_entries,
            "verified_encrypted_archive_count": result.checksum_matches,
        },
    )
    print(
        json.dumps(
            {
                "status": "complete",
                "decrypted_archives": result.archive_count,
                "skipped_session_archives": result.skipped_session_archives,
                "checksum_matches": result.checksum_matches,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
