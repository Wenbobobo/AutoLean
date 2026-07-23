"""Download a Hugging Face dataset snapshot into an ignored, integrity-checked quarantine.

This tool is intentionally archival, not an importer. It never extracts archives, interprets
sessions, executes recovered code, prints filenames, or reads credentials. Operators inspect and
promote a selected sanitized subset only after the recovery manifest is complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

_CHUNK_SIZE = 4 * 1024 * 1024
_USER_AGENT = "AutoLean-Quarantine-Recovery/1.0"


@dataclass(frozen=True, slots=True)
class RemoteFile:
    path: str
    expected_sha256: str | None
    expected_size: int | None


def fetch_json(url: str) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": _USER_AGENT})
    with urlopen(request, timeout=60) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError("Hugging Face API returned an unexpected JSON root")
    return parsed


def safe_relative_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise RuntimeError("dataset contains an unsafe file path")
    return path


def parse_files(metadata: dict[str, Any]) -> tuple[RemoteFile, ...]:
    siblings = metadata.get("siblings")
    if not isinstance(siblings, list):
        raise RuntimeError("dataset metadata is missing siblings")
    files: list[RemoteFile] = []
    for item in siblings:
        if not isinstance(item, dict) or not isinstance(item.get("rfilename"), str):
            raise RuntimeError("dataset metadata contains an invalid sibling record")
        path = str(item["rfilename"])
        safe_relative_path(path)
        lfs = item.get("lfs")
        expected_sha256: str | None = None
        expected_size: int | None = None
        if isinstance(lfs, dict):
            oid = lfs.get("oid")
            if (
                isinstance(oid, str)
                and len(oid) == 64
                and all(char in "0123456789abcdef" for char in oid)
            ):
                expected_sha256 = oid
            size = lfs.get("size")
            if isinstance(size, int) and size >= 0:
                expected_size = size
        files.append(RemoteFile(path, expected_sha256, expected_size))
    return tuple(files)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def valid_existing(path: Path, remote: RemoteFile) -> bool:
    if not path.is_file():
        return False
    digest, size = sha256_file(path)
    return (remote.expected_sha256 is None or digest == remote.expected_sha256) and (
        remote.expected_size is None or size == remote.expected_size
    )


def download_file(
    *,
    dataset: str,
    revision: str,
    remote: RemoteFile,
    destination: Path,
) -> tuple[str, int]:
    target = destination / Path(safe_relative_path(remote.path))
    target.parent.mkdir(parents=True, exist_ok=True)
    if valid_existing(target, remote):
        return sha256_file(target)
    temporary = target.with_name(target.name + ".partial")
    temporary.unlink(missing_ok=True)
    encoded_path = "/".join(quote(part, safe="") for part in safe_relative_path(remote.path).parts)
    url = (
        f"https://huggingface.co/datasets/{dataset}/resolve/{revision}/{encoded_path}?download=true"
    )
    request = Request(url, headers={"User-Agent": _USER_AGENT})
    digest = hashlib.sha256()
    size = 0
    try:
        with urlopen(request, timeout=120) as response, temporary.open("wb") as handle:
            while chunk := response.read(_CHUNK_SIZE):
                handle.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        actual = digest.hexdigest()
        if remote.expected_sha256 is not None and actual != remote.expected_sha256:
            raise RuntimeError("downloaded file failed its Hugging Face SHA-256 check")
        if remote.expected_size is not None and size != remote.expected_size:
            raise RuntimeError("downloaded file failed its Hugging Face size check")
        os.replace(temporary, target)
        return actual, size
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_manifest(
    destination: Path,
    *,
    dataset: str,
    revision: str,
    records: list[dict[str, object]],
) -> None:
    manifest = {
        "schema_version": "autolean.quarantine-recovery.v1",
        "dataset": dataset,
        "revision": revision,
        "retrieved_at_epoch": int(time.time()),
        "files": records,
        "warning": "Quarantine only. Do not add recovered files to a repository or model context.",
    }
    temporary = destination / ".recovery-manifest.partial"
    target = destination / "recovery-manifest.json"
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="Garydesu/AutoArchon_Private")
    parser.add_argument("--revision", default=None)
    parser.add_argument(
        "--destination",
        type=Path,
        default=Path(".quarantine") / "hf-autoarchon-private",
    )
    args = parser.parse_args()
    if "/" not in args.dataset or args.dataset.startswith("/"):
        raise SystemExit("dataset must have the owner/name form")
    metadata = fetch_json(f"https://huggingface.co/api/datasets/{args.dataset}")
    revision = args.revision or metadata.get("sha")
    if not isinstance(revision, str) or len(revision) < 7:
        raise SystemExit("dataset metadata did not provide a usable immutable revision")
    files = parse_files(metadata)
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    lock = destination / ".recovery.lock"
    try:
        lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise SystemExit("a recovery is already running for this destination") from exc
    try:
        os.write(lock_fd, str(os.getpid()).encode("ascii"))
        os.close(lock_fd)
        records: list[dict[str, object]] = []
        total = 0
        for remote in files:
            digest, size = download_file(
                dataset=args.dataset,
                revision=revision,
                remote=remote,
                destination=destination,
            )
            records.append(
                {
                    **asdict(remote),
                    "actual_sha256": digest,
                    "actual_size": size,
                }
            )
            total += size
        write_manifest(destination, dataset=args.dataset, revision=revision, records=records)
        print(json.dumps({"status": "complete", "file_count": len(records), "total_bytes": total}))
        return 0
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
