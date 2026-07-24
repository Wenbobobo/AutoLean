from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from subprocess import CompletedProcess
from types import ModuleType
from typing import Any, cast

import pytest


def _load_verify_module() -> ModuleType:
    script = Path(__file__).resolve().parents[2] / "Library" / "scripts" / "verify.py"
    specification = importlib.util.spec_from_file_location("library_verify_test", script)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    assert isinstance(module, ModuleType)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


VERIFY: Any = _load_verify_module()
LIBRARY_ROOT = Path(__file__).resolve().parents[2] / "Library"


def _make_minimal_build_tree(root: Path) -> None:
    (root / "AutoLeanLibrary" / "Nested").mkdir(parents=True)
    for relative, content in {
        "lean-toolchain": "leanprover/lean4:v4.28.0\n",
        "lakefile.lean": "lean_lib AutoLeanLibrary\n",
        "lake-manifest.json": "{}\n",
        "AutoLeanLibrary.lean": "theorem root : True := True.intro\n",
        "AutoLeanLibrary/Zeta.lean": "theorem zeta : True := True.intro\n",
        "AutoLeanLibrary/alpha.lean": "theorem alpha : True := True.intro\n",
        "AutoLeanLibrary/Nested/Beta.lean": "theorem beta : True := True.intro\n",
    }.items():
        path = root.joinpath(*Path(relative).parts)
        path.write_text(content, encoding="utf-8")


def _copy_receipt_fixture(tmp_path: Path) -> Path:
    destination = tmp_path / "Library"
    VERIFY._copy_input_tree(LIBRARY_ROOT, destination)
    for relative in (
        "scripts/verify.py",
        VERIFY.SPIKE_PACKET_RELATIVE,
        VERIFY.SPIKE_RECEIPT_RELATIVE,
    ):
        source = LIBRARY_ROOT.joinpath(*Path(relative).parts)
        target = destination.joinpath(*Path(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


def _make_dependency_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict[str, object]]:
    cache_entry = tmp_path / "cache-entry"
    packages = cache_entry / "packages"
    (packages / "mathlib" / ".lake" / "build" / "lib" / "lean").mkdir(parents=True)
    (packages / "mathlib" / "Mathlib.lean").write_text(
        "import Mathlib.Algebra\n",
        encoding="utf-8",
    )
    (packages / "mathlib" / ".lake" / "build" / "lib" / "lean" / "Mathlib.olean").write_bytes(
        b"olean-cache-v1"
    )
    monkeypatch.setattr(VERIFY, "_verify_package_directory", lambda _: None)
    binding = VERIFY._write_dependency_manifest(cache_entry, packages)
    identity = VERIFY._cache_identity(LIBRARY_ROOT, binding)
    (cache_entry / "identity.json").write_text(
        json.dumps(identity, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return cache_entry, packages, binding


def test_committed_library_lock_passes_review() -> None:
    VERIFY.check_lock()


def test_committed_compile_receipt_passes_review() -> None:
    VERIFY.verify_compile_receipt()


def test_build_targets_cover_only_public_root_and_nonpromotable_terminals() -> None:
    assert VERIFY.BUILD_TARGETS == (
        "AutoLeanLibrary",
        "AutoLeanLibrary.Fixtures.Dag.Certificate",
        "AutoLeanLibrary.Fixtures.ModelTheory.Packet",
    )


def test_input_hash_uses_posix_utf8_byte_order(tmp_path: Path) -> None:
    _make_minimal_build_tree(tmp_path)
    relative_paths = VERIFY._input_relative_paths(tmp_path)
    assert relative_paths == sorted(relative_paths, key=lambda value: value.encode("utf-8"))
    assert relative_paths == [
        "AutoLeanLibrary.lean",
        "AutoLeanLibrary/Nested/Beta.lean",
        "AutoLeanLibrary/Zeta.lean",
        "AutoLeanLibrary/alpha.lean",
        "lake-manifest.json",
        "lakefile.lean",
        "lean-toolchain",
    ]

    reference = hashlib.sha256()
    reference.update(VERIFY.BUILD_INPUT_SCHEMA.encode("ascii"))
    reference.update(b"\n")
    for relative in relative_paths:
        reference.update(relative.encode("utf-8"))
        reference.update(b"\0")
        reference.update(hashlib.sha256((tmp_path / Path(relative)).read_bytes()).digest())
        reference.update(b"\n")
    assert VERIFY.input_tree_sha256(tmp_path) == reference.hexdigest()


def test_input_hash_excludes_non_lake_state(tmp_path: Path) -> None:
    _make_minimal_build_tree(tmp_path)
    initial = VERIFY.input_tree_sha256(tmp_path)

    for relative in (
        "README.md",
        "docs/decision.md",
        "records/staging/receipt.json",
        "evidence/run.json",
        "scripts/verify.py",
        ".lake/generated",
    ):
        path = tmp_path / Path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not read by Lake\n", encoding="utf-8")
    assert VERIFY.input_tree_sha256(tmp_path) == initial

    (tmp_path / "AutoLeanLibrary" / "alpha.lean").write_text(
        "theorem alpha : True := by trivial\n",
        encoding="utf-8",
    )
    assert VERIFY.input_tree_sha256(tmp_path) != initial


def test_copy_input_tree_copies_only_authoritative_build_inputs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _make_minimal_build_tree(source)
    (source / "records").mkdir()
    (source / "records" / "receipt.json").write_text("{}\n", encoding="utf-8")
    destination = tmp_path / "destination"

    VERIFY._copy_input_tree(source, destination)

    copied = sorted(
        (
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_file()
        ),
        key=lambda value: value.encode("utf-8"),
    )
    assert copied == VERIFY._input_relative_paths(source)
    assert not (destination / "records").exists()


@pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("wsl.exe") is None,
    reason="requires a Windows host with WSL",
)
def test_committed_windows_and_wsl_input_hashes_match() -> None:
    def wsl_path(path: Path) -> str:
        completed = subprocess.run(
            (
                "wsl.exe",
                "--distribution",
                VERIFY.DEFAULT_WSL_DISTRIBUTION,
                "--exec",
                "/usr/bin/wslpath",
                "-a",
                "-u",
                str(path.resolve()),
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode:
            pytest.skip(f"configured WSL distribution unavailable: {completed.stderr.strip()}")
        return completed.stdout.strip()

    completed = subprocess.run(
        (
            "wsl.exe",
            "--distribution",
            VERIFY.DEFAULT_WSL_DISTRIBUTION,
            "--exec",
            "/usr/bin/python3",
            wsl_path(LIBRARY_ROOT / "scripts" / "verify.py"),
            "hash-input",
            "--source-root",
            wsl_path(LIBRARY_ROOT),
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode:
        pytest.skip(f"configured WSL Python unavailable: {completed.stderr.strip()}")
    wsl_payload = json.loads(completed.stdout)
    assert wsl_payload == {
        "schema_version": VERIFY.BUILD_INPUT_SCHEMA,
        "source_tree_sha256": VERIFY.input_tree_sha256(LIBRARY_ROOT),
        "input_paths": VERIFY._input_relative_paths(LIBRARY_ROOT),
    }


def test_receipt_rejects_changed_lean_input(tmp_path: Path) -> None:
    root = _copy_receipt_fixture(tmp_path)
    fixture = root / "AutoLeanLibrary" / "Fixtures" / "ModelTheory" / "Packet.lean"
    fixture.write_text(fixture.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="source-tree digest"):
        VERIFY.verify_compile_receipt(root)


def test_receipt_rejects_packet_claim_drift(tmp_path: Path) -> None:
    root = _copy_receipt_fixture(tmp_path)
    packet_path = root.joinpath(*Path(VERIFY.SPIKE_PACKET_RELATIVE).parts)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["gap"]["state"] = "closed"
    packet_path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="gap must remain open"):
        VERIFY.verify_compile_receipt(root)


def test_receipt_rejects_report_drift_even_with_updated_backlink(tmp_path: Path) -> None:
    root = _copy_receipt_fixture(tmp_path)
    receipt_path = root.joinpath(*Path(VERIFY.SPIKE_RECEIPT_RELATIVE).parts)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["build_report"]["status"] = "failed"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    packet_path = root.joinpath(*Path(VERIFY.SPIKE_PACKET_RELATIVE).parts)
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["compile_receipt"]["sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    packet_path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="build report digest drifted"):
        VERIFY.verify_compile_receipt(root)


def test_evidence_must_be_new_json_below_evidence_directory(tmp_path: Path) -> None:
    source = tmp_path / "Library"
    source.mkdir()
    output = source / "evidence" / "run.json"
    report = {"schema_version": VERIFY.BUILD_EVIDENCE_SCHEMA, "contains_absolute_paths": False}

    VERIFY._write_evidence(output, source, report)
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(SystemExit, match="already exists"):
        VERIFY._write_evidence(output, source, report)
    with pytest.raises(SystemExit, match="below Library/evidence"):
        VERIFY._write_evidence(source / "run.json", source, report)


def test_windows_host_dispatches_only_wsl_python(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[tuple[str, ...]] = []
    expected_report = {
        "schema_version": VERIFY.BUILD_EVIDENCE_SCHEMA,
        "status": "passed",
    }

    monkeypatch.setattr(VERIFY, "_wsl_path", lambda distribution, path: "/mnt/c/AutoLean/input")

    def fake_run(command: object, **_: object) -> CompletedProcess[bytes]:
        command_tuple = tuple(cast(Sequence[str], command))
        commands.append(command_tuple)
        return CompletedProcess(command_tuple, 0, json.dumps(expected_report).encode(), b"")

    monkeypatch.setattr(VERIFY, "_run", fake_run)
    report = VERIFY._host_build(
        "/home/operator/.cache/autolean/library",
        "Ubuntu-24.04",
        Path("Library/evidence/run.json"),
    )

    assert report == expected_report
    assert commands == [
        (
            "wsl.exe",
            "--distribution",
            "Ubuntu-24.04",
            "--exec",
            "/usr/bin/python3",
            "/mnt/c/AutoLean/input",
            "_native-build",
            "--source-root",
            "/mnt/c/AutoLean/input",
            "--cache-root",
            "/home/operator/.cache/autolean/library",
            "--evidence-out",
            "/mnt/c/AutoLean/input",
        )
    ]


def test_cache_root_requires_absolute_posix_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(VERIFY.Path, "home", lambda: Path("/home/operator"))
    assert VERIFY._cache_root(None) == Path("/home/operator/.cache/autolean/library")
    with pytest.raises(SystemExit, match="absolute"):
        VERIFY._cache_root("relative/cache")
    with pytest.raises(SystemExit, match="traversal-free"):
        VERIFY._cache_root("/home/operator/../cache")


def test_native_environment_retains_proxy_routing_without_reporting_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", "/home/operator")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    environment = VERIFY._native_environment()

    assert environment["HTTPS_PROXY"] == "http://proxy.invalid:3128"
    assert "GIT_CONFIG_GLOBAL" in environment


def test_dependency_manifest_uses_posix_utf8_byte_order(tmp_path: Path) -> None:
    packages = tmp_path / "packages"
    for relative, content in {
        "zeta/.lake/build/lib/lean/Z.olean": b"z",
        "Alpha/source.lean": b"a",
        "alpha/.lake/build/lib/lean/A.olean": b"a",
        "alpha/Nested/source.lean": b"n",
    }.items():
        path = packages.joinpath(*Path(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    manifest = VERIFY._dependency_tree_manifest(packages)
    entries = cast(list[dict[str, object]], manifest["entries"])
    paths = [cast(str, entry["path"]) for entry in entries]

    assert paths == sorted(paths, key=lambda value: value.encode("utf-8"))
    assert all("\\" not in path for path in paths)


def test_dependency_cache_rejects_olean_byte_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_entry, packages, _ = _make_dependency_cache(tmp_path, monkeypatch)
    VERIFY._validate_dependency_cache(cache_entry, LIBRARY_ROOT)

    olean = packages / "mathlib" / ".lake" / "build" / "lib" / "lean" / "Mathlib.olean"
    olean.write_bytes(b"same-size-cache")

    with pytest.raises(SystemExit, match="bytes differ"):
        VERIFY._validate_dependency_cache(cache_entry, LIBRARY_ROOT)


@pytest.mark.parametrize("operation", ("add", "remove"))
def test_dependency_cache_rejects_file_set_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    cache_entry, packages, _ = _make_dependency_cache(tmp_path, monkeypatch)
    build_root = packages / "mathlib" / ".lake" / "build" / "lib" / "lean"
    if operation == "add":
        (build_root / "Injected.olean").write_bytes(b"injected")
    else:
        (build_root / "Mathlib.olean").unlink()

    with pytest.raises(SystemExit, match="bytes differ"):
        VERIFY._validate_dependency_cache(cache_entry, LIBRARY_ROOT)


def test_dependency_cache_rejects_manifest_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_entry, _, _ = _make_dependency_cache(tmp_path, monkeypatch)
    manifest_path = cache_entry / VERIFY.DEPENDENCY_MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["entries"] = []
    manifest_path.write_bytes(VERIFY._canonical_json_bytes(manifest) + b"\n")

    with pytest.raises(SystemExit, match="manifest file digest drifted"):
        VERIFY._validate_dependency_cache(cache_entry, LIBRARY_ROOT)


def test_live_receipt_rejects_missing_dependency_cache(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="cache is missing"):
        VERIFY._verify_live_dependency_cache(LIBRARY_ROOT, tmp_path)


def test_live_receipt_rejects_pollution_even_if_local_cache_is_resigned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache_entry, _, original_binding = _make_dependency_cache(tmp_path, monkeypatch)
    cache_root = tmp_path / "cache-root"
    expected_entry = cache_root / "dependencies" / VERIFY._dependency_cache_key(LIBRARY_ROOT)
    expected_entry.parent.mkdir(parents=True)
    cache_entry.rename(expected_entry)
    olean = (
        expected_entry
        / "packages"
        / "mathlib"
        / ".lake"
        / "build"
        / "lib"
        / "lean"
        / "Mathlib.olean"
    )
    olean.write_bytes(b"polluted-but-locally-resigned")
    manifest_path = expected_entry / VERIFY.DEPENDENCY_MANIFEST_FILENAME
    manifest_path.unlink()
    changed_binding = VERIFY._write_dependency_manifest(
        expected_entry,
        expected_entry / "packages",
    )
    (expected_entry / "identity.json").write_text(
        json.dumps(
            VERIFY._cache_identity(LIBRARY_ROOT, changed_binding),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(VERIFY, "_tracked_dependency_tree", lambda _: original_binding)

    assert changed_binding != original_binding
    with pytest.raises(SystemExit, match="differs from the tracked receipt"):
        VERIFY._verify_live_dependency_cache(LIBRARY_ROOT, cache_root)


def test_dependency_tree_binds_safe_relative_symlink(tmp_path: Path) -> None:
    packages = tmp_path / "packages"
    package = packages / "package"
    package.mkdir(parents=True)
    target = package / "README.md"
    target.write_text("bound target\n", encoding="utf-8")
    link = package / "docs.md"
    try:
        os.symlink("README.md", link)
    except OSError as error:
        pytest.skip(f"symlinks unavailable in this environment: {error}")

    manifest = VERIFY._dependency_tree_manifest(packages)
    entries = cast(list[dict[str, object]], manifest["entries"])

    assert {
        "kind": "symlink",
        "path": "package/docs.md",
        "target": "README.md",
    } in entries


def test_dependency_tree_rejects_generated_output_symlink(tmp_path: Path) -> None:
    packages = tmp_path / "packages"
    build = packages / "package" / ".lake" / "build"
    build.mkdir(parents=True)
    target = packages / "package" / "source.olean"
    target.write_bytes(b"target")
    link = build / "Injected.olean"
    try:
        os.symlink("../../source.olean", link)
    except OSError as error:
        pytest.skip(f"symlinks unavailable in this environment: {error}")

    with pytest.raises(SystemExit, match="must not be a symlink"):
        VERIFY._dependency_tree_manifest(packages)


@pytest.mark.parametrize("git_name", (".git", ".GIT"))
def test_dependency_tree_rejects_symlink_into_excluded_git_metadata(
    tmp_path: Path,
    git_name: str,
) -> None:
    packages = tmp_path / "packages"
    package = packages / "package"
    excluded = package / git_name
    excluded.mkdir(parents=True)
    private = excluded / "private.hash"
    private.write_bytes(b"first-unmanifested-value")
    visible = package / "visible.hash"
    try:
        os.symlink(f"{git_name}/private.hash", visible)
    except OSError as error:
        pytest.skip(f"symlinks unavailable in this environment: {error}")

    with pytest.raises(SystemExit, match="targets excluded Git metadata"):
        VERIFY._dependency_tree_manifest(packages)

    private.write_bytes(b"changed-unmanifested-value")
    with pytest.raises(SystemExit, match="targets excluded Git metadata"):
        VERIFY._dependency_tree_manifest(packages)


@pytest.mark.parametrize("target", ("/outside/cache", "../../../outside/cache"))
def test_dependency_tree_rejects_escaping_symlink_target(target: str) -> None:
    with pytest.raises(SystemExit, match="symlink"):
        VERIFY._normalize_dependency_symlink(PurePosixPath("package/docs"), target)


def test_dependency_tree_rejects_junction_or_reparse_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packages = tmp_path / "packages"
    suspect = packages / "package"
    suspect.mkdir(parents=True)
    monkeypatch.setattr(VERIFY, "_is_junction", lambda path: path == suspect)

    with pytest.raises(SystemExit, match="junction"):
        VERIFY._dependency_tree_manifest(packages)
