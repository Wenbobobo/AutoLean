from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import cast

import pytest

from scripts import (
    mathlib_build_resources,
    mathlib_source_lock,
    oci_mathlib_worker,
    oci_worker,
)


def _package(index: int) -> mathlib_source_lock.GitPackage:
    if index == 0:
        name = "mathlib"
        repository = "mathlib4"
    elif index == 1:
        name = oci_mathlib_worker.PROOFWIDGETS_NAME
        repository = "ProofWidgets4"
    else:
        name = f"dependency{index}"
        repository = f"repository{index}"
    rev = f"{index + 1:040x}"
    return mathlib_source_lock.GitPackage(
        name=name,
        url=f"https://github.com/example/{repository}",
        rev=rev,
        owner="example",
        repository=repository,
        archive_url=f"https://codeload.github.com/example/{repository}/tar.gz/{rev}",
    )


def _prepared(tmp_path: Path) -> oci_mathlib_worker.PreparedInputs:
    archives: list[tuple[mathlib_source_lock.GitPackage, Path, str]] = []
    records: list[dict[str, object]] = []
    archive_lines: list[str] = []
    layout_lines: list[str] = []
    for index in range(9):
        package = _package(index)
        archive = tmp_path / "cache" / f"{package.name}.tar.gz"
        archive.parent.mkdir(exist_ok=True)
        archive.write_bytes(f"archive-{package.name}\n".encode())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive_name = f"{index:02d}-{package.name}.tar.gz"
        role = "root" if index == 0 else "dependency"
        root = f"{package.repository}-{package.rev}"
        archives.append((package, archive, archive_name))
        records.append(
            {
                "archive_file": archive_name,
                "archive_root": root,
                "archive_sha256": digest,
                "name": package.name,
                "rev": package.rev,
                "role": role,
                "url": package.url,
            }
        )
        archive_lines.append(f"{digest}  sources/{archive_name}\n")
        layout_lines.append(f"{package.name}\t{archive_name}\t{root}\t{role}\n")
    archive_manifest = "".join(archive_lines).encode()
    layout = "".join(layout_lines).encode()
    local_path_manifest = b'{"packages":[]}\n'
    js_files = tuple(
        mathlib_build_resources.ResourceFile(
            path=path,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )
        for path, content in (
            ("js/interactiveExpr.js", b"interactive fixture\n"),
            ("js/lake.trace", b"trace fixture\n"),
        )
    )
    js_manifest = "".join(f"{selected.sha256}  {selected.path}\n" for selected in js_files).encode(
        "ascii"
    )
    proofwidgets_js = mathlib_build_resources.PrunedResource(
        files=js_files,
        manifest=js_manifest,
        manifest_sha256=hashlib.sha256(js_manifest).hexdigest(),
        file_count=len(js_files),
        unpacked_bytes=sum(len(selected.content) for selected in js_files),
    )
    source_inputs: dict[str, object] = {
        "build_resource_lock_sha256": "e" * 64,
        "lake_manifest_sha256": "a" * 64,
        "lean_archive_sha256": "b" * 64,
        "mathlib_build_target": oci_mathlib_worker.MATHLIB_BUILD_TARGET,
        "mathlib_local_path_manifest_sha256": hashlib.sha256(local_path_manifest).hexdigest(),
        "mathlib_revision": oci_mathlib_worker.MATHLIB_REVISION,
        "mathlib_source_manifest_sha256": "c" * 64,
        "mathlib_target": oci_mathlib_worker.MATHLIB_TARGET,
        "packages": records,
        "proofwidgets_js_file_count": proofwidgets_js.file_count,
        "proofwidgets_js_manifest_sha256": proofwidgets_js.manifest_sha256,
        "proofwidgets_js_unpacked_bytes": proofwidgets_js.unpacked_bytes,
        "proofwidgets_release_asset_name": mathlib_build_resources.ASSET_NAME,
        "proofwidgets_release_asset_sha256": mathlib_build_resources.ASSET_SHA256,
        "proofwidgets_release_asset_size": mathlib_build_resources.ASSET_SIZE,
        "proofwidgets_release_tag": mathlib_build_resources.RELEASE_TAG,
        "proofwidgets_revision": mathlib_build_resources.SOURCE_REVISION,
        "schema_version": oci_mathlib_worker.SOURCE_INPUTS_SCHEMA,
        "source_archives_manifest_sha256": hashlib.sha256(archive_manifest).hexdigest(),
        "source_layout_sha256": hashlib.sha256(layout).hexdigest(),
        "source_lock_sha256": "d" * 64,
    }
    source_input_bytes = oci_mathlib_worker._canonical_json_bytes(source_inputs)
    return oci_mathlib_worker.PreparedInputs(
        source_inputs=source_inputs,
        source_inputs_bytes=source_input_bytes,
        source_archives_manifest=archive_manifest,
        source_layout=layout,
        local_path_manifest=local_path_manifest,
        proofwidgets_js=proofwidgets_js,
        archives=tuple(archives),
        build_resource_lock_sha256="e" * 64,
        source_lock_sha256="d" * 64,
        source_inputs_sha256=hashlib.sha256(source_input_bytes).hexdigest(),
        source_archives_manifest_sha256=hashlib.sha256(archive_manifest).hexdigest(),
        source_layout_sha256=hashlib.sha256(layout).hexdigest(),
        lake_manifest_sha256="a" * 64,
        mathlib_source_manifest_sha256="c" * 64,
        local_path_manifest_sha256=hashlib.sha256(local_path_manifest).hexdigest(),
        proofwidgets_js_manifest_sha256=proofwidgets_js.manifest_sha256,
    )


def test_mathlib_profile_is_separate_and_source_build_assets_are_frozen() -> None:
    assert oci_mathlib_worker.IMAGE_TAG.startswith("autolean/mathlib-worker:")
    assert oci_mathlib_worker.IMAGE_TAG != oci_worker.IMAGE_TAG
    assert oci_mathlib_worker.MATHLIB_TARGET == "Mathlib.ModelTheory.Semantics"
    assert oci_mathlib_worker.BUILD_ASSETS == (
        "Dockerfile.mathlib",
        "AutoleanMathlibQuery.lean",
        "autolean-mathlib-wrapper",
        "autolean-mathlib-build-receipt",
    )


def test_mathlib_source_manifest_must_match_all_locked_dependencies() -> None:
    dependencies = tuple(_package(index) for index in range(1, 9))
    library_records: dict[str, dict[str, object]] = {}
    document = {
        "lakeDir": ".lake",
        "name": "mathlib",
        "packagesDir": ".lake/packages",
        "version": "1.1.0",
        "packages": [
            {
                "configFile": (
                    "lakefile.lean"
                    if package.name == oci_mathlib_worker.PROOFWIDGETS_NAME
                    else "lakefile.toml"
                ),
                "inherited": False,
                "inputRev": "main",
                "manifestFile": "lake-manifest.json",
                "name": package.name,
                "rev": package.rev,
                "scope": "example",
                "subDir": None,
                "type": "git",
                "url": package.url,
            }
            for package in dependencies
        ],
    }
    for record in cast(list[dict[str, object]], document["packages"]):
        library_records[cast(str, record["name"])] = dict(record)
    rendered = json.dumps(document).encode()

    overlay_bytes = oci_mathlib_worker._mathlib_local_path_manifest(
        rendered,
        dependencies,
        library_records,
    )
    overlay = json.loads(overlay_bytes)

    assert [record["name"] for record in overlay["packages"]] == [
        package.name for package in dependencies
    ]
    assert [record["dir"] for record in overlay["packages"]] == [
        f".lake/packages/{package.name}" for package in dependencies
    ]
    assert all(record["type"] == "path" for record in overlay["packages"])
    assert overlay["packages"][0]["configFile"] == "lakefile.lean"
    assert all(record["configFile"] == "lakefile.toml" for record in overlay["packages"][1:])
    cast(dict[str, object], document["packages"][0])["rev"] = "f" * 40
    with pytest.raises(
        oci_mathlib_worker.MathlibWorkerError,
        match="locked dependency proofwidgets",
    ):
        oci_mathlib_worker._mathlib_local_path_manifest(
            json.dumps(document).encode(),
            dependencies,
            library_records,
        )


def test_fresh_build_context_has_exact_inputs_and_excludes_host_lake_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    worker = repo / "Prover" / "worker"
    worker.mkdir(parents=True)
    for name in oci_mathlib_worker.BUILD_ASSETS:
        source = Path(__file__).resolve().parents[2] / "Prover" / "worker" / name
        (worker / name).write_bytes(source.read_bytes())
    (worker / "mathlib-source-lock.v1.json").write_text("{}\n", encoding="utf-8")
    (worker / "mathlib-build-resource-lock.v1.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (repo / ".lake" / "build").mkdir(parents=True)
    (repo / ".lake" / "build" / "poison.olean").write_bytes(b"host poison")
    prepared = _prepared(tmp_path)
    (tmp_path / "cache" / ".lake").mkdir()
    (tmp_path / "cache" / ".lake" / "poison.olean").write_bytes(b"cache poison")
    lean_archive = tmp_path / "lean.tar.zst"
    lean_archive.write_bytes(b"lean archive fixture")
    monkeypatch.setattr(
        oci_worker,
        "LEAN_ARCHIVE_SHA256",
        hashlib.sha256(lean_archive.read_bytes()).hexdigest(),
    )

    inventory = oci_mathlib_worker._stage_build_context(
        repo,
        tmp_path / "fresh-context",
        lean_archive,
        prepared,
    )

    assert len([path for path in inventory if path.startswith("sources/")]) == 9
    assert not any(".lake" in path for path in inventory)
    assert not any(
        forbidden in path for path in inventory for forbidden in ("/lib/", "/ir/", ".olean", ".so")
    )
    assert mathlib_build_resources.ASSET_NAME not in inventory
    assert set(inventory) == {
        oci_worker.LEAN_ARCHIVE,
        "mathlib-build-resource-lock.v1.json",
        "mathlib-source-lock.v1.json",
        "mathlib-source-inputs.v1.json",
        "source-archives.sha256",
        "source-layout.tsv",
        "mathlib-local-path-manifest.v1.json",
        "proofwidgets-js.sha256",
        *oci_mathlib_worker.BUILD_ASSETS,
        *(f"proofwidgets-release/{selected.path}" for selected in prepared.proofwidgets_js.files),
        *(f"sources/{archive_name}" for _, _, archive_name in prepared.archives),
    }


def test_dockerfile_checks_all_source_hashes_before_extracting_and_builds_offline_profile() -> None:
    worker = Path(__file__).resolve().parents[2] / "Prover" / "worker"
    dockerfile = (worker / "Dockerfile.mathlib").read_text(encoding="utf-8")
    helper = (worker / "AutoleanMathlibQuery.lean").read_text(encoding="utf-8")
    wrapper = (worker / "autolean-mathlib-wrapper").read_text(encoding="utf-8")
    receipt_tool = (worker / "autolean-mathlib-build-receipt").read_text(encoding="utf-8")

    assert dockerfile.index("sha256sum --check --strict source-archives.sha256") < (
        dockerfile.index("tar --no-same-owner")
    )
    assert 'test "$(find /tmp/autolean-build/sources -type f | wc -l)" -eq 9' in dockerfile
    assert "test ! -e /opt/mathlib/.lake/build" in dockerfile
    assert "mathlib-source-lake-manifest.json" in dockerfile
    assert "mathlib-local-path-manifest.v1.json" in dockerfile
    assert "mathlib-build-resource-lock.v1.json" in dockerfile
    assert "proofwidgets-release/js/" in dockerfile
    assert "proofwidgets-js.sha256" in dockerfile
    assert "lake build --no-build widgetJsAll" in dockerfile
    assert "lake build widgetJsAll" in dockerfile
    assert "test ! -e widget/node_modules" in dockerfile
    assert "lakefile.autolean-source-build.lean" not in dockerfile
    assert "proofwidgets-config-patch-policy" not in dockerfile
    assert f"RUN lake build {oci_mathlib_worker.MATHLIB_BUILD_TARGET}" in dockerfile
    helper_compile = dockerfile.index('LEAN_PATH="$(cat /opt/autolean/environment/lean-path)" lean')
    assert dockerfile.rfind("\nWORKDIR /\n", 0, helper_compile) > dockerfile.index(
        f"RUN lake build {oci_mathlib_worker.MATHLIB_BUILD_TARGET}"
    )
    assert "lean --deps" in dockerfile
    assert "/opt/lean-4.28.0-linux/*.olean|/opt/mathlib/*.olean" in dockerfile
    assert "/opt/lean-*/*.olean" not in dockerfile
    assert "/opt/autolean/environment/lean-path" in dockerfile
    assert "apt-get" not in dockerfile
    assert "curl " not in dockerfile
    assert "git clone" not in dockerfile
    assert "import Mathlib.ModelTheory.Semantics" in helper
    assert oci_mathlib_worker.MATHLIB_REVISION in helper
    assert "/deps" not in wrapper
    assert "sha256sum --check --strict --status" in receipt_tool
    assert "proofwidgets-js.sha256" in receipt_tool
    assert "find js -type f -print | LC_ALL=C sort" in receipt_tool
    assert 'cmp -s "$proofwidgets_expected" "$proofwidgets_actual"' in receipt_tool
    assert '"$proofwidgets_bytes" -eq 6902528' in receipt_tool
    assert 'wc -l <"$proofwidgets_actual"' in receipt_tool


def test_receipt_tool_rejects_false_dynamic_claims(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("a POSIX shell is required for the receipt helper test")
    worker = Path(__file__).resolve().parents[2] / "Prover" / "worker"
    script = tmp_path / "receipt"
    script.write_bytes((worker / "autolean-mathlib-build-receipt").read_bytes())
    artifacts = {
        "helper.olean": b"helper",
        "closure.sha256": b"a" * 64 + b"  /opt/mathlib/A.olean\n",
        "target.olean": b"target",
        "runtime.sha256": b"b" * 64 + b"  /opt/autolean/file\n",
    }
    for name, content in artifacts.items():
        (tmp_path / name).write_bytes(content)
    receipt = {
        "helper_olean_sha256": hashlib.sha256(artifacts["helper.olean"]).hexdigest(),
        "mathlib_import_closure_count": 1,
        "mathlib_import_closure_sha256": hashlib.sha256(artifacts["closure.sha256"]).hexdigest(),
        "mathlib_target_olean_sha256": hashlib.sha256(artifacts["target.olean"]).hexdigest(),
        "runtime_files_manifest_sha256": hashlib.sha256(artifacts["runtime.sha256"]).hexdigest(),
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, separators=(",", ":")) + "\n",
        encoding="ascii",
        newline="\n",
    )
    command = [
        bash,
        "-c",
        (
            "AUTOLEAN_RECEIPT_VERIFY_DYNAMIC_ONLY=1 /bin/sh receipt "
            "receipt.json helper.olean closure.sha256 target.olean runtime.sha256"
        ),
    ]

    accepted = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert accepted.returncode == 0, accepted.stderr

    receipt["runtime_files_manifest_sha256"] = "0" * 64
    receipt_path.write_text(
        json.dumps(receipt, separators=(",", ":")) + "\n",
        encoding="ascii",
        newline="\n",
    )
    rejected = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0

    receipt["runtime_files_manifest_sha256"] = hashlib.sha256(
        artifacts["runtime.sha256"]
    ).hexdigest()
    receipt_path.write_text(
        json.dumps(receipt, separators=(",", ":")) + "\n",
        encoding="ascii",
        newline="\n",
    )
    (tmp_path / "runtime.sha256").write_bytes(b"changed after receipt generation\n")
    rejected_changed_artifact = subprocess.run(
        command,
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected_changed_artifact.returncode != 0


def test_receipt_command_is_digest_pinned_and_network_disabled() -> None:
    image = "autolean/mathlib-worker@sha256:" + "a" * 64

    command = oci_mathlib_worker._receipt_command(image)

    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") :][:2] == ["--cap-drop", "ALL"]
    assert command[command.index("--user") :][:2] == ["--user", "65532:65532"]
    with pytest.raises(oci_mathlib_worker.MathlibWorkerError, match="digest-pinned"):
        oci_mathlib_worker._receipt_command(oci_mathlib_worker.IMAGE_TAG)


def test_local_build_without_repo_digest_fails_closed() -> None:
    with pytest.raises(
        oci_mathlib_worker.MathlibWorkerError,
        match="digest-pinned repository identity",
    ):
        oci_mathlib_worker._image_reference({"Id": "sha256:" + "a" * 64, "RepoDigests": []})


def test_normalized_build_policy_binds_public_args_without_temp_context(
    tmp_path: Path,
) -> None:
    prepared = _prepared(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    assets = oci_mathlib_worker._asset_hashes(repo_root / "Prover" / "worker")
    policy = oci_mathlib_worker._normalized_build_policy(prepared, assets)
    command = oci_mathlib_worker._build_command(tmp_path / "ephemeral", prepared, assets)

    assert policy["flags"] == ["--no-cache", "--pull=false", "--network=none"]
    assert policy["context"] == "fresh-exact-staging-directory"
    assert str(tmp_path) not in json.dumps(policy)
    assert command[-1] == str(tmp_path / "ephemeral")
    assert "--no-cache" in command
    assert command[command.index("--network=none") :][:2] == ["--network=none", "--file"]
    for name, value in cast(dict[str, str], policy["build_args"]).items():
        assert f"{name}={value}" in command


def test_image_receipt_verifier_binds_labels_static_inputs_and_dynamic_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    assets = oci_mathlib_worker._asset_hashes(repo_root / "Prover" / "worker")
    labels = {
        oci_mathlib_worker.LABEL_BUILD_RESOURCE_LOCK: (prepared.build_resource_lock_sha256),
        oci_mathlib_worker.LABEL_SOURCE_LOCK: prepared.source_lock_sha256,
        oci_mathlib_worker.LABEL_SOURCE_INPUTS: prepared.source_inputs_sha256,
        oci_mathlib_worker.LABEL_LAKE_MANIFEST: prepared.lake_manifest_sha256,
        oci_mathlib_worker.LABEL_LOCAL_PATH_MANIFEST: (prepared.local_path_manifest_sha256),
        oci_mathlib_worker.LABEL_PROOFWIDGETS_ASSET: (mathlib_build_resources.ASSET_SHA256),
        oci_mathlib_worker.LABEL_PROOFWIDGETS_JS_MANIFEST: (
            prepared.proofwidgets_js_manifest_sha256
        ),
        oci_mathlib_worker.LABEL_PROOFWIDGETS_JS_FILE_COUNT: str(
            prepared.proofwidgets_js.file_count
        ),
        oci_mathlib_worker.LABEL_PROOFWIDGETS_RELEASE_TAG: (mathlib_build_resources.RELEASE_TAG),
        oci_mathlib_worker.LABEL_PROOFWIDGETS_REVISION: (mathlib_build_resources.SOURCE_REVISION),
        oci_mathlib_worker.LABEL_MATHLIB_REVISION: oci_mathlib_worker.MATHLIB_REVISION,
        oci_mathlib_worker.LABEL_MATHLIB_TARGET: oci_mathlib_worker.MATHLIB_TARGET,
        oci_mathlib_worker.LABEL_MATHLIB_BUILD_TARGET: (oci_mathlib_worker.MATHLIB_BUILD_TARGET),
        oci_mathlib_worker.LABEL_DOCKERFILE: assets["Dockerfile.mathlib"],
        oci_mathlib_worker.LABEL_HELPER: assets["AutoleanMathlibQuery.lean"],
        oci_mathlib_worker.LABEL_WRAPPER: assets["autolean-mathlib-wrapper"],
    }
    receipt = {
        "build_resource_lock_sha256": prepared.build_resource_lock_sha256,
        "build_receipt_tool_sha256": assets["autolean-mathlib-build-receipt"],
        "dockerfile_sha256": assets["Dockerfile.mathlib"],
        "helper_olean_sha256": "1" * 64,
        "helper_source_sha256": assets["AutoleanMathlibQuery.lean"],
        "lake_manifest_sha256": prepared.lake_manifest_sha256,
        "lean_archive_sha256": oci_worker.LEAN_ARCHIVE_SHA256,
        "mathlib_build_target": oci_mathlib_worker.MATHLIB_BUILD_TARGET,
        "mathlib_import_closure_count": 42,
        "mathlib_import_closure_sha256": "2" * 64,
        "mathlib_local_path_manifest_sha256": prepared.local_path_manifest_sha256,
        "mathlib_revision": oci_mathlib_worker.MATHLIB_REVISION,
        "mathlib_source_manifest_sha256": prepared.mathlib_source_manifest_sha256,
        "mathlib_target": oci_mathlib_worker.MATHLIB_TARGET,
        "mathlib_target_olean_sha256": "3" * 64,
        "proofwidgets_js_file_count": prepared.proofwidgets_js.file_count,
        "proofwidgets_js_manifest_sha256": prepared.proofwidgets_js_manifest_sha256,
        "proofwidgets_js_unpacked_bytes": prepared.proofwidgets_js.unpacked_bytes,
        "proofwidgets_release_asset_name": mathlib_build_resources.ASSET_NAME,
        "proofwidgets_release_asset_sha256": mathlib_build_resources.ASSET_SHA256,
        "proofwidgets_release_asset_size": mathlib_build_resources.ASSET_SIZE,
        "proofwidgets_release_tag": mathlib_build_resources.RELEASE_TAG,
        "proofwidgets_revision": mathlib_build_resources.SOURCE_REVISION,
        "runtime_files_manifest_sha256": "4" * 64,
        "schema_version": oci_mathlib_worker.BUILD_RECEIPT_SCHEMA,
        "source_inputs_sha256": prepared.source_inputs_sha256,
        "source_lock_sha256": prepared.source_lock_sha256,
        "wrapper_sha256": assets["autolean-mathlib-wrapper"],
    }
    monkeypatch.setattr(
        oci_mathlib_worker,
        "_inspect",
        lambda image: {"Id": "sha256:" + "9" * 64, "Config": {"Labels": labels}},
    )
    monkeypatch.setattr(
        oci_mathlib_worker,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0],
            0,
            json.dumps(receipt, separators=(",", ":")) + "\n",
            "",
        ),
    )
    image = "autolean/mathlib-worker@sha256:" + "a" * 64

    _, observed = oci_mathlib_worker.verify_image_receipt(
        repo_root,
        image,
        prepared,
    )

    assert observed == receipt
    labels[oci_mathlib_worker.LABEL_SOURCE_LOCK] = "0" * 64
    with pytest.raises(oci_mathlib_worker.MathlibWorkerError, match="source-lock"):
        oci_mathlib_worker.verify_image_receipt(repo_root, image, prepared)
