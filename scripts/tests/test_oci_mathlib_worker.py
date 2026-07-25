from __future__ import annotations

import hashlib
import json
import os
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
    oci_worker_canary,
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
        "AutoleanMathlibDeclarationQuery.lean",
        "autolean-mathlib-wrapper",
        "autolean-mathlib-declaration-query",
        "autolean-mathlib-build-receipt",
    )
    assert oci_mathlib_worker.IMAGE_TAG.endswith("source-v2")
    assert oci_mathlib_worker.BUILD_RECEIPT_SCHEMA.endswith(".v2")


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
    declaration_helper = (worker / "AutoleanMathlibDeclarationQuery.lean").read_text(
        encoding="utf-8"
    )
    wrapper = (worker / "autolean-mathlib-wrapper").read_text(encoding="utf-8")
    declaration_wrapper = (worker / "autolean-mathlib-declaration-query").read_text(
        encoding="utf-8"
    )
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
    assert '"lake_manifest_sha256":"%s"' in dockerfile
    assert '"lake_manifest_hash":"%s"' not in dockerfile
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
    assert "readModuleData" in declaration_helper
    assert "candidate.constNames.any" in declaration_helper
    assert "declaration is not defined by Candidate" in declaration_helper
    assert "allImportedModuleNames" in declaration_helper
    assert "AutoleanMathlibDeclarationQuery.olean" in dockerfile
    assert "autolean-mathlib-declaration-query" in dockerfile
    assert "/deps" not in wrapper
    assert "declarations must be sorted" in declaration_wrapper
    assert "--compiled" in declaration_wrapper
    assert 'LEAN_PATH="/compiled:$lean_path" lean --run' in declaration_wrapper
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
        "declaration-helper.olean": b"declaration helper",
        "closure.sha256": b"a" * 64 + b"  /opt/mathlib/A.olean\n",
        "target.olean": b"target",
        "runtime.sha256": b"b" * 64 + b"  /opt/autolean/file\n",
    }
    for name, content in artifacts.items():
        (tmp_path / name).write_bytes(content)
    receipt = {
        "declaration_query_helper_olean_sha256": hashlib.sha256(
            artifacts["declaration-helper.olean"]
        ).hexdigest(),
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
            "receipt.json helper.olean declaration-helper.olean closure.sha256 "
            "target.olean runtime.sha256"
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
        oci_mathlib_worker.LABEL_DECLARATION_QUERY_HELPER: assets[
            "AutoleanMathlibDeclarationQuery.lean"
        ],
        oci_mathlib_worker.LABEL_DECLARATION_QUERY_WRAPPER: assets[
            "autolean-mathlib-declaration-query"
        ],
    }
    receipt = {
        "build_resource_lock_sha256": prepared.build_resource_lock_sha256,
        "build_receipt_tool_sha256": assets["autolean-mathlib-build-receipt"],
        "declaration_query_helper_olean_sha256": "0" * 64,
        "declaration_query_helper_source_sha256": assets["AutoleanMathlibDeclarationQuery.lean"],
        "declaration_query_wrapper_sha256": assets["autolean-mathlib-declaration-query"],
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


def _declaration_query_record(
    prepared: oci_mathlib_worker.PreparedInputs,
    assets: dict[str, str],
    declarations: tuple[str, ...],
) -> dict[str, object]:
    return {
        "candidate_direct_imports": ["Mathlib.ModelTheory.Semantics"],
        "declarations": [
            {
                "canonical_type": f"Type for {declaration}",
                "declaration": declaration,
                "observed_axioms": [],
            }
            for declaration in declarations
        ],
        "image_identity": {
            "query_helper_path": oci_mathlib_worker.DECLARATION_QUERY_HELPER,
            "query_helper_sha256": assets["AutoleanMathlibDeclarationQuery.lean"],
            "schema_version": "autolean.image-owned-declaration-query-identity.v1",
            "wrapper_path": oci_mathlib_worker.DECLARATION_QUERY_EXECUTABLE,
            "wrapper_sha256": assets["autolean-mathlib-declaration-query"],
        },
        "lake_manifest_hash": prepared.lake_manifest_sha256,
        "lean_version": "v4.28.0",
        "mathlib_revision": oci_mathlib_worker.MATHLIB_REVISION,
        "module_import_closure": ["Candidate", "Mathlib.ModelTheory.Semantics"],
        "schema_version": oci_mathlib_worker.DECLARATION_QUERY_SCHEMA,
        "type_format": "autolean.lean-pp-expr.v1",
    }


def test_declaration_query_record_binds_image_identity_types_axioms_and_closure(
    tmp_path: Path,
) -> None:
    prepared = _prepared(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    assets = oci_mathlib_worker._asset_hashes(repo_root / "Prover" / "worker")
    declarations = ("AutoLean.Test.alpha", "AutoLean.Test.beta")
    record = _declaration_query_record(prepared, assets, declarations)

    observed = oci_mathlib_worker._declaration_query_record(
        json.dumps(record, separators=(",", ":")),
        declarations=declarations,
        prepared=prepared,
        assets=assets,
    )

    assert observed["candidate_direct_imports"] == ["Mathlib.ModelTheory.Semantics"]
    assert observed["module_import_closure"] == ["Candidate", "Mathlib.ModelTheory.Semantics"]
    observed_declarations = cast(list[dict[str, object]], observed["declarations"])
    assert [item["declaration"] for item in observed_declarations] == list(declarations)
    assert all(
        len(cast(str, item["canonical_type_sha256"])) == 64 for item in observed_declarations
    )

    record["module_import_closure"] = ["Mathlib.ModelTheory.Semantics"]
    with pytest.raises(oci_mathlib_worker.MathlibWorkerError, match="omits the compiled candidate"):
        oci_mathlib_worker._declaration_query_record(
            json.dumps(record, separators=(",", ":")),
            declarations=declarations,
            prepared=prepared,
            assets=assets,
        )


@pytest.mark.parametrize(
    "case",
    (
        "extra-stdout-line",
        "nested-duplicate-json-key",
        "declaration-order",
        "declaration-replaced",
        "image-helper-hash-replaced",
        "lake-manifest-replaced",
        "mathlib-revision-replaced",
        "field-added",
        "field-deleted",
        "field-wrong-type",
    ),
)
def test_declaration_query_record_rejects_protocol_mutations(
    tmp_path: Path,
    case: str,
) -> None:
    prepared = _prepared(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    assets = oci_mathlib_worker._asset_hashes(repo_root / "Prover" / "worker")
    declarations = ("AutoLean.Test.alpha", "AutoLean.Test.beta")
    record = _declaration_query_record(prepared, assets, declarations)
    rendered: str

    if case == "extra-stdout-line":
        rendered = f"{json.dumps(record)}\n{json.dumps(record)}"
    elif case == "nested-duplicate-json-key":
        rendered = json.dumps(record).replace(
            '"image_identity": {',
            '"image_identity": {"query_helper_sha256": "' + "0" * 64 + '", ',
            1,
        )
    else:
        if case == "declaration-order":
            record["declarations"] = list(reversed(cast(list[object], record["declarations"])))
        elif case == "declaration-replaced":
            result = cast(list[dict[str, object]], record["declarations"])
            result[0]["declaration"] = "AutoLean.Test.replaced"
        elif case == "image-helper-hash-replaced":
            identity = cast(dict[str, object], record["image_identity"])
            identity["query_helper_sha256"] = "0" * 64
        elif case == "lake-manifest-replaced":
            record["lake_manifest_hash"] = "0" * 64
        elif case == "mathlib-revision-replaced":
            record["mathlib_revision"] = "0" * 40
        elif case == "field-added":
            record["unexpected"] = True
        elif case == "field-deleted":
            del record["type_format"]
        elif case == "field-wrong-type":
            record["module_import_closure"] = "not-a-list"
        else:
            raise AssertionError(f"unknown protocol mutation {case}")
        rendered = json.dumps(record)

    with pytest.raises(oci_mathlib_worker.MathlibWorkerError):
        oci_mathlib_worker._declaration_query_record(
            rendered,
            declarations=declarations,
            prepared=prepared,
            assets=assets,
        )


def test_declaration_query_command_and_cli_require_sorted_fully_qualified_names(
    tmp_path: Path,
) -> None:
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    candidate = tmp_path / "Candidate.olean"
    candidate.write_bytes(b"fixture")
    declarations = ("AutoLean.Test.alpha", "AutoLean.Test.beta")

    command = oci_mathlib_worker._declaration_query_command(
        image,
        candidate,
        "fixture-query",
        declarations,
    )

    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert "--read-only" in command
    assert command[command.index("--compiled") :][:2] == [
        "--compiled",
        "/compiled/Candidate.olean",
    ]
    assert any("dst=/compiled/Candidate.olean,readonly" in item for item in command)
    assert command[-4:] == [
        "--declaration",
        "AutoLean.Test.alpha",
        "--declaration",
        "AutoLean.Test.beta",
    ]
    parsed = oci_mathlib_worker.parse_args(
        [
            "query-declarations",
            "--image",
            image,
            "--candidate",
            str(candidate),
            "--declaration",
            declarations[0],
            "--declaration",
            declarations[1],
        ]
    )
    assert tuple(parsed.declaration) == declarations
    with pytest.raises(SystemExit):
        oci_mathlib_worker.parse_args(
            [
                "query-declarations",
                "--image",
                image,
                "--candidate",
                str(candidate),
                "--declaration",
                "AutoLean.Test.beta",
                "--declaration",
                "AutoLean.Test.alpha",
            ]
        )
    with pytest.raises(SystemExit):
        oci_mathlib_worker.parse_args(
            [
                "query-declarations",
                "--image",
                image,
                "--candidate",
                str(candidate),
                "--declaration",
                "not-qualified",
            ]
        )


class _FakeDeclarationQueryWorker:
    SEALED_CANDIDATE_MAX_BYTES = oci_worker_canary.SEALED_CANDIDATE_MAX_BYTES

    def __init__(self, observation: str) -> None:
        self._observation = observation
        self._candidate: Path | None = None
        self._compiler_output: Path | None = None
        self.compiled_source: bytes | None = None
        self.calls: list[tuple[list[str], str]] = []

    def _compile_command(
        self,
        image: str,
        candidate: Path,
        compiler_output: Path,
        container_name: str,
    ) -> list[str]:
        self._candidate = candidate
        self._compiler_output = compiler_output
        return ["compile", image, container_name]

    def _seal_direct_olean(
        self,
        compiler_output: Path,
        sealed_directory: Path,
    ) -> tuple[Path, str]:
        assert compiler_output == self._compiler_output
        sealed = sealed_directory / "Candidate.olean"
        sealed.write_bytes((compiler_output / "Candidate.olean").read_bytes())
        return sealed, hashlib.sha256(sealed.read_bytes()).hexdigest()

    def _run_phase(
        self,
        command: list[str],
        container_name: str,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, container_name))
        if command[0] == "compile":
            assert self._compiler_output is not None
            assert self._candidate is not None
            self.compiled_source = self._candidate.read_bytes()
            (self._compiler_output / "Candidate.olean").write_bytes(
                b"compiled:" + self.compiled_source
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=self._observation, stderr="")


def _fixture_source_snapshot(
    candidate: Path,
    snapshot_directory: Path,
) -> oci_mathlib_worker.CandidateSourceSnapshot:
    snapshot_directory.mkdir(mode=0o700)
    destination = snapshot_directory / "Candidate.lean"
    content = candidate.read_bytes()
    destination.write_bytes(content)
    destination.chmod(0o444)
    return oci_mathlib_worker.CandidateSourceSnapshot(
        path=destination,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def test_declaration_query_action_compiles_frozen_source_and_has_stable_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared(tmp_path)
    repo_root = Path(__file__).resolve().parents[2]
    assets = oci_mathlib_worker._asset_hashes(repo_root / "Prover" / "worker")
    declarations = ("AutoLean.Test.alpha", "AutoLean.Test.beta")
    observation = json.dumps(_declaration_query_record(prepared, assets, declarations))
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    candidate = (
        repo_root / "Prover" / "worker" / "tests" / "fixtures" / "CandidateWithMathlibImport.lean"
    )
    candidate_source = candidate.read_bytes()
    assert b"import Mathlib.ModelTheory.Semantics" in candidate_source
    assert b"theorem candidateOwned" in candidate_source
    fake_worker = _FakeDeclarationQueryWorker(observation)

    monkeypatch.setattr(oci_mathlib_worker, "_oci_worker_canary", lambda: fake_worker)
    if getattr(os, "O_NOFOLLOW", None) is None:
        monkeypatch.setattr(
            oci_mathlib_worker,
            "_snapshot_candidate",
            _fixture_source_snapshot,
        )
    monkeypatch.setattr(
        oci_mathlib_worker,
        "prepare_inputs",
        lambda _repo, _source, _resources: prepared,
    )
    monkeypatch.setattr(
        oci_mathlib_worker,
        "verify_image_receipt",
        lambda _repo, _image, _prepared: ({}, {"schema_version": "fixture"}),
    )
    monkeypatch.setattr(oci_mathlib_worker, "_asset_hashes", lambda _worker: assets)

    result = oci_mathlib_worker.query_declarations(
        repo_root,
        tmp_path / "sources",
        tmp_path / "resources",
        image,
        candidate,
        declarations,
    )

    assert len(fake_worker.calls) == 2
    assert fake_worker.calls[0][0][0] == "compile"
    assert (
        fake_worker.calls[1][0][
            fake_worker.calls[1][0].index(oci_mathlib_worker.DECLARATION_QUERY_EXECUTABLE)
        ]
        == oci_mathlib_worker.DECLARATION_QUERY_EXECUTABLE
    )
    assert fake_worker.compiled_source == candidate_source
    assert result["source_snapshot_sha256"] == hashlib.sha256(candidate_source).hexdigest()
    assert (
        result["sealed_candidate_sha256"]
        == hashlib.sha256(b"compiled:" + candidate_source).hexdigest()
    )
    assert result["observation"] == oci_mathlib_worker._declaration_query_record(
        observation,
        declarations=declarations,
        prepared=prepared,
        assets=assets,
    )
    second_worker = _FakeDeclarationQueryWorker(observation)
    monkeypatch.setattr(oci_mathlib_worker, "_oci_worker_canary", lambda: second_worker)
    second_result = oci_mathlib_worker.query_declarations(
        repo_root,
        tmp_path / "sources",
        tmp_path / "resources",
        image,
        candidate,
        declarations,
    )

    policy_json = json.dumps(result["execution_policy"], sort_keys=True)
    policy = cast(dict[str, object], result["execution_policy"])
    phases = cast(list[dict[str, object]], policy["phases"])
    assert result["execution_policy"] == second_result["execution_policy"]
    assert result["execution_policy_sha256"] == second_result["execution_policy_sha256"]
    assert policy["image"] == image
    assert cast(dict[str, object], policy["container_policy"])["network"] == "none"
    assert cast(dict[str, object], policy["container_policy"])["read_only_rootfs"] is True
    assert [phase["name"] for phase in phases] == ["compile", "seal", "query"]
    assert cast(list[dict[str, object]], phases[0]["mounts"])[0]["role"] == "source_snapshot"
    assert cast(list[dict[str, object]], phases[2]["mounts"])[0]["role"] == "sealed_candidate"
    assert phases[1]["sealed_candidate_max_bytes"] == oci_worker_canary.SEALED_CANDIDATE_MAX_BYTES
    assert phases[2]["declarations"] == list(declarations)
    assert "compile_command_sha256" not in result
    assert "query_command_sha256" not in result
    assert str(tmp_path) not in policy_json
    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        assert str(getuid()) not in policy_json
    for _, container_name in [*fake_worker.calls, *second_worker.calls]:
        assert container_name not in policy_json


def test_declaration_query_evidence_has_stable_content_and_non_self_referential_hash(
    tmp_path: Path,
) -> None:
    document: dict[str, object] = {
        "image": "autolean/mathlib-worker@sha256:" + "a" * 64,
        "schema_version": oci_mathlib_worker.DECLARATION_QUERY_EVIDENCE_SCHEMA,
        "source_inputs_sha256": "b" * 64,
    }
    expected = (
        "{\n"
        f'  "image": "{document["image"]}",\n'
        '  "schema_version": "autolean.mathlib-declaration-query-evidence.v1",\n'
        f'  "source_inputs_sha256": "{document["source_inputs_sha256"]}"\n'
        "}\n"
    ).encode()

    result = oci_mathlib_worker._record_declaration_query_evidence(tmp_path, document)

    output = (
        tmp_path
        / "release-evidence"
        / "oci-worker"
        / oci_mathlib_worker.DECLARATION_QUERY_EVIDENCE_NAME
    )
    assert output.read_bytes() == expected
    assert hashlib.sha256(expected).hexdigest() == (
        "0b24e915be544411ca450876bc4ed0d882ba765a60468fc05f4d553e805bef61"
    )
    assert result == {
        **document,
        "evidence_sha256": hashlib.sha256(expected).hexdigest(),
    }
    assert "evidence_sha256" not in json.loads(output.read_text(encoding="utf-8"))
    assert "evidence_sha256" not in document


def test_external_python_query_cli_records_and_prints_evidence_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    candidate = tmp_path / "Candidate.lean"
    candidate.write_text("theorem fixture : True := trivial\n", encoding="utf-8")
    document: dict[str, object] = {
        "schema_version": oci_mathlib_worker.DECLARATION_QUERY_EVIDENCE_SCHEMA,
    }
    recorded: list[tuple[Path, dict[str, object]]] = []
    monkeypatch.setattr(
        oci_mathlib_worker,
        "query_declarations",
        lambda *_arguments: document,
    )

    def record(repo_root: Path, result: dict[str, object]) -> dict[str, object]:
        recorded.append((repo_root, result))
        return {**result, "evidence_sha256": "c" * 64}

    monkeypatch.setattr(oci_mathlib_worker, "_record_declaration_query_evidence", record)

    oci_mathlib_worker.main(
        [
            "query-declarations",
            "--image",
            image,
            "--candidate",
            str(candidate),
            "--declaration",
            "AutoLean.Test.fixture",
            "--native",
            "--external-python",
        ]
    )

    printed = json.loads(capsys.readouterr().out)
    assert len(recorded) == 1
    assert recorded[0][0] == Path(oci_mathlib_worker.__file__).resolve().parents[1]
    assert recorded[0][1] is document
    assert printed["evidence_sha256"] == "c" * 64


def test_external_mathlib_actions_sync_complete_runtime_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def run(
        argv: list[str],
        **_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(shutil, "which", lambda _name: "/fixture/uv")
    monkeypatch.setattr(oci_mathlib_worker, "_run", run)
    image = "autolean/mathlib-worker@sha256:" + "a" * 64
    repo_root = tmp_path / "repo"
    source_cache = tmp_path / "sources"
    build_resource_cache = tmp_path / "resources"
    candidate = tmp_path / "Candidate.lean"

    oci_mathlib_worker._external_canary(
        repo_root,
        source_cache,
        build_resource_cache,
        image,
    )
    canary_calls = list(calls)
    calls.clear()
    oci_mathlib_worker._external_declaration_query(
        repo_root,
        source_cache,
        build_resource_cache,
        image,
        candidate,
        ("AutoLean.Test.fixture",),
    )
    declaration_calls = list(calls)
    expected_sync = [
        "/fixture/uv",
        "sync",
        "--frozen",
        "--package",
        "autolean-builder",
        "--package",
        "autolean-control-plane",
        "--package",
        "autolean-prover",
        "--no-dev",
    ]

    assert oci_mathlib_worker.EXTERNAL_RUNTIME_PACKAGES == (
        "autolean-builder",
        "autolean-control-plane",
        "autolean-prover",
    )
    assert canary_calls[0] == expected_sync
    assert declaration_calls[0] == expected_sync
    assert canary_calls[1][canary_calls[1].index("-m") + 2] == "canary"
    assert declaration_calls[1][declaration_calls[1].index("-m") + 2] == "query-declarations"


@pytest.mark.integration
@pytest.mark.skipif(os.name != "posix", reason="source-v2 OCI integration is Linux-only")
def test_source_v2_image_enforces_candidate_declaration_ownership() -> None:
    image = os.environ.get("AUTOLEAN_TEST_MATHLIB_SOURCE_V2_IMAGE")
    if image is None:
        pytest.skip("AUTOLEAN_TEST_MATHLIB_SOURCE_V2_IMAGE is not configured")
    repo_root = Path(__file__).resolve().parents[2]
    candidate = (
        repo_root / "Prover" / "worker" / "tests" / "fixtures" / "CandidateWithMathlibImport.lean"
    )
    owned_declaration = "AutoLean.OCI.Ownership.candidateOwned"

    owned = oci_mathlib_worker.query_declarations(
        repo_root,
        mathlib_source_lock.DEFAULT_CACHE,
        mathlib_build_resources.DEFAULT_CACHE,
        image,
        candidate,
        (owned_declaration,),
    )

    observation = cast(dict[str, object], owned["observation"])
    owned_records = cast(list[dict[str, object]], observation["declarations"])
    assert [record["declaration"] for record in owned_records] == [owned_declaration]
    with pytest.raises(
        oci_mathlib_worker.MathlibWorkerError,
        match=r"declaration is not defined by Candidate: Nat\.add_comm",
    ):
        oci_mathlib_worker.query_declarations(
            repo_root,
            mathlib_source_lock.DEFAULT_CACHE,
            mathlib_build_resources.DEFAULT_CACHE,
            image,
            candidate,
            ("Nat.add_comm",),
        )


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires O_NOFOLLOW")
def test_source_snapshot_does_not_mix_a_to_b_to_a_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "Candidate.lean"
    candidate_source = b"theorem candidateA : True := trivial\n"
    candidate.write_bytes(candidate_source)
    replacement = tmp_path / "Candidate-B.lean"
    replacement.write_bytes(b"theorem candidateB : False := by contradiction\n")
    restored = tmp_path / "Candidate-A-restored.lean"
    restored.write_bytes(candidate_source)
    original_read = os.read
    swapped = False

    def read_after_path_swap(descriptor: int, count: int) -> bytes:
        nonlocal swapped
        if not swapped:
            os.replace(replacement, candidate)
            os.replace(restored, candidate)
            swapped = True
        return original_read(descriptor, count)

    monkeypatch.setattr(os, "read", read_after_path_swap)

    try:
        snapshot = oci_mathlib_worker._snapshot_candidate(candidate, tmp_path / "snapshot")
    except oci_mathlib_worker.MathlibWorkerError as error:
        assert "changed during snapshot" in str(error)
    else:
        assert snapshot.path.read_bytes() == candidate_source
        assert snapshot.sha256 == hashlib.sha256(candidate_source).hexdigest()
        assert snapshot.path.stat().st_mode & 0o222 == 0
    assert swapped
