from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


workflow = _load("release_candidate_workflow", "release-candidate.py")
parity = _load("package_parity", "verify-package-parity.py")
signing = _load("signing_artifacts", "sign-artifacts.py")


def _git_repo(tmp_path: Path, *, version: str = "1.0.0a0") -> tuple[Path, str]:
    repository = tmp_path / "repository"
    (repository / "src/caretaker").mkdir(parents=True)
    (repository / "pyproject.toml").write_text(f'version = "{version}"\n', encoding="utf-8")
    (repository / "src/caretaker/__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-qm", "candidate"],
        cwd=repository,
        check=True,
    )
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True, text=True, capture_output=True
    ).stdout.strip()
    return repository, revision


def _archive_pair(tmp_path: Path, *, source_text: str = "value = 1\n") -> tuple[Path, Path, Path]:
    source_root = tmp_path / "source"
    package = source_root / "src/caretaker"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(source_text, encoding="utf-8")
    wheel = tmp_path / "caretaker-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("caretaker/__init__.py", source_text)
        archive.writestr("caretaker-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nVersion: 1.0.0\n")
    sdist = tmp_path / "caretaker-1.0.0.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in {
            "caretaker-1.0.0/src/caretaker/__init__.py": source_text.encode(),
            "caretaker-1.0.0/PKG-INFO": b"Metadata-Version: 2.1\nVersion: 1.0.0\n",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return source_root, sdist, wheel


def test_candidate_clean_gate_distinguishes_clean_and_dirty_inputs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repository, _ = _git_repo(tmp_path)
    monkeypatch.setattr(workflow, "git_status", lambda _: "")
    workflow.require_clean(repository)
    monkeypatch.setattr(workflow, "git_status", lambda _: " M src/caretaker/__init__.py")
    with pytest.raises(workflow.WorkflowError, match="dirty"):
        workflow.require_clean(repository)


def test_candidate_output_rejects_stale_distribution_artifacts(tmp_path: Path) -> None:
    output = tmp_path / "dist"
    output.mkdir()
    (output / "caretaker-1.0.0-py3-none-any.whl").write_bytes(b"wheel")
    (output / "caretaker-1.0.0.tar.gz").write_bytes(b"sdist")
    (output / "caretaker-0.9.0-py3-none-any.whl").write_bytes(b"stale")
    with pytest.raises(workflow.WorkflowError, match="stale"):
        workflow._package_artifacts(output, "1.0.0")


def test_wheel_sdist_and_source_parity_rejects_source_mismatch(tmp_path: Path) -> None:
    source_root, sdist, wheel = _archive_pair(tmp_path)
    result = parity.verify_payloads(sdist_path=sdist, wheel_path=wheel, source_root=source_root, version="1.0.0")
    assert result["version"] == "1.0.0"
    (source_root / "src/caretaker/__init__.py").write_text("value = 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source/package payload mismatch"):
        parity.verify_payloads(sdist_path=sdist, wheel_path=wheel, source_root=source_root, version="1.0.0")


def test_version_only_release_transformation_is_allowed_but_functional_change_is_not(tmp_path: Path) -> None:
    repository, revision = _git_repo(tmp_path)
    candidate_inventory = workflow.source_inventory(repository)
    for path in (repository / "pyproject.toml", repository / "src/caretaker/__init__.py"):
        path.write_text(path.read_text(encoding="utf-8").replace("1.0.0a0", "1.0.0"), encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-qm", "release-version"],
        cwd=repository,
        check=True,
    )
    assert workflow.compare_release_inputs(repository, candidate_inventory, revision, "1.0.0a0", "1.0.0") == []
    (repository / "src/caretaker/__init__.py").write_text(
        '__version__ = "1.0.0"\nfunctional_change = True\n', encoding="utf-8"
    )
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-qm", "functional"],
        cwd=repository,
        check=True,
    )
    assert "src/caretaker/__init__.py" in workflow.compare_release_inputs(
        repository, candidate_inventory, revision, "1.0.0a0", "1.0.0"
    )


def test_signing_input_ledger_rejects_changed_manifest_and_artifact(tmp_path: Path) -> None:
    (tmp_path / "finalization.json").write_text('{"status":"FINALIZED_UNSIGNED"}\n', encoding="utf-8")
    (tmp_path / "release-manifest.json").write_text('{"package_version":"1.0.0"}\n', encoding="utf-8")
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/caretaker-1.0.0-py3-none-any.whl").write_bytes(b"wheel")
    ledger = {
        "schema_version": 1,
        "record_type": "caretaker-signing-inputs",
        "candidate_id": "cand-test",
        "finalization_sha256": workflow.sha256_file(tmp_path / "finalization.json"),
        "files": {
            "release-manifest.json": workflow.sha256_file(tmp_path / "release-manifest.json"),
            "artifacts/caretaker-1.0.0-py3-none-any.whl": workflow.sha256_file(
                tmp_path / "artifacts/caretaker-1.0.0-py3-none-any.whl"
            ),
        },
    }
    (tmp_path / "signing-inputs.json").write_text(json.dumps(ledger), encoding="utf-8")
    signing.verify_signing_inputs(tmp_path)
    (tmp_path / "release-manifest.json").write_text('{"package_version":"1.0.1"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        signing.verify_signing_inputs(tmp_path)


def test_parity_rejects_mismatched_package_versions(tmp_path: Path) -> None:
    source_root, sdist, wheel = _archive_pair(tmp_path)
    with pytest.raises(ValueError, match="version mismatch"):
        parity.verify_payloads(sdist_path=sdist, wheel_path=wheel, source_root=source_root, version="1.0.1")
