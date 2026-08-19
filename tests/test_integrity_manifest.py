from __future__ import annotations

from pathlib import Path

import pytest

from caretaker.integrity import (
    IntegrityClass,
    ManifestType,
    build_manifest,
    load_manifest,
    sha256sum_lines,
    verify_artifacts,
    write_manifest,
)
from caretaker.integrity.canonical import assert_canonical_json, canonical_json_bytes
from caretaker.integrity.manifest import validate_manifest_scope
from caretaker.integrity.models import RolePolicy, RootMetadata


def test_manifest_is_canonical_and_verifies_artifacts(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "b.py").write_text("VALUE = 2\n", encoding="utf-8")

    manifest = build_manifest(
        root_dir=root,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("*.py",),
    )
    destination = tmp_path / "release-manifest.json"
    write_manifest(destination, manifest)

    assert assert_canonical_json(destination)["project"] == "caretaker"
    loaded = load_manifest(destination)
    assert [item.path for item in loaded.artifacts] == ["a.py", "b.py"]
    assert all(item.valid for item in verify_artifacts(root, loaded))
    assert "a.py" in sha256sum_lines(loaded)

    (root / "a.py").write_text("VALUE = 99\n", encoding="utf-8")
    results = verify_artifacts(root, loaded)
    assert not results[0].valid
    assert results[1].valid


def test_canonical_metadata_rejects_float() -> None:
    with pytest.raises(TypeError):
        canonical_json_bytes({"score": 1.5})


def test_manifest_excludes_transient_python_bytecode(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    cache = root / "protected" / "__pycache__"
    cache.mkdir(parents=True)
    (root / "protected" / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (cache / "module.cpython-312.pyc").write_bytes(b"generated")

    manifest = build_manifest(
        root_dir=root,
        project="caretaker",
        package_version="0.6.0",
        manifest_type=ManifestType.PROTECTED,
        manifest_version=1,
        root_version=1,
        include=("protected/**",),
        path_classes={"protected/**": IntegrityClass.PROTECTED},
    )
    fingerprints = ("A" * 40, "B" * 40, "C" * 40)
    policy = RootMetadata(
        schema_version=1,
        project="caretaker",
        root_version=1,
        roles={
            "release": RolePolicy("release", fingerprints, 1),
            "protected": RolePolicy("protected", fingerprints, 2),
            "root": RolePolicy("root", fingerprints, 2),
        },
        protected_paths=("protected/**",),
    )

    assert [item.path for item in manifest.artifacts] == ["protected/module.py"]
    assert "**/__pycache__/**" in manifest.excluded_patterns
    assert validate_manifest_scope(policy, manifest, root) == ()


def test_wheel_layout_preserves_source_root_integrity_classes(tmp_path: Path) -> None:
    tree = tmp_path / "site-packages"
    protected = tree / "caretaker" / "integrity"
    protected.mkdir(parents=True)
    (protected / "verifier.py").write_text("VALUE = 1\n", encoding="utf-8")
    fingerprints = ("A" * 40, "B" * 40, "C" * 40)
    root = RootMetadata(
        schema_version=1,
        project="caretaker",
        root_version=1,
        roles={
            "release": RolePolicy("release", fingerprints, 1),
            "protected": RolePolicy("protected", fingerprints, 2),
            "root": RolePolicy("root", fingerprints, 2),
        },
        protected_paths=("src/caretaker/integrity/**",),
    )
    manifest = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.6.0",
        manifest_type=ManifestType.PROTECTED,
        manifest_version=1,
        root_version=1,
        include=("caretaker/integrity/**",),
        path_classes={"caretaker/integrity/**": IntegrityClass.PROTECTED},
        metadata={"artifact_layout": "wheel"},
    )

    assert validate_manifest_scope(root, manifest, tree) == ()
