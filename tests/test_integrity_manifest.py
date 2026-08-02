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
