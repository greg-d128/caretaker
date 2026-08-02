from __future__ import annotations

from pathlib import Path

from caretaker.integrity import ManifestType, RolePolicy, RootMetadata, load_manifest, write_root
from caretaker.integrity.cli import main


def test_generate_manifest_uses_root_policy_to_separate_protected_paths(tmp_path: Path) -> None:
    fingerprints = ("A" * 40, "B" * 40, "C" * 40)
    root_path = tmp_path / "root.json"
    write_root(
        root_path,
        RootMetadata(
            schema_version=1,
            project="caretaker",
            root_version=1,
            roles={
                "release": RolePolicy("release", fingerprints, 1),
                "protected": RolePolicy("protected", fingerprints, 2),
                "root": RolePolicy("root", fingerprints, 2),
            },
            protected_paths=("protected/**",),
            sealed_paths=("protected/sealed.py",),
        ),
    )
    tree = tmp_path / "tree"
    (tree / "ordinary").mkdir(parents=True)
    (tree / "protected").mkdir(parents=True)
    (tree / "ordinary" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (tree / "protected" / "b.py").write_text("B = 1\n", encoding="utf-8")
    (tree / "protected" / "sealed.py").write_text("C = 1\n", encoding="utf-8")

    release_path = tmp_path / "release.json"
    assert main([
        "generate-manifest",
        "--root-dir", str(tree),
        "--output", str(release_path),
        "--package-version", "0.3.0a2",
        "--manifest-type", "release",
        "--manifest-version", "1",
        "--root-version", "1",
        "--root-policy", str(root_path),
        "--include", "**/*.py",
    ]) == 0
    release = load_manifest(release_path)
    assert release.manifest_type is ManifestType.RELEASE
    assert [item.path for item in release.artifacts] == ["ordinary/a.py"]

    protected_path = tmp_path / "protected.json"
    assert main([
        "generate-manifest",
        "--root-dir", str(tree),
        "--output", str(protected_path),
        "--package-version", "0.3.0a2",
        "--manifest-type", "protected",
        "--manifest-version", "1",
        "--root-version", "1",
        "--root-policy", str(root_path),
    ]) == 0
    protected = load_manifest(protected_path)
    assert {item.path for item in protected.artifacts} == {"protected/b.py", "protected/sealed.py"}
    classes = {item.path: item.integrity_class.value for item in protected.artifacts}
    assert classes["protected/b.py"] == "protected"
    assert classes["protected/sealed.py"] == "sealed"
