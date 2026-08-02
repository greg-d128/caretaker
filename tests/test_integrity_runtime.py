from __future__ import annotations

from pathlib import Path

from caretaker.integrity import (
    IntegrityClass,
    ManifestType,
    RuntimeIntegrityMonitor,
    build_manifest,
    render_gpg_verification_commands,
)


def sample(value: int) -> int:
    return value + 1


def test_runtime_function_fingerprint_detects_replacement(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = build_manifest(
        root_dir=root,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("*.py",),
    )
    monitor = RuntimeIntegrityMonitor(manifest, root)
    monitor.accept_function(sample)
    assert monitor.verify_function(sample)

    original = sample.__code__
    try:
        sample.__code__ = (lambda value: value + 2).__code__
        assert not monitor.verify_function(sample)
    finally:
        sample.__code__ = original


def test_instructions_include_independent_gpg_and_hash_commands(tmp_path: Path) -> None:
    from caretaker.integrity import RolePolicy, RootMetadata, write_root

    fingerprints = (
        "A" * 40,
        "B" * 40,
        "C" * 40,
    )
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
        ),
    )
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("*.py",),
    )
    from caretaker.integrity import write_manifest
    manifest_path = tmp_path / "release.json"
    write_manifest(manifest_path, manifest)

    commands = render_gpg_verification_commands(
        root_path=root_path,
        root_signature_paths=[tmp_path / "root.a.asc", tmp_path / "root.b.asc"],
        trusted_primary_fingerprints=fingerprints,
        manifest_path=manifest_path,
        signature_paths=[tmp_path / "release.a.asc"],
        public_key_paths=[tmp_path / "a.asc", tmp_path / "b.asc", tmp_path / "c.asc"],
        artifact_root=tree,
    )
    assert "gpg --homedir" in commands
    assert "--no-auto-key-retrieve" in commands
    assert "--status-fd=1 --verify" in commands
    assert "sha256sum --check -" in commands
    assert "count=$((count + 1))" in commands
    assert "Unauthorized signer" in commands

    script = tmp_path / "verify.sh"
    script.write_text(commands, encoding="utf-8")
    import subprocess
    completed = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr


def test_rendered_instructions_verify_real_gpg_signatures(tmp_path: Path) -> None:
    import subprocess

    from caretaker.integrity import RolePolicy, RootMetadata, write_manifest, write_root
    from tests.integrity_helpers import (
        export_public_key,
        generate_test_key,
        make_gpg_home,
        sign_file,
    )

    signer_home = make_gpg_home(tmp_path / "signer")
    fingerprints = tuple(
        generate_test_key(
            signer_home,
            f"Caretaker Instruction {name} <{name.lower()}@example.invalid>",
            signing_subkey=(name == "A"),
        )
        for name in ("A", "B", "C")
    )
    public_keys = []
    for index, fingerprint in enumerate(fingerprints):
        path = tmp_path / f"key-{index}.asc"
        export_public_key(signer_home, fingerprint, path)
        public_keys.append(path)

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
        ),
    )
    root_a = tmp_path / "root.a.asc"
    root_b = tmp_path / "root.b.asc"
    sign_file(signer_home, fingerprints[0], root_path, root_a)
    sign_file(signer_home, fingerprints[1], root_path, root_b)

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("*.py",),
    )
    manifest_path = tmp_path / "release.json"
    write_manifest(manifest_path, manifest)
    release_signatures = []
    for index, fingerprint in enumerate(fingerprints):
        signature = tmp_path / f"release.{index}.asc"
        sign_file(signer_home, fingerprint, manifest_path, signature)
        release_signatures.append(signature)

    script = tmp_path / "verify.sh"
    script.write_text(
        render_gpg_verification_commands(
            root_path=root_path,
            root_signature_paths=[root_a, root_b],
            trusted_primary_fingerprints=fingerprints,
            manifest_path=manifest_path,
            signature_paths=release_signatures,
            public_key_paths=public_keys,
            artifact_root=tree,
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        ["sh", str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Caretaker signature thresholds and artifact integrity verified." in completed.stdout
