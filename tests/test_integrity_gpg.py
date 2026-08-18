from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from caretaker.integrity import (
    GPGVerifier,
    IntegrityClass,
    IntegrityStateStore,
    IntegrityVerifier,
    ManifestType,
    RolePolicy,
    RootMetadata,
    build_manifest,
    verify_release_publication,
    write_manifest,
    write_root,
)

from .integrity_helpers import export_public_key, generate_test_key, make_gpg_home, sign_file


def _keys(tmp_path: Path) -> tuple[Path, dict[str, str], dict[str, Path]]:
    home = make_gpg_home(tmp_path / "signer")
    fingerprints = {
        "a": generate_test_key(home, "Caretaker A <a@example.invalid>", signing_subkey=True),
        "b": generate_test_key(home, "Caretaker B <b@example.invalid>"),
        "c": generate_test_key(home, "Caretaker C <c@example.invalid>"),
        "d": generate_test_key(home, "Caretaker D <d@example.invalid>"),
    }
    public: dict[str, Path] = {}
    for name, fingerprint in fingerprints.items():
        destination = tmp_path / f"key-{name}.asc"
        export_public_key(home, fingerprint, destination)
        public[name] = destination
    return home, fingerprints, public


def _root(path: Path, version: int, fingerprints: tuple[str, str, str]) -> RootMetadata:
    root = RootMetadata(
        schema_version=1,
        project="caretaker",
        root_version=version,
        roles={
            "release": RolePolicy("release", fingerprints, 1),
            "protected": RolePolicy("protected", fingerprints, 2),
            "root": RolePolicy("root", fingerprints, 2),
        },
        protected_paths=("protected.py",),
        sealed_paths=(),
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    write_root(path, root)
    return root


def test_release_and_protected_thresholds(tmp_path: Path) -> None:
    home, fingerprints, public = _keys(tmp_path)
    root_path = tmp_path / "root.json"
    _root(root_path, 1, (fingerprints["a"], fingerprints["b"], fingerprints["c"]))

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ordinary.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tree / "protected.py").write_text("VALUE = 2\n", encoding="utf-8")

    release = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("ordinary.py",),
    )
    release_path = tmp_path / "release.json"
    write_manifest(release_path, release)
    release_sig = tmp_path / "release.a.asc"
    sign_file(home, fingerprints["a"], release_path, release_sig)

    verifier = IntegrityVerifier(gpg=GPGVerifier())
    result = verifier.verify_manifest(
        root_path=root_path,
        manifest_path=release_path,
        signature_paths=[release_sig],
        public_key_paths=list(public.values()),
        artifact_root=tree,
        root_trusted=True,
    )
    assert result.trusted
    # Key A signs through a subkey, but threshold identity is its primary certificate.
    assert result.signature_verification.valid_primary_fingerprints == (fingerprints["a"],)

    protected = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.PROTECTED,
        manifest_version=1,
        root_version=1,
        include=("protected.py",),
        path_classes={"protected.py": IntegrityClass.PROTECTED},
    )
    protected_path = tmp_path / "protected.json"
    write_manifest(protected_path, protected)
    sig_a = tmp_path / "protected.a.asc"
    sig_b = tmp_path / "protected.b.asc"
    sign_file(home, fingerprints["a"], protected_path, sig_a)
    sign_file(home, fingerprints["b"], protected_path, sig_b)

    result = verifier.verify_manifest(
        root_path=root_path,
        manifest_path=protected_path,
        signature_paths=[sig_a],
        public_key_paths=list(public.values()),
        artifact_root=tree,
        root_trusted=True,
    )
    assert not result.trusted

    result = verifier.verify_manifest(
        root_path=root_path,
        manifest_path=protected_path,
        signature_paths=[sig_a, sig_b],
        public_key_paths=list(public.values()),
        artifact_root=tree,
        root_trusted=True,
    )
    assert result.trusted
    assert set(result.signature_verification.valid_primary_fingerprints) == {
        fingerprints["a"], fingerprints["b"]
    }

    duplicate = verifier.verify_manifest(
        root_path=root_path,
        manifest_path=protected_path,
        signature_paths=[sig_a, sig_a],
        public_key_paths=list(public.values()),
        artifact_root=tree,
        root_trusted=True,
    )
    assert not duplicate.trusted
    assert any("Duplicate signer" in item for item in duplicate.signature_verification.errors)


def test_runtime_publication_status_verifies_root_and_both_manifests(tmp_path: Path) -> None:
    home, fingerprints, public = _keys(tmp_path)
    selected = (fingerprints["a"], fingerprints["b"], fingerprints["c"])
    root = _root(tmp_path / "root.json", 1, selected)
    write_root(
        tmp_path / "root.json",
        replace(
            root,
            key_slots={"A": selected[0], "B": selected[1], "C": selected[2]},
        ),
    )
    keys = tmp_path / "release-keys"
    keys.mkdir()
    for slot in "abc":
        (keys / f"caretaker-key-{slot}.asc").write_bytes(public[slot].read_bytes())
        sign_file(home, fingerprints[slot], tmp_path / "root.json", tmp_path / f"root.json.key-{slot}.asc")
    (tmp_path / "ordinary.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "protected.py").write_text("VALUE = 2\n", encoding="utf-8")
    for name, manifest_type, include, classes in (
        ("release-manifest.json", ManifestType.RELEASE, ("ordinary.py",), {}),
        ("protected-manifest.json", ManifestType.PROTECTED, ("protected.py",), {"protected.py": IntegrityClass.PROTECTED}),
    ):
        write_manifest(
            tmp_path / name,
            build_manifest(
                root_dir=tmp_path,
                project="caretaker",
                package_version="0.6.0",
                manifest_type=manifest_type,
                manifest_version=1,
                root_version=1,
                include=include,
                path_classes=classes,
            ),
        )
        for slot in "abc":
            sign_file(home, fingerprints[slot], tmp_path / name, tmp_path / f"{name}.key-{slot}.asc")

    status = verify_release_publication(tmp_path, trusted_primary_fingerprints=selected)

    assert status["status"] == "TRUSTED", status
    assert status["root_anchored"] is True
    assert status["manifests"]["release-manifest.json"]["valid_signers"] == 3
    assert status["manifests"]["protected-manifest.json"]["invalid_artifacts"] == 0


def test_root_rotation_requires_old_and_new_thresholds(tmp_path: Path) -> None:
    home, fingerprints, public = _keys(tmp_path)
    old_path = tmp_path / "root-1.json"
    new_path = tmp_path / "root-2.json"
    _root(old_path, 1, (fingerprints["a"], fingerprints["b"], fingerprints["c"]))
    _root(new_path, 2, (fingerprints["a"], fingerprints["b"], fingerprints["d"]))

    sig_a = tmp_path / "root-2.a.asc"
    sig_b = tmp_path / "root-2.b.asc"
    sign_file(home, fingerprints["a"], new_path, sig_a)
    sign_file(home, fingerprints["b"], new_path, sig_b)

    old_result, new_result = IntegrityVerifier().verify_root_transition(
        old_root_path=old_path,
        new_root_path=new_path,
        new_root_signature_paths=[sig_a, sig_b],
        public_key_paths=list(public.values()),
    )
    assert old_result.satisfied
    assert new_result.satisfied


def test_anti_rollback_state(tmp_path: Path) -> None:
    store = IntegrityStateStore(tmp_path / "trusted-state.json")
    state = store.load("caretaker")
    state = store.accept(
        state=state,
        root_version=3,
        manifest_type=ManifestType.RELEASE,
        manifest_version=12,
        manifest_hash="a" * 64,
    )
    assert state.highest_root_version == 3
    assert state.highest_release_manifest_version == 12

    import pytest
    from caretaker.integrity import IntegrityRollbackError

    with pytest.raises(IntegrityRollbackError):
        store.assert_not_rollback(
            state=state,
            root_version=2,
            manifest_type=ManifestType.RELEASE,
            manifest_version=12,
        )


def test_verifier_refuses_secret_key_input(tmp_path: Path) -> None:
    from .integrity_helpers import export_secret_key

    home = make_gpg_home(tmp_path / "signer-secret")
    fingerprint = generate_test_key(home, "Caretaker Secret Input <secret@example.invalid>")
    secret_path = tmp_path / "must-not-import.asc"
    export_secret_key(home, fingerprint, secret_path)
    data = tmp_path / "data.txt"
    signature = tmp_path / "data.asc"
    data.write_text("signed data\n", encoding="utf-8")
    sign_file(home, fingerprint, data, signature)

    result = GPGVerifier().verify_threshold(
        signed_path=data,
        signature_paths=[signature],
        public_key_paths=[secret_path],
        role=RolePolicy("release", (fingerprint,), 1),
    )
    assert not result.satisfied
    assert any("Secret-key material is not accepted" in error for error in result.errors)


def test_root_protected_paths_cannot_be_downgraded_or_omitted(tmp_path: Path) -> None:
    home, fingerprints, public = _keys(tmp_path)
    root_path = tmp_path / "root.json"
    _root(root_path, 1, (fingerprints["a"], fingerprints["b"], fingerprints["c"]))
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "protected.py").write_text("VALUE = 1\n", encoding="utf-8")

    downgraded = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("protected.py",),
    )
    downgraded_path = tmp_path / "downgraded.json"
    write_manifest(downgraded_path, downgraded)
    signature = tmp_path / "downgraded.a.asc"
    sign_file(home, fingerprints["a"], downgraded_path, signature)

    result = IntegrityVerifier().verify_manifest(
        root_path=root_path,
        manifest_path=downgraded_path,
        signature_paths=[signature],
        public_key_paths=list(public.values()),
        artifact_root=tree,
        root_trusted=True,
    )
    assert not result.trusted
    assert any("cannot authorize protected" in error for error in result.errors)


def test_manifest_is_not_trusted_without_root_anchor(tmp_path: Path) -> None:
    home, fingerprints, public = _keys(tmp_path)
    root_path = tmp_path / "root.json"
    _root(root_path, 1, (fingerprints["a"], fingerprints["b"], fingerprints["c"]))
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ordinary.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = build_manifest(
        root_dir=tree,
        project="caretaker",
        package_version="0.3.0a2",
        manifest_type=ManifestType.RELEASE,
        manifest_version=1,
        root_version=1,
        include=("ordinary.py",),
    )
    manifest_path = tmp_path / "release.json"
    write_manifest(manifest_path, manifest)
    signature = tmp_path / "release.a.asc"
    sign_file(home, fingerprints["a"], manifest_path, signature)

    result = IntegrityVerifier().verify_manifest(
        root_path=root_path,
        manifest_path=manifest_path,
        signature_paths=[signature],
        public_key_paths=list(public.values()),
        artifact_root=tree,
    )
    assert result.signature_verification.satisfied
    assert not result.root_anchored
    assert not result.trusted
    assert any("not externally anchored" in error for error in result.errors)


def test_initial_root_requires_exact_published_identity_set(tmp_path: Path) -> None:
    import pytest
    from caretaker.integrity import IntegrityVerificationError

    home, fingerprints, public = _keys(tmp_path)
    root_path = tmp_path / "root.json"
    _root(root_path, 1, (fingerprints["a"], fingerprints["b"], fingerprints["c"]))
    sig_a = tmp_path / "root.a.asc"
    sig_b = tmp_path / "root.b.asc"
    sign_file(home, fingerprints["a"], root_path, sig_a)
    sign_file(home, fingerprints["b"], root_path, sig_b)

    with pytest.raises(IntegrityVerificationError):
        IntegrityVerifier().verify_initial_root(
            root_path=root_path,
            signature_paths=[sig_a, sig_b],
            public_key_paths=list(public.values()),
            trusted_primary_fingerprints=[fingerprints["a"], fingerprints["b"], fingerprints["d"]],
        )
