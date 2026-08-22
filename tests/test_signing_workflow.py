from __future__ import annotations

import json
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.repository


ROOT = Path(__file__).resolve().parents[1]


def _root(path: Path) -> None:
    path.write_text(json.dumps({
        "root_version": 7,
        "key_slots": {"A": "A" * 40, "B": "B" * 40, "C": "C" * 40},
    }), encoding="utf-8")


def test_signing_status_identifies_first_missing_step(tmp_path: Path) -> None:
    root = tmp_path / "root.json"
    _root(root)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/signing-status.py"), str(tmp_path), str(root)],
        text=True,
        capture_output=True,
        check=True,
    )
    assert "release-manifest.json: MISSING" in result.stdout
    assert "Next action: generate and review the missing manifest(s)" in result.stdout


def test_signing_status_reports_signature_matrix_and_verification_step(tmp_path: Path) -> None:
    root = tmp_path / "root.json"
    _root(root)
    for artifact in ("release-manifest.json", "protected-manifest.json"):
        (tmp_path / artifact).write_text("{}\n", encoding="utf-8")
    for slot in "abc":
        (tmp_path / f"caretaker-key-{slot}.asc").write_text("public\n", encoding="utf-8")
        for artifact in ("root.json", "release-manifest.json", "protected-manifest.json"):
            (tmp_path / f"{artifact}.key-{slot}.asc").write_text("signature\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/signing-status.py"), str(tmp_path), str(root)],
        text=True,
        capture_output=True,
        check=True,
    )
    assert "release-manifest.json: A=yes, B=yes, C=yes" in result.stdout
    assert "run make verify-publication" in result.stdout


def test_signing_status_accepts_separate_public_key_directory(tmp_path: Path) -> None:
    root = tmp_path / "root.json"
    _root(root)
    keys = tmp_path / "release-keys"
    keys.mkdir()
    for artifact in ("release-manifest.json", "protected-manifest.json"):
        (tmp_path / artifact).write_text("{}\n", encoding="utf-8")
    for slot in "abc":
        (keys / f"caretaker-key-{slot}.asc").write_text("public\n", encoding="utf-8")
        for artifact in ("root.json", "release-manifest.json", "protected-manifest.json"):
            (tmp_path / f"{artifact}.key-{slot}.asc").write_text("signature\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/signing-status.py"),
            str(tmp_path),
            str(root),
            str(keys),
        ],
        text=True,
        capture_output=True,
        check=True,
    )

    assert "Public key A: present" in result.stdout
    assert "run make verify-publication" in result.stdout


def test_make_help_groups_signing_commands_by_role() -> None:
    result = subprocess.run(
        ["make", "help"], cwd=ROOT, text=True, capture_output=True, check=True
    )
    assert "Release coordinator:" in result.stdout
    assert "Signing station:" in result.stdout
    assert "make sign-all KEY_SLOT=a" in result.stdout


def test_verify_wheel_selects_current_package_version() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert 'wheel="dist/caretaker-$(PACKAGE_VERSION)-py3-none-any.whl"' in makefile
    assert "find dist -maxdepth 1 -type f -name '*.whl' -print -quit" not in makefile


def test_verified_lab_has_overridable_published_fingerprint_defaults() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    root = json.loads((ROOT / "root.json").read_text(encoding="utf-8"))
    default_line = next(
        line for line in makefile.splitlines() if line.startswith("TRUSTED_FINGERPRINTS ?=")
    )
    defaults = default_line.partition("?=")[2].split()
    assert defaults == list(root["key_slots"].values())
    assert "TRUSTED_FINGERPRINTS='...'" in makefile


def test_lab_targets_select_the_explicit_sandbox_profile() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert makefile.count("--profile sandbox") == 2


def test_wheel_release_requires_signed_profiles_and_installed_manifests() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    setup = (ROOT / "setup.py").read_text(encoding="utf-8")
    assert "sign-check:" in makefile
    assert "sign-all:" in makefile
    assert "wheel-manifests:" in makefile
    assert "sign-wheel-set:" not in makefile
    assert '"$$tmp/venv/bin/caretaker-integrity" verify-install' in makefile
    assert "signed wheel publication is incomplete" in setup


def test_signing_inventory_contains_all_production_profiles_but_not_sandbox() -> None:
    script = (ROOT / "scripts/sign-artifacts.py").read_text(encoding="utf-8")
    assert "profiles/caretaker-observe-only-v1.json" in script
    assert "profiles/caretaker-balanced-v1.json" in script
    assert "profiles/caretaker-high-assurance-v1.json" in script
    assert "caretaker-sandbox" not in script


def test_package_manifest_excludes_generated_interactive_lab_state() -> None:
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    assert "prune examples/.caretaker-interactive-lab" in manifest


def test_wheel_manifest_generator_uses_installed_paths(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    shutil.copytree(ROOT / "src", repository / "src")
    shutil.copytree(ROOT / "profiles", repository / "profiles")
    shutil.copy2(ROOT / "root.json", repository / "root.json")
    for profile in (
        "caretaker-observe-only-v1.json",
        "caretaker-balanced-v1.json",
        "caretaker-high-assurance-v1.json",
    ):
        for slot in "abc":
            (repository / "profiles" / f"{profile}.key-{slot}.asc").write_text(
                "test signature placeholder\n", encoding="utf-8"
            )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/generate-wheel-manifests.py"),
            "--repository",
            str(repository),
            "--package-version",
            "0.6.0",
            "--manifest-version",
            "1",
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=True,
        text=True,
        capture_output=True,
    )
    release = json.loads((repository / "wheel-release-manifest.json").read_text())
    protected = json.loads((repository / "wheel-protected-manifest.json").read_text())
    assert release["metadata"]["artifact_layout"] == "wheel"
    assert protected["metadata"]["artifact_layout"] == "wheel"
    assert all(not item["path"].startswith("src/") for item in release["artifacts"])
    assert all(not item["path"].startswith("src/") for item in protected["artifacts"])
    assert any(item["path"] == "caretaker/profiles/caretaker-balanced-v1.json" for item in release["artifacts"])


def test_framework_policy_check_requires_canonical_framework_layer(tmp_path: Path) -> None:
    root = tmp_path / "root.json"
    repository_root = json.loads((ROOT / "root.json").read_text(encoding="utf-8"))
    root.write_text(json.dumps(repository_root), encoding="utf-8")
    framework = ROOT / "examples/policy_authority/framework-policy.json"
    valid = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check-framework-policy.py"),
            str(framework),
            str(root),
            "protected",
        ],
        text=True,
        capture_output=True,
    )
    assert valid.returncode == 0, valid.stderr

    application = ROOT / "examples/policy_authority/application-policy.json"
    invalid = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check-framework-policy.py"),
            str(application),
            str(root),
            "protected",
        ],
        text=True,
        capture_output=True,
    )
    assert invalid.returncode == 2
    assert "not 'framework'" in invalid.stderr


def test_signing_bundle_contains_only_reviewable_station_material(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    root = source / "root.json"
    _root(root)
    for name in ("release-manifest.json", "protected-manifest.json"):
        (source / name).write_text('{"schema_version":1}\n', encoding="utf-8")
    keys = source / "keys"
    keys.mkdir()
    for slot in "abc":
        (keys / f"caretaker-key-{slot}.asc").write_text(
            f"PUBLIC KEY {slot}\n", encoding="utf-8"
        )
    output = tmp_path / "station"

    subprocess.run([
        sys.executable,
        str(ROOT / "scripts/create-signing-bundle.py"),
        "--output", str(output),
        "--root", str(root),
        "--release-manifest", str(source / "release-manifest.json"),
        "--protected-manifest", str(source / "protected-manifest.json"),
        "--public-key-dir", str(keys),
    ], check=True)

    signed_artifacts = {
        "root.json",
        "release-manifest.json",
        "protected-manifest.json",
        "wheel-release-manifest.json",
        "wheel-protected-manifest.json",
        "profiles/caretaker-observe-only-v1.json",
        "profiles/caretaker-balanced-v1.json",
        "profiles/caretaker-high-assurance-v1.json",
    }
    required_files = signed_artifacts | {
        "Makefile", "README.txt", "SHA256SUMS",
        "release-keys/caretaker-key-a.asc", "release-keys/caretaker-key-b.asc",
        "release-keys/caretaker-key-c.asc", "sign-artifacts.py",
        "check-signing-key.py", "signing-status.py",
    }
    allowed_signatures = {
        f"{artifact}.key-{slot}.asc"
        for artifact in signed_artifacts
        for slot in "abc"
    }
    allowed_files = required_files | allowed_signatures
    actual = {
        str(path.relative_to(output))
        for path in output.rglob("*")
        if path.is_file()
    }

    assert required_files <= actual
    assert actual <= allowed_files
    assert "make sign-all KEY_SLOT=a" in (output / "README.txt").read_text()
    assert "release-manifest.json" in (output / "SHA256SUMS").read_text()

    repeated = subprocess.run([
        sys.executable,
        str(ROOT / "scripts/create-signing-bundle.py"),
        "--output", str(output),
        "--root", str(root),
        "--release-manifest", str(source / "release-manifest.json"),
        "--protected-manifest", str(source / "protected-manifest.json"),
        "--public-key-dir", str(keys),
    ], text=True, capture_output=True)
    assert repeated.returncode == 2
    assert "output already exists" in repeated.stderr


def test_sign_artifact_inventory_detects_missing_and_stale_signatures(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location(
        "sign_artifacts", ROOT / "scripts/sign-artifacts.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    for item in module.ARTIFACTS:
        if not item.generated_later:
            artifact = tmp_path / item.path
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("artifact\n", encoding="utf-8")
    valid = tmp_path / "root.json.key-a.asc"
    valid.write_text("valid\n", encoding="utf-8")
    stale = tmp_path / "release-manifest.json.key-a.asc"
    stale.write_text("stale\n", encoding="utf-8")
    module.signature_valid = lambda home, artifact, signature, fingerprint: signature == valid

    result = module.states(
        tmp_path, {"a": "A" * 40, "b": "B" * 40, "c": "C" * 40}, "unused"
    )

    assert result["root.json"]["a"] == "VALID"
    assert result["release-manifest.json"]["a"] == "STALE/INVALID"
    assert result["protected-manifest.json"]["a"] == "MISSING"
    assert result["wheel-release-manifest.json"]["a"] == "PENDING"
