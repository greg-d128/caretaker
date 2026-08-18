from __future__ import annotations

import json
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
    assert "make sign-release-set KEY_SLOT=a" in result.stdout


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

    assert {path.name for path in output.iterdir()} == {
        "Makefile", "README.txt", "SHA256SUMS", "root.json",
        "release-manifest.json", "protected-manifest.json",
        "caretaker-key-a.asc", "caretaker-key-b.asc", "caretaker-key-c.asc",
        "sign-code.sh", "check-signing-key.py", "signing-status.py",
    }
    assert "make sign-release-set KEY_SLOT=a" in (output / "README.txt").read_text()
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
