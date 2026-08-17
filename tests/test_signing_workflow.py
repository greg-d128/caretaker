from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


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


def test_make_help_groups_signing_commands_by_role() -> None:
    result = subprocess.run(
        ["make", "help"], cwd=ROOT, text=True, capture_output=True, check=True
    )
    assert "Release coordinator:" in result.stdout
    assert "Signing station:" in result.stdout
    assert "make sign-release-set KEY_SLOT=a" in result.stdout
