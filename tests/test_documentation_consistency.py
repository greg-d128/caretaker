from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _documentation_files() -> tuple[Path, ...]:
    files = list(ROOT.glob("*.md"))
    files.extend(ROOT.glob("*.txt"))
    files.extend((ROOT / "docs").glob("*.md"))
    files.extend((ROOT / "examples").glob("*.md"))
    files.extend((ROOT / "examples").glob("*/README.md"))
    return tuple(sorted(set(files)))


def test_relative_documentation_links_resolve() -> None:
    missing: list[str] = []
    for document in _documentation_files():
        text = document.read_text(encoding="utf-8")
        for reference in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            target = reference.split("#", 1)[0]
            if not target or "://" in target or target.startswith("mailto:"):
                continue
            if not (document.parent / target).resolve().exists():
                missing.append(f"{document.relative_to(ROOT)} -> {reference}")
    assert missing == []


def test_current_operator_documentation_uses_current_labels() -> None:
    current = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "README.md",
            ROOT / "docs/ADMIN_CONTROL.md",
            ROOT / "docs/POLICY_AUTHORITY.md",
            ROOT / "examples/interactive_caretaker_lab.md",
        )
    )
    stale_labels = (
        "Execute function",
        "Execute 1000 times",
        "Apply selected behavior",
        "Reset all substitutions",
        "Close function epoch",
        "Compare epochs",
        "Investigate correlated",
        "Guard > LLM assist",
        "Refresh repair",
        "Delete selected",
        "Confirm archive/delete",
    )
    assert [label for label in stale_labels if label in current] == []


def test_signing_guide_uses_role_oriented_workflow() -> None:
    guide = (ROOT / "docs/SIGNING_STATION.md").read_text(encoding="utf-8")
    for expected in (
        "make generate-manifests",
        "make signing-bundle",
        "make sign-release-set KEY_SLOT=a",
        "make verify-publication",
    ):
        assert expected in guide
    assert "make sign-all" not in guide
    assert "make verify-all" not in guide
