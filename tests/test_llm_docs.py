from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import caretaker
import pytest

from caretaker.llm_docs import CONTRACT_LINE, SCHEMA_VERSION, entry_path, load_index, read_entry
from caretaker.llm_docs_cli import main


ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "src" / "caretaker" / "llm_docs"
STATUSES = {
    "implemented",
    "experimental",
    "operator-only",
    "environment-dependent",
    "not-guaranteed",
    "future",
}
REQUIRED_CARD_SECTIONS = (
    "Task",
    "Audience",
    "Status",
    "Supported package versions",
    "Use when",
    "Do not use when",
    "Prerequisites",
    "Minimal command or code",
    "Required configuration",
    "Expected result",
    "Verification",
    "Common failures",
    "Security and scope limitations",
    "Related tasks",
    "Canonical documentation",
)


def test_index_schema_paths_version_contract_statuses_and_bounded_estimates() -> None:
    index = load_index()
    assert index["schema_version"] == SCHEMA_VERSION
    assert index["package_version"] == caretaker.__version__
    assert index["contract_line"] == CONTRACT_LINE == "caretaker-0.6.5"
    entries = index["entries"]
    assert len({entry["id"] for entry in entries}) == len(entries)
    assert len({entry["path"] for entry in entries}) == len(entries)
    for entry in entries:
        path = Path(entry["path"])
        assert not path.is_absolute()
        assert ".." not in path.parts
        assert entry["status"] in STATUSES
        assert 100 <= entry["token_estimate"] <= 1200
        assert entry["path"] == path.as_posix()
        assert (CORPUS / path).is_file()
        assert not (CORPUS / path).is_symlink()


def test_every_index_entry_is_readable_as_a_package_resource() -> None:
    for entry in load_index()["entries"]:
        selected, body = read_entry(entry["id"])
        assert selected == entry
        assert body
        with entry_path(entry["id"]) as path:
            assert path.is_file()


def test_task_cards_have_required_sections_and_no_internal_api_claims() -> None:
    for entry in load_index()["entries"]:
        if entry["kind"] != "task":
            continue
        body = (CORPUS / entry["path"]).read_text(encoding="utf-8")
        assert all(f"## {section}" in body for section in REQUIRED_CARD_SECTIONS)
        assert "src/caretaker" not in body
        assert "caretaker._" not in body
        assert "internal module" not in body.lower()
        assert "caretaker.__" not in body


def test_documented_public_api_names_match_package_inventory() -> None:
    reference = json.loads((CORPUS / "reference/public-api.json").read_text())
    exported = set(caretaker.__all__)
    for group in ("stable_integration", "advanced_application_capabilities", "compatibility_surface"):
        assert set(reference[group]) <= exported


def test_docs_cli_list_show_index_path_and_rejects_bad_ids(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["list"]) == 0
    listed = capsys.readouterr().out
    assert "0.6.5" in listed
    assert "caretaker-0.6.5" in listed
    assert "tasks.logging-quickstart" in listed

    assert main(["show", "tasks.logging-quickstart"]) == 0
    shown = capsys.readouterr().out
    assert "# Start with application logging" in shown
    assert "Package: 0.6.5" in shown

    assert main(["index", "--json"]) == 0
    indexed = json.loads(capsys.readouterr().out)
    assert indexed["contract_line"] == CONTRACT_LINE

    assert main(["path", "tasks.logging-quickstart"]) == 0
    path_output = capsys.readouterr().out.strip()
    assert path_output.endswith("tasks/logging-quickstart.md")

    assert main(["show", "tasks."]) == 2
    assert main(["path", "../index.json"]) == 2
    errors = capsys.readouterr().err
    assert "ambiguous" in errors
    assert "safe relative" in errors


def test_representative_examples_use_supported_commands_and_public_imports() -> None:
    cards = "\n".join(
        (CORPUS / entry["path"]).read_text(encoding="utf-8")
        for entry in load_index()["entries"]
        if entry["kind"] == "task"
    )
    assert "caretaker-docs list" in cards
    assert "caretaker-run" in cards
    assert "caretaker-integrity" in cards
    assert "from caretaker import" in cards
    assert "from caretaker.logging import" in cards


@pytest.mark.repository
def test_wheel_installs_llm_corpus_and_cli_without_source_path(tmp_path: Path) -> None:
    output = tmp_path / "wheel"
    output.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["CARETAKER_RELEASE_SIGNING"] = "disabled"
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(output)],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = next(output.glob("caretaker-*.whl"))
    clean_env = tmp_path / "clean-env"
    subprocess.run([sys.executable, "-m", "venv", str(clean_env)], check=True)
    python = clean_env / "bin" / "python"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    clean_runtime = environment.copy()
    clean_runtime.pop("PYTHONPATH", None)
    listed = subprocess.run(
        [str(clean_env / "bin" / "caretaker-docs"), "list"],
        cwd=tmp_path,
        env=clean_runtime,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "tasks.logging-quickstart" in listed.stdout
    indexed = subprocess.run(
        [str(clean_env / "bin" / "caretaker-docs"), "index", "--json"],
        cwd=tmp_path,
        env=clean_runtime,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(indexed.stdout)["package_version"] == caretaker.__version__
