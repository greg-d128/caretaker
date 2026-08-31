from __future__ import annotations

import json
from pathlib import Path

import pytest

from caretaker.failure_corpus import (
    FailureCorpus,
    FailureCorpusError,
    MAX_CORPUS_BYTES,
)


ROOT = Path(__file__).resolve().parents[1]


def test_repository_failure_corpus_is_bounded_metadata_only() -> None:
    corpus = FailureCorpus.load(ROOT / "examples" / "failure_corpus" / "manifest.json")

    assert corpus.corpus_id == "caretaker-default-failure-corpus-v1"
    assert len(corpus.scenarios) == 10
    assert {item.category for item in corpus.scenarios} == {
        "exception", "timeout", "invalid-output", "dependency", "configuration",
        "resource", "worker", "repair", "malicious-evidence", "llm",
    }
    assert all(item.summary()["executable"] is False for item in corpus.scenarios)
    assert all("stimulus" in item.summary() for item in corpus.scenarios)


def test_failure_corpus_is_read_only_and_bounded(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "description": "test",
        "scenarios": [{
            "scenario_id": "exception.test",
            "category": "exception",
            "description": "test",
            "stimulus": "test input",
            "expected": {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
                "minimum_isolation": "PROCESS",
            },
            "tags": [],
        }],
    }))
    corpus = FailureCorpus.load(path)

    assert corpus.get("exception.test").minimum_isolation == "PROCESS"
    assert corpus.list_summaries(limit=1)[0]["executable"] is False
    with pytest.raises(KeyError):
        corpus.get("exception.missing")
    with pytest.raises(FailureCorpusError, match="byte limit"):
        FailureCorpus.load(path, maximum_bytes=1)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("scenario_id", "not valid", "identifier"),
        ("category", "unknown", "unknown category"),
        ("expected_signal", "NOT_A_SIGNAL", "unknown expected signal"),
    ),
)
def test_failure_corpus_rejects_unsafe_or_unknown_values(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    manifest = {
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "description": "test",
        "scenarios": [{
            "scenario_id": "exception.test",
            "category": "exception",
            "description": "test",
            "stimulus": "test input",
            "expected": {
                "signal": "EXCEPTION",
                "caretaker_action": "CAPTURE_INCIDENT",
                "authority_effect": "NO_AUTHORITY_CHANGE",
                "minimum_isolation": "PROCESS",
            },
            "tags": [],
        }],
    }
    if field == "expected_signal":
        manifest["scenarios"][0]["expected"]["signal"] = value
    else:
        manifest["scenarios"][0][field] = value
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))

    with pytest.raises(FailureCorpusError, match=message):
        FailureCorpus.load(path)


def test_failure_corpus_rejects_executable_manifest_fields(tmp_path: Path) -> None:
    manifest = {
        "schema_version": 1,
        "corpus_id": "test-corpus",
        "description": "test",
        "scenarios": [],
        "command": "python -c malicious",
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))

    with pytest.raises(FailureCorpusError, match="manifest fields"):
        FailureCorpus.load(path)
