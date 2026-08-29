from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker import (
    DATA_ONLY_NOT_EXECUTABLE,
    RegressionCorpus,
    RegressionFixtureIntegrityError,
    RegressionFixturePolicy,
    RegressionFixtureStore,
    ValidationIsolationLevel,
)
from caretaker.logging.policy import load_operator_policy


def test_fixture_store_persists_bounded_redacted_json_only(tmp_path: Path) -> None:
    policy = RegressionFixturePolicy(
        enabled=True,
        maximum_fixture_bytes=32 * 1024,
        maximum_depth=3,
        maximum_collection_items=2,
        maximum_text_characters=12,
    )
    store = RegressionFixtureStore(tmp_path, policy=policy)
    incident_id = uuid4()
    envelope = store.record(
        target_id="app:payments:charge",
        name="repaired-incident",
        args=("customer", {"token": "secret-value", "items": [1, 2, 3]}),
        kwargs={"authorization": "Bearer private", "region": "us-east"},
        expected={"ok": True},
        incident_id=incident_id,
        candidate_id=uuid4(),
        source_function_version=2,
        source_function_hash="a" * 64,
        replay_safety="PURE",
    )

    assert envelope is not None
    assert envelope["replay_status"] == DATA_ONLY_NOT_EXECUTABLE
    assert envelope["content_sha256"]
    raw = json.loads(next((tmp_path / "regression-fixtures").rglob("*.json")).read_text())
    authorization = next(
        value for key, value in raw["kwargs"].items() if key.startswith("authoriz")
    )
    assert authorization["value"] == "<redacted>"
    assert raw["args"][1]["items"][0]["truncated"] is True
    assert store.load(envelope["fixture_id"])["content_sha256"] == envelope["content_sha256"]
    summary = store.list_summaries()
    assert summary[0]["integrity_verified"] is True
    assert summary[0]["replay_status"] == DATA_ONLY_NOT_EXECUTABLE


def test_fixture_tampering_is_visible_and_load_fails(tmp_path: Path) -> None:
    store = RegressionFixtureStore(tmp_path)
    envelope = store.record(
        target_id="app:target",
        name="case",
        args=(1,),
        kwargs={},
        expected=2,
        incident_id=None,
        candidate_id=None,
        source_function_version=1,
        source_function_hash=None,
        replay_safety="IDEMPOTENT",
    )
    assert envelope is not None
    path = next((tmp_path / "regression-fixtures").rglob("*.json"))
    data = json.loads(path.read_text())
    data["expected"] = 99
    path.write_text(json.dumps(data))

    summary = store.list_summaries()
    assert summary[0]["integrity_verified"] is False
    with pytest.raises(RegressionFixtureIntegrityError):
        store.load(envelope["fixture_id"])


def test_fixture_store_refuses_more_than_configured_target_limit(tmp_path: Path) -> None:
    policy = RegressionFixturePolicy(maximum_cases_per_target=1)
    store = RegressionFixtureStore(tmp_path, policy=policy)
    arguments = dict(
        target_id="app:target",
        name="case",
        args=(),
        kwargs={},
        expected=True,
        incident_id=None,
        candidate_id=None,
        source_function_version=1,
        source_function_hash=None,
        replay_safety="PURE",
    )
    assert store.record(**arguments) is not None
    assert store.record(**arguments) is None
    assert len(store.list_summaries()) == 1


def test_persistent_fixture_does_not_become_executable_corpus_case(tmp_path: Path) -> None:
    store = RegressionFixtureStore(tmp_path)
    corpus = RegressionCorpus(fixture_store=store)
    case = corpus.add_successful_replay(
        target_id="app:target",
        args=(1,),
        kwargs={},
        expected=2,
        incident_id=None,
        candidate_id=None,
        source_function_version=1,
        source_function_hash="b" * 64,
        replay_safety="PURE",
    )
    assert case is not None
    assert corpus.registered_cases_for_target("app:target")
    assert store.list_summaries()[0]["replay_status"] == DATA_ONLY_NOT_EXECUTABLE


def test_logging_policy_parses_regression_fixture_limits(tmp_path: Path) -> None:
    path = tmp_path / "logging.toml"
    path.write_text(
        """
[logging]
directory = "./data"

[logging.regression]
enabled = true
replay_enabled = true
replay_minimum_isolation = "CONTAINER"
replay_require_source_match = false
maximum_cases_per_target = 7
maximum_fixture_bytes = 4096
maximum_depth = 4
maximum_collection_items = 5
maximum_text_characters = 99
"""
    )
    policy, _ = load_operator_policy(path)
    assert policy.regression == RegressionFixturePolicy(
        enabled=True,
        replay_enabled=True,
        replay_minimum_isolation=ValidationIsolationLevel.CONTAINER,
        replay_require_source_match=False,
        maximum_cases_per_target=7,
        maximum_fixture_bytes=4096,
        maximum_depth=4,
        maximum_collection_items=5,
        maximum_text_characters=99,
    )
