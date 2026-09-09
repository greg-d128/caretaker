from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.behavior import BehaviorSnapshotStore, content_hash
from caretaker.capsule import IncidentCapsuleIntegrityError, IncidentCapsuleStore
from caretaker.regression import RegressionFixtureIntegrityError, RegressionFixtureStore
from caretaker.replay import ReplayExecutionError, ReplayResultStore


def test_regression_fixture_schema_and_target_path_are_bound(tmp_path: Path) -> None:
    store = RegressionFixtureStore(tmp_path)
    envelope = store.record(
        target_id="app:target",
        name="case",
        args=(),
        kwargs={},
        expected=True,
        incident_id=None,
        candidate_id=None,
        source_function_version=1,
        source_function_hash="a" * 64,
        replay_safety="PURE",
    )
    assert envelope is not None
    path = next((tmp_path / "regression-fixtures").rglob("*.json"))
    data = json.loads(path.read_text())
    data["unexpected"] = True
    path.write_text(json.dumps(data))
    with pytest.raises(RegressionFixtureIntegrityError, match="schema fields"):
        store.load(envelope["fixture_id"])

    data.pop("unexpected")
    data["target_id"] = "app:other"
    payload = dict(data)
    payload.pop("content_sha256")
    data["content_sha256"] = content_hash(payload)
    path.write_text(json.dumps(data))
    with pytest.raises(RegressionFixtureIntegrityError, match="directory"):
        store.load(envelope["fixture_id"])


def test_replay_result_schema_rejects_unknown_fields_and_nonfinite_json(tmp_path: Path) -> None:
    store = ReplayResultStore(tmp_path)
    recorded = store.record({"results": [{"fixture_id": str(uuid4())}]})
    path = store.directory / f"{recorded['content_sha256']}.json"
    data = json.loads(path.read_text())
    data["unexpected"] = True
    path.write_text(json.dumps(data))
    with pytest.raises(ReplayExecutionError, match="envelope fields"):
        store.load(recorded["content_sha256"])

    path.write_text('{"schema_version": 1, "result": NaN}')
    with pytest.raises(ReplayExecutionError, match="valid JSON"):
        store.load(recorded["content_sha256"])


def test_capsule_and_snapshot_schema_versions_are_verified_after_rehash(tmp_path: Path) -> None:
    incident_id = uuid4()
    capsule_store = IncidentCapsuleStore(tmp_path)
    capsule = capsule_store.create_placeholder(incident_id)
    capsule_path = tmp_path / "incident-capsules" / f"{capsule['capsule']['capsule_id']}.r1.json"
    capsule_data = json.loads(capsule_path.read_text())
    capsule_data["capsule"]["schema_version"] = 999
    capsule_data["integrity"]["content_sha256"] = content_hash(capsule_data["capsule"])
    capsule_path.write_text(json.dumps(capsule_data))
    with pytest.raises(IncidentCapsuleIntegrityError, match="schema"):
        capsule_store.load(capsule["capsule"]["capsule_id"])

    behavior_store = BehaviorSnapshotStore(tmp_path / "behavior-data")
    snapshot = behavior_store.create({"scope": "function", "subject_key": "function:x", "subject": {}, "profile": {}, "children": []})
    snapshot_path = behavior_store.snapshot_directory / f"{snapshot['snapshot']['snapshot_id']}.json"
    snapshot_data = json.loads(snapshot_path.read_text())
    snapshot_data["snapshot"]["schema_version"] = 999
    snapshot_data["integrity"]["content_sha256"] = content_hash(snapshot_data["snapshot"])
    snapshot_path.write_text(json.dumps(snapshot_data))
    with pytest.raises(ValueError, match="schema"):
        behavior_store.load(snapshot["snapshot"]["snapshot_id"])
