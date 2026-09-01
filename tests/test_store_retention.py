from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from caretaker import SQLiteRepairStore


def _insert_record(path, table: str, *, target_id: str | None, payload: dict, created_at: datetime) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            f"INSERT INTO {table}(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
            (str(uuid4()), target_id, created_at.isoformat(), json.dumps(payload)),
        )
        connection.commit()


def test_retention_dry_run_preserves_incident_and_signed_evidence_without_mutation(tmp_path) -> None:
    path = tmp_path / "repair.sqlite"
    store = SQLiteRepairStore(path)
    old = datetime.now(timezone.utc) - timedelta(days=2)
    fresh = datetime.now(timezone.utc)
    _insert_record(path, "candidates", target_id="ordinary.target", payload={"kind": "derived"}, created_at=old)
    _insert_record(
        path,
        "attempts",
        target_id="incident.target",
        payload={"incident_id": str(uuid4()), "kind": "evidence"},
        created_at=old,
    )
    _insert_record(
        path,
        "repair_rollouts",
        target_id="signed.target",
        payload={"signature_state": "SIGNED", "kind": "evidence"},
        created_at=old,
    )
    _insert_record(path, "candidates", target_id="fresh.target", payload={"kind": "fresh"}, created_at=fresh)
    _insert_record(path, "events", target_id="audit.target", payload={"event_type": "audit"}, created_at=old)

    before = store.query_records("candidates", limit=100)
    plan = store.retention_dry_run(older_than=datetime.now(timezone.utc) - timedelta(days=1))

    assert plan["schema_version"] == 1
    assert plan["truncated"] is False
    assert len(plan["candidate_records"]) == 1
    assert len(plan["preserved_records"]) == 3
    reasons = {item["reason"] for item in plan["preserved_records"]}
    assert reasons == {"incident_linked_evidence", "signed_evidence", "protected_artifact_family"}
    assert store.query_records("candidates", limit=100) == before


def test_retention_dry_run_is_bounded_and_validates_scope(tmp_path) -> None:
    path = tmp_path / "repair.sqlite"
    store = SQLiteRepairStore(path)
    old = datetime.now(timezone.utc) - timedelta(days=2)
    for target in ("first.target", "second.target"):
        _insert_record(path, "candidates", target_id=target, payload={}, created_at=old)

    plan = store.retention_dry_run(
        older_than=datetime.now(timezone.utc) - timedelta(days=1),
        families=("candidates",),
        maximum_records=1,
    )
    assert plan["examined_records"] == 1
    assert plan["truncated"] is True
    assert len(plan["candidate_records"]) == 1

    with pytest.raises(ValueError, match="timezone-aware"):
        store.retention_dry_run(older_than=datetime.now())
    with pytest.raises(ValueError, match="Unknown Caretaker store table"):
        store.retention_dry_run(
            older_than=datetime.now(timezone.utc), families=("not-a-table",)
        )
