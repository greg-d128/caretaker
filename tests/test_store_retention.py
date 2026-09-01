from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
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


def test_retention_archive_is_compressed_idempotent_and_does_not_delete(tmp_path) -> None:
    path = tmp_path / "repair.sqlite"
    store = SQLiteRepairStore(path)
    old = datetime.now(timezone.utc) - timedelta(days=2)
    _insert_record(path, "candidates", target_id="archive.target", payload={"kind": "derived"}, created_at=old)
    plan = store.retention_dry_run(
        older_than=datetime.now(timezone.utc) - timedelta(days=1),
        families=("candidates",),
    )
    archive_path = tmp_path / "archives" / "repair.jsonl.gz"

    result = store.retention_archive(plan, archive_path=archive_path)

    assert result["complete"] is True
    assert result["partial"] is False
    assert archive_path.exists()
    assert not (tmp_path / "archives" / "repair.jsonl.gz.partial.jsonl").exists()
    with gzip.open(archive_path, "rt", encoding="utf-8") as stream:
        lines = [json.loads(line) for line in stream]
    assert lines[0]["kind"] == "retention_archive_header"
    assert lines[1]["kind"] == "retention_archive_record"
    assert lines[1]["payload"] == {"kind": "derived"}
    assert lines[-1]["kind"] == "retention_archive_footer"
    assert store.query_records("candidates", limit=100)[0]["kind"] == "derived"
    status = store.retention_archive_status(archive_path)
    assert status["complete"] is True
    assert status["record_count"] == 1
    assert status["record_families"] == ["candidates"]

    repeated = store.retention_archive(plan, archive_path=archive_path)
    assert repeated["complete"] is True
    assert repeated["archived_records"] == 1


def test_retention_archive_resumes_from_bounded_partial_and_rechecks_rows(tmp_path) -> None:
    path = tmp_path / "repair.sqlite"
    store = SQLiteRepairStore(path)
    old = datetime.now(timezone.utc) - timedelta(days=2)
    for target in ("first.target", "second.target"):
        _insert_record(path, "candidates", target_id=target, payload={"target": target}, created_at=old)
    plan = store.retention_dry_run(
        older_than=datetime.now(timezone.utc) - timedelta(days=1),
        families=("candidates",),
    )
    archive_path = tmp_path / "repair.jsonl.gz"

    first = store.retention_archive(plan, archive_path=archive_path, maximum_records=1)
    assert first["complete"] is False
    assert first["archived_records"] == 1
    assert first["remaining_records"] == 1
    assert Path(first["partial_path"]).exists()

    second = store.retention_archive(plan, archive_path=archive_path, maximum_records=1)
    assert second["complete"] is True
    assert second["archived_records"] == 2
    assert second["resumed_records"] == 1

    with gzip.open(archive_path, "rt", encoding="utf-8") as stream:
        records = [json.loads(line) for line in stream]
    assert [item["kind"] for item in records].count("retention_archive_record") == 2


def test_retention_archive_rejects_truncated_or_stale_plan(tmp_path) -> None:
    path = tmp_path / "repair.sqlite"
    store = SQLiteRepairStore(path)
    old = datetime.now(timezone.utc) - timedelta(days=2)
    _insert_record(path, "candidates", target_id="stale.target", payload={}, created_at=old)
    plan = store.retention_dry_run(
        older_than=datetime.now(timezone.utc) - timedelta(days=1),
        families=("candidates",),
    )
    archive_path = tmp_path / "repair.jsonl.gz"

    truncated = dict(plan)
    truncated["truncated"] = True
    with pytest.raises(ValueError, match="truncated"):
        store.retention_archive(truncated, archive_path=archive_path)

    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "UPDATE candidates SET target_id = ? WHERE target_id = ?",
            ("changed.target", "stale.target"),
        )
        connection.commit()
    with pytest.raises(ValueError, match="stale"):
        store.retention_archive(plan, archive_path=archive_path)


def test_retention_archive_rejects_valid_archive_with_wrong_record_set(tmp_path) -> None:
    path = tmp_path / "repair.sqlite"
    store = SQLiteRepairStore(path)
    old = datetime.now(timezone.utc) - timedelta(days=2)
    _insert_record(path, "candidates", target_id="planned.target", payload={}, created_at=old)
    plan = store.retention_dry_run(
        older_than=datetime.now(timezone.utc) - timedelta(days=1),
        families=("candidates",),
    )
    archive_path = tmp_path / "repair.jsonl.gz"
    store.retention_archive(plan, archive_path=archive_path)

    with gzip.open(archive_path, "rb") as stream:
        lines = stream.read().splitlines()
    record = json.loads(lines[1])
    record["record_id"] = str(uuid4())
    unsigned = dict(record)
    unsigned.pop("record_sha256")
    record["record_sha256"] = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    lines[1] = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    lines[-1] = json.dumps(
        {
            "kind": "retention_archive_footer",
            "record_count": 1,
            "records_sha256": hashlib.sha256(lines[1] + b"\n").hexdigest(),
            "schema_version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with gzip.open(archive_path, "wb") as stream:
        stream.write(b"\n".join(lines) + b"\n")

    with pytest.raises(ValueError, match="does not match"):
        store.retention_archive(plan, archive_path=archive_path)
