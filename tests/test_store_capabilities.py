from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from math import nan
from uuid import uuid4

import pytest

from caretaker import (
    InMemoryRepairStore,
    SQLiteRepairStore,
    evidence_store_view,
    integrity_store_view,
    lifecycle_store_view,
    postmortem_store_view,
    worker_recovery_store_view,
)


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_store_views_expose_only_their_declared_capability(tmp_path, store_kind: str) -> None:
    store = (
        InMemoryRepairStore()
        if store_kind == "memory"
        else SQLiteRepairStore(tmp_path / "repair.sqlite3")
    )

    lifecycle = lifecycle_store_view(store)
    evidence = evidence_store_view(store)
    worker_recovery = worker_recovery_store_view(store)
    integrity = integrity_store_view(store)
    postmortem = postmortem_store_view(store)

    assert callable(lifecycle.record_episode)
    assert callable(lifecycle.commit_rollout_transition)
    assert callable(evidence.record_observation)
    assert callable(worker_recovery.record_recovery)
    assert callable(integrity.record_integrity_incident)
    assert callable(postmortem.record_internal_incident)
    assert callable(postmortem.recent_events)

    with pytest.raises(AttributeError):
        evidence.record_integrity_incident
    with pytest.raises(AttributeError):
        integrity.record_observation
    with pytest.raises(AttributeError):
        lifecycle.record_worker_failure
    with pytest.raises(AttributeError):
        worker_recovery.record_policy
    with pytest.raises(AttributeError):
        postmortem.record_observation


def test_sqlite_durable_records_reject_non_finite_json(tmp_path) -> None:
    @dataclass(frozen=True)
    class EvidenceRecord:
        internal_incident_id: object
        occurred_at: object
        evidence: float

    store = SQLiteRepairStore(tmp_path / "repair.sqlite3")
    record = EvidenceRecord(uuid4(), datetime.now(timezone.utc), nan)
    with pytest.raises(ValueError, match="Out of range float values"):
        store._write("internal_incidents", record, target_id=None)
