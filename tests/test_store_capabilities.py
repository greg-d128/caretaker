from __future__ import annotations

import pytest

from caretaker import (
    InMemoryRepairStore,
    SQLiteRepairStore,
    evidence_store_view,
    integrity_store_view,
    lifecycle_store_view,
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

    assert callable(lifecycle.record_episode)
    assert callable(lifecycle.commit_rollout_transition)
    assert callable(evidence.record_observation)
    assert callable(worker_recovery.record_recovery)
    assert callable(integrity.record_integrity_incident)

    with pytest.raises(AttributeError):
        evidence.record_integrity_incident
    with pytest.raises(AttributeError):
        integrity.record_observation
    with pytest.raises(AttributeError):
        lifecycle.record_worker_failure
    with pytest.raises(AttributeError):
        worker_recovery.record_policy
