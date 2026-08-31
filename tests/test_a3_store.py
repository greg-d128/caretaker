from uuid import uuid4

from caretaker.domain import RepairEvent
from caretaker.store import SQLiteRepairStore


def test_sqlite_store_rehydrates_events_and_exposes_schema_version(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "caretaker.sqlite")
    event = RepairEvent.create(
        "test.event",
        "module:function",
        incident_id=uuid4(),
        details={"answer": 42},
    )
    store.append_event(event)
    loaded = store.recent_events("module:function")
    assert loaded == (event,)
    assert store.schema_version == 3
    assert store.query_records("events", target_id="module:function")[0]["details"]["answer"] == 42
