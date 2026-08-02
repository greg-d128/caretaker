from pathlib import Path

from caretaker.postmortem import PostMortemRecorder
from caretaker.registry import TargetRegistry
from caretaker.store import InMemoryRepairStore


def test_internal_failure_creates_postmortem_and_emergency_record(tmp_path: Path) -> None:
    store = InMemoryRepairStore()
    recorder = PostMortemRecorder(
        store=store,
        registry=TargetRegistry(),
        emergency_path=tmp_path / "internal.jsonl",
    )
    try:
        raise RuntimeError("caretaker test failure")
    except RuntimeError as exc:
        record = recorder.capture(
            exc,
            component="test",
            operation="postmortem",
        )
    assert record is not None
    assert record.internal_incident_id in store.internal_incidents
    assert "caretaker test failure" in (tmp_path / "internal.jsonl").read_text()
