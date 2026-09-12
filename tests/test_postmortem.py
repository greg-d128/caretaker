from pathlib import Path
import math

import pytest

from caretaker.postmortem import PostMortemRecorder
from caretaker.registry import TargetRegistry
from caretaker.store import InMemoryRepairStore
from caretaker.store import _jsonable as store_jsonable
from caretaker.operator import _jsonable as operator_jsonable


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


def test_postmortem_json_boundaries_reject_non_finite_evidence() -> None:
    for encode in (store_jsonable, operator_jsonable):
        with pytest.raises(ValueError, match="non-finite"):
            encode({"evidence": math.nan})
