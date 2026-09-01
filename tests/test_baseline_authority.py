from __future__ import annotations

from types import SimpleNamespace

from uuid import uuid4

from caretaker.guard import GuardEngine, GuardBinding
from caretaker.evidence.store import SQLiteEvidenceStore
from caretaker.operator import OperatorRuntimeRegistry


class _Audit:
    def __init__(self) -> None:
        self.calls = []

    def emit(self, event_type, **fields):
        self.calls.append({"event_type": event_type, **fields})
        return {"event_id": "baseline-audit-1"}


def _guard(store=None) -> GuardEngine:
    guard = GuardEngine(store=store)
    guard.register_target(
        "test.baseline.authority",
        lambda value: value,
        GuardBinding(enabled=True),
        periodic=False,
    )
    return guard


def test_direct_manager_acceptance_is_not_runtime_store_acceptance():
    guard = _guard()
    target = guard._targets["test.baseline.authority"]
    call_id = uuid4()
    guard.before_call("test.baseline.authority", target.function, call_id, candidate_id=None)
    guard.after_call(
        "test.baseline.authority", target.function, call_id, candidate_id=None,
        succeeded=True, elapsed_seconds=0.001, result=1,
    )
    guard.close_target_window("test.baseline.authority")
    guard.baselines.accept(target.identity)
    assert not guard.store.guard_baselines
    assert not guard.store.baseline_acceptances


def test_authoritative_operator_acceptance_is_recorded_and_audited(monkeypatch):
    audit = _Audit()
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: SimpleNamespace(audit=audit),
    )
    guard = _guard()
    # Seed the manager with a window through the public event path.
    target = guard._targets["test.baseline.authority"]
    call_id = uuid4()
    guard.before_call("test.baseline.authority", target.function, call_id, candidate_id=None)
    guard.after_call(
        "test.baseline.authority", target.function, call_id, candidate_id=None,
        succeeded=True, elapsed_seconds=0.001, result=1,
    )
    guard.close_target_window("test.baseline.authority")
    registry = OperatorRuntimeRegistry()
    registry.register_guard_engine(guard)

    result = registry.handle_request(
        {
            "command": "guard-baseline-accept",
            "target": "test.baseline.authority",
            "reason": "reviewed capture",
        },
        (123, 1001, 1001),
    )

    assert result["ok"] is True
    acceptance = next(iter(guard.store.baseline_acceptances.values()))
    assert acceptance.actor_id == "uid:1001"
    assert acceptance.reason == "reviewed capture"
    assert acceptance.authority_fingerprint
    assert audit.calls[0]["event_type"] == "GUARD_BASELINE_ACCEPTED"
    assert audit.calls[0]["outcome"]["authority_granted"] is False


def test_authoritative_acceptance_is_persisted_by_sqlite_store(tmp_path):
    store = SQLiteEvidenceStore(tmp_path / "guard.sqlite")
    guard = _guard(store)
    target = guard._targets["test.baseline.authority"]
    call_id = uuid4()
    guard.before_call("test.baseline.authority", target.function, call_id, candidate_id=None)
    guard.after_call(
        "test.baseline.authority", target.function, call_id, candidate_id=None,
        succeeded=True, elapsed_seconds=0.001, result=1,
    )
    guard.close_target_window("test.baseline.authority")
    guard.accept_baseline(
        "test.baseline.authority",
        actor_type="operator",
        actor_id="uid:1001",
        reason="sqlite persistence coverage",
    )

    rows = store.query(
        "SELECT target_id, actor_id, reason FROM baseline_acceptances"
    )
    assert rows == ({
        "target_id": "test.baseline.authority",
        "actor_id": "uid:1001",
        "reason": "sqlite persistence coverage",
    },)
