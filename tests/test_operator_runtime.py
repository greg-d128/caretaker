from __future__ import annotations

from types import SimpleNamespace

from caretaker import GuardBinding, RepairAuthority, RepairEngine, RepairMode, RepairPolicy
from caretaker.guard import GuardEngine
from caretaker.operator import OperatorRuntimeRegistry
from caretaker.registry import build_target


class _Audit:
    def __init__(self) -> None:
        self.calls = []

    def emit(self, event_type, **fields):
        self.calls.append({"event_type": event_type, **fields})
        return {"event_id": "event-1", "stream_sequence": 1}


def test_operator_registry_exposes_repair_and_guard_targets():
    registry = OperatorRuntimeRegistry()
    guard = GuardEngine()
    engine = RepairEngine(guard=guard)
    registry.register_guard_engine(guard)
    registry.register_repair_engine(engine)

    def sample(value):
        return value

    target = build_target(
        sample,
        target_id="test.operator.sample",
        policy=RepairPolicy(
            mode=RepairMode.DIAGNOSE,
            authority=RepairAuthority.ANALYZE_ONLY,
            guard=GuardBinding(enabled=True),
        ),
    )
    engine.register(target)

    status = registry.status()
    assert status["target_count"] == 1
    assert status["current_status"] == "HEALTHY"
    assert registry.targets()[0]["target_id"] == "test.operator.sample"
    assert registry.targets()[0]["slot_role"] == "TARGET_IMPLEMENTATION"
    assert registry.targets()[0]["observation_level"] is None
    assert registry.targets()[0]["execution_contract"] == {
        "side_effects": "UNKNOWN",
        "retry_safety": "UNKNOWN",
    }


def test_unsupervised_behavior_capture_emits_local_audit_evidence(monkeypatch):
    audit = _Audit()
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: SimpleNamespace(
            supervised=False,
            audit=audit,
            effective=SimpleNamespace(fingerprint="sha256:policy", generation=3),
        ),
    )
    registry = OperatorRuntimeRegistry()
    guard = GuardEngine()

    def sample(value):
        return value

    guard.register_target("test.local.capture", sample, GuardBinding(enabled=True), periodic=False)
    registry.register_guard_engine(guard)

    response = registry.handle_request(
        {
            "command": "behavior-capture",
            "scope": "function",
            "subject": "test.local.capture",
            "calls": 3,
            "reason": "local audit coverage",
        },
        (1234, 1001, 1001),
    )

    assert response["ok"] is True
    assert len(audit.calls) == 1
    assert audit.calls[0]["event_type"] == "BEHAVIOR_COLLECTION_OUTCOME"
    assert audit.calls[0]["actor"] == {
        "type": "caretaker",
        "id": "uid:1001",
    }
    assert audit.calls[0]["outcome"]["authority_granted"] is False


def test_supervised_behavior_capture_does_not_emit_local_audit(monkeypatch):
    audit = _Audit()
    monkeypatch.setattr(
        "caretaker.logging.handler.get_runtime",
        lambda: SimpleNamespace(supervised=True, audit=audit),
    )
    registry = OperatorRuntimeRegistry()
    guard = GuardEngine()

    def sample(value):
        return value

    guard.register_target("test.supervised.capture", sample, GuardBinding(enabled=True), periodic=False)
    registry.register_guard_engine(guard)
    response = registry.handle_request(
        {
            "command": "behavior-capture",
            "scope": "function",
            "subject": "test.supervised.capture",
            "calls": 1,
        },
        (1234, 1001, 1001),
    )

    assert response["ok"] is True
    assert audit.calls == []


def test_operator_runtime_reports_validation_activity():
    registry = OperatorRuntimeRegistry()
    engine = RepairEngine()
    registry.register_repair_engine(engine)
    engine._active_validations[__import__("uuid").uuid4()] = {"target_id": "target.one"}

    status = registry.status()
    assert status["current_status"] == "VALIDATING"
    assert status["validation_count"] == 1
    assert status["validating_functions"] == ["target.one"]


def test_operator_runtime_exposes_fail_safe_repair_recovery_plan():
    registry = OperatorRuntimeRegistry()
    engine = RepairEngine()
    registry.register_repair_engine(engine)

    response = registry.handle_request(
        {"command": "repair-recovery-plan"},
        (123, 1000, 1000),
    )

    assert response["ok"] is True
    assert response["target"] is None
    assert response["plans"][0]["restart_policy"] == "DEPLOYED_CODE_ONLY"
    assert response["plans"][0]["automatic_reactivation"] is False


def test_operator_runtime_requires_confirmation_to_record_recovery_plan(monkeypatch):
    import pytest

    registry = OperatorRuntimeRegistry()
    engine = RepairEngine()
    registry.register_repair_engine(engine)
    plan = {
        "schema_version": 1,
        "read_only": True,
        "decisions": [],
    }
    applied = []
    monkeypatch.setattr(engine, "recovery_plan", lambda *, target_id=None: plan)
    monkeypatch.setattr(
        engine,
        "apply_recovery_plan",
        lambda value: applied.append(value) or {"applied_count": 0},
    )

    with pytest.raises(ValueError, match="confirm=true"):
        registry.handle_request(
            {"command": "repair-recovery-apply"},
            (123, 1000, 1000),
        )

    response = registry.handle_request(
        {"command": "repair-recovery-apply", "confirm": True},
        (123, 1000, 1000),
    )
    assert response["ok"] is True
    assert response["actions_dispatched"] is False
    assert response["automatic_reactivation"] is False
    assert applied == [plan]


def test_recovery_plan_supplies_registered_target_context_for_revalidation(monkeypatch):
    engine = RepairEngine()

    def sample(value):
        return value

    target = build_target(
        sample,
        target_id="test.recovery.sample",
        policy=RepairPolicy(mode=RepairMode.DIAGNOSE, authority=RepairAuthority.ANALYZE_ONLY),
    )
    engine.register(target)
    captured = {}

    def fake_plan(store, **kwargs):
        captured.update(kwargs)
        return {"decisions": []}

    monkeypatch.setattr("caretaker.engine.build_repair_recovery_plan", fake_plan)

    engine.recovery_plan(target_id=target.target_id)

    context = captured["live_context_by_target"][target.target_id]
    assert context["target_id"] == target.target_id
    assert context["code_hash"] == target.slot.load().source_hash
    assert context["authority_policy_generation"] is not None
    assert context["authority_policy_fingerprint"]


def test_operator_registry_attaches_adaptive_state_to_guard_dependency(monkeypatch):
    registry = OperatorRuntimeRegistry()
    guard = GuardEngine()
    registry.register_guard_engine(guard)

    def dependency(value):
        return value

    guard.register_target(
        "test.dependency", dependency, GuardBinding(enabled=True), periodic=False
    )
    monkeypatch.setattr(
        "caretaker.adaptive.get_adaptive_state",
        lambda target_id: {
            "level": "BEHAVIOR",
            "stage": "pre-repair-behavior",
            "stage_label": "BEHAVIOR",
            "promotion_reason": "exception threshold",
        } if target_id == "test.dependency" else None,
    )

    target = registry.targets()[0]
    assert target["slot_role"] == "DEPENDENCY_BOUNDARY"
    assert target["observation_level"] == "BEHAVIOR"
    assert target["lifecycle_stage"] == "pre-repair-behavior"
    assert target["escalation_reason"] == "exception threshold"


def test_operator_runtime_exposes_adaptive_aggregation_context(monkeypatch):
    registry = OperatorRuntimeRegistry()
    monkeypatch.setattr(
        "caretaker.adaptive.adaptive_aggregation_status",
        lambda: (
            {
                "enabled": True,
                "target_id": "test.aggregate",
                "generation_id": "generation-a",
                "policy_fingerprint": "policy-a",
            },
        ),
    )

    response = registry.handle_request(
        {"command": "adaptive-aggregation-context"},
        (123, 1000, 1000),
    )

    assert response == {
        "ok": True,
        "contexts": [
            {
                "enabled": True,
                "target_id": "test.aggregate",
                "generation_id": "generation-a",
                "policy_fingerprint": "policy-a",
            }
        ],
        "context_count": 1,
        "bounded": False,
    }


def test_authority_update_rolls_back_process_context_when_component_refresh_fails(monkeypatch):
    from caretaker.authority import get_authority_runtime_context

    registry = OperatorRuntimeRegistry()
    engine = RepairEngine()
    registry.register_repair_engine(engine)
    context = get_authority_runtime_context()
    previous = context.effective.snapshot_dict()
    changed = dict(previous)
    changed["generation"] = int(previous.get("generation", 0)) + 1
    changed["fingerprint"] = "changed-authority-generation"

    def fail_refresh():
        raise RuntimeError("synthetic refresh failure")

    monkeypatch.setattr(engine, "refresh_authority_policy", fail_refresh)
    try:
        import pytest
        with pytest.raises(RuntimeError, match="synthetic refresh failure"):
            registry.handle_request(
                {"command": "policy-authority-update", "snapshot": changed},
                (123, 1000, 1000),
            )
        assert context.effective.fingerprint == previous["fingerprint"]
        assert context.effective.generation == previous["generation"]
    finally:
        context.update_from_snapshot(previous)
