from __future__ import annotations

from caretaker import GuardBinding, RepairAuthority, RepairEngine, RepairMode, RepairPolicy
from caretaker.guard import GuardEngine
from caretaker.operator import OperatorRuntimeRegistry
from caretaker.registry import build_target


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


def test_operator_runtime_reports_validation_activity():
    registry = OperatorRuntimeRegistry()
    engine = RepairEngine()
    registry.register_repair_engine(engine)
    engine._active_validations[__import__("uuid").uuid4()] = {"target_id": "target.one"}

    status = registry.status()
    assert status["current_status"] == "VALIDATING"
    assert status["validation_count"] == 1
    assert status["validating_functions"] == ["target.one"]


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
