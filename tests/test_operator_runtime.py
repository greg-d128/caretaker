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


def test_operator_runtime_reports_validation_activity():
    registry = OperatorRuntimeRegistry()
    engine = RepairEngine()
    registry.register_repair_engine(engine)
    engine._active_validations[__import__("uuid").uuid4()] = {"target_id": "target.one"}

    status = registry.status()
    assert status["current_status"] == "VALIDATING"
    assert status["validation_count"] == 1
    assert status["validating_functions"] == ["target.one"]
