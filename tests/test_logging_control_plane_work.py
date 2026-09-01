from __future__ import annotations

from uuid import uuid4

from caretaker import (
    CaretakerComponent,
    RuntimeActionKind,
    RuntimeControlPlane,
    RuntimeInteractionPolicy,
    RuntimeSignal,
    SignalDomain,
    SignalSeverity,
    WorkRegistry,
)


def test_active_work_matching_fingerprint_is_not_treated_as_new_attack():
    registry = WorkRegistry()
    work = registry.start(
        component=CaretakerComponent.REPAIR,
        work_kind="activation",
        scope="demo:fn",
        root_signal_id=uuid4(),
        expected_code_fingerprints={"demo:fn": "expected"},
    )
    plane = RuntimeControlPlane()
    signal = RuntimeSignal.create(
        domain=SignalDomain.BEHAVIOR,
        kind="runtime-code-change",
        severity=SignalSeverity.HIGH,
        run_id=uuid4(),
        source_component="guard",
        target_id="demo:fn",
        attributes={"observed_code_fingerprint": "expected"},
    )
    decision = plane.submit(signal, context={"work_registry": registry})
    assert decision.actions == (RuntimeActionKind.RECORD,)
    assert "work in progress" in decision.reason


def test_conflicting_change_during_work_requests_interrogation():
    registry = WorkRegistry()
    registry.start(
        component=CaretakerComponent.REPAIR,
        work_kind="activation",
        scope="demo:fn",
        root_signal_id=uuid4(),
        expected_code_fingerprints={"demo:fn": "expected"},
    )
    plane = RuntimeControlPlane()
    signal = RuntimeSignal.create(
        domain=SignalDomain.BEHAVIOR,
        kind="runtime-code-change-2",
        severity=SignalSeverity.HIGH,
        run_id=uuid4(),
        source_component="guard",
        target_id="demo:fn",
        attributes={"observed_code_fingerprint": "other"},
    )
    decision = plane.submit(signal, context={"work_registry": registry})
    assert RuntimeActionKind.INTERROGATE_LOGS in decision.actions
    assert decision.requires_human_review


def test_control_plane_history_is_bounded_by_policy():
    plane = RuntimeControlPlane(
        interaction_policy=RuntimeInteractionPolicy(maximum_history_entries=2)
    )
    for index in range(4):
        plane.submit(
            RuntimeSignal.create(
                domain=SignalDomain.FAILURE,
                kind=f"failure-{index}",
                severity=SignalSeverity.LOW,
                run_id=uuid4(),
                source_component="test",
            )
        )

    assert len(plane.signals) == 2
    assert len(plane.decisions) == 2
    assert len(plane.actions) == 2
    assert plane.signals[0].kind == "failure-2"
    assert plane.decisions[0].signal_id == plane.signals[0].signal_id
