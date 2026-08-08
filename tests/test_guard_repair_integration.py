from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    GuardBinding,
    GuardEngine,
    GuardMode,
    GuardPolicy,
    InMemoryRepairStore,
    ObservationPolicy,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    repair,
)
from caretaker.control_plane import RuntimeSignal, SignalDomain, SignalSeverity
from caretaker.guard.models import (
    BehaviorDeviation,
    DeviationCategory,
    EvidenceSummary,
)
from caretaker.guard.policy import AggregationPolicy, BaselinePolicy
from tests.guard_targets import failing, ordinary


def _guard_policy() -> GuardPolicy:
    return GuardPolicy(
        mode=GuardMode.AUDIT,
        aggregation=AggregationPolicy(
            close_after_events=2,
            close_after_calls=1,
            close_after_seconds=999,
        ),
        baseline=BaselinePolicy(minimum_windows=1),
    )


def _repair_policy() -> RepairPolicy:
    return RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(initial_successful_executions=5),
        guard=GuardBinding(
            enabled=True,
            observe_network=True,
            observe_filesystem=True,
            include_guard_context_in_repair=True,
            validate_candidate_behavior=True,
            monitor_during_probation=True,
        ),
    )


def test_guard_rejects_candidate_that_introduces_new_capability(tmp_path) -> None:
    guard = GuardEngine(policy=_guard_policy())
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source=(
                    "def failing(value: int) -> int:\n"
                    "    open('/tmp/caretaker-guard-test', 'w').write('x')\n"
                    "    return value\n"
                ),
                explanation="Adds filesystem behavior",
            )
        ]
    )
    engine = RepairEngine(provider=provider, guard=guard)
    wrapped = repair(policy=_repair_policy(), engine=engine)(failing)

    with pytest.raises(ValueError, match="broken"):
        wrapped(3)
    attempt = next(iter(engine.store.attempts.values()))
    assert attempt.score_card is not None
    assert not attempt.score_card.eligible
    assert any("filesystem capability" in item for item in attempt.score_card.disqualifications)


def test_guard_can_queue_behavior_repair_for_next_decorated_call() -> None:
    guard = GuardEngine(policy=_guard_policy())
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="def ordinary(value: int) -> int:\n    return value * 10\n",
                explanation="Respond to Guard deviation",
            )
        ]
    )
    engine = RepairEngine(provider=provider, guard=guard)
    wrapped = repair(policy=_repair_policy(), engine=engine)(ordinary)
    target = wrapped.__caretaker_target__
    deviation = BehaviorDeviation(
        deviation_id=uuid4(),
        baseline_id=uuid4(),
        observation_window_id=uuid4(),
        subject=guard._targets[target.target_id].identity,
        category=DeviationCategory.RATE_INCREASE,
        expected=EvidenceSummary("normal", {"rate": 1}),
        observed=EvidenceSummary("abnormal", {"rate": 50}),
        novelty_score=80,
        magnitude_score=90,
        sensitivity_score=50,
        confidence_score=90,
        persistence_score=50,
        significance_score=75,
        explanation="Function behavior rate increased unexpectedly",
    )
    engine.queue_guard_repair(target.target_id, (deviation,))

    assert wrapped(4) == 40
    assert target.slot.load().number == 1


def test_guard_control_plane_can_roll_back_active_candidate() -> None:
    guard = GuardEngine(policy=_guard_policy())
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="def failing(value: int) -> int:\n    return value * 2\n",
                explanation="Fix",
            )
        ]
    )
    engine = RepairEngine(provider=provider, guard=guard)
    wrapped = repair(policy=_repair_policy(), engine=engine)(failing)
    assert wrapped(5) == 10
    current = wrapped.__caretaker_target__.slot.load()
    assert current.candidate_id is not None

    signal = RuntimeSignal.create(
        domain=SignalDomain.BEHAVIOR,
        kind="candidate-deviation",
        severity=SignalSeverity.HIGH,
        run_id=guard.run_id,
        source_component="test",
        target_id=wrapped.__caretaker_target__.target_id,
        attributes={
            "requested_action": "ROLLBACK_ACTIVE_CANDIDATE",
            "candidate_id": str(current.candidate_id),
        },
    )
    guard.control_plane.submit(signal)
    assert wrapped.__caretaker_target__.slot.load().number == 0


def test_guard_binding_reports_resource_observation_categories() -> None:
    from caretaker import GuardBinding

    binding = GuardBinding(enabled=True, observe_network=True, observe_imports=True)
    assert binding.observed_resource_categories == ("network", "imports")
    assert GuardBinding(enabled=True).observed_resource_categories == ()
