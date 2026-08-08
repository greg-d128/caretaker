from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from caretaker import (
    CandidateProposal,
    ComparisonResult,
    DifferentialExecutionMode,
    DifferentialExecutionPolicy,
    ExceptionTrigger,
    IntegrityClass,
    IntegrityRepairPolicy,
    ObservationPolicy,
    PolicyConfigurationError,
    RepairEngine,
    RepairPolicy,
    RepairAuthority,
    ReplaySafety,
    RetryPolicy,
    SnapshotStrategy,
    StatePolicy,
    StaticRepairProvider,
    diagnose_only,
    observe_only,
    repair,
    repair_and_retry,
    repair_on_exception,
    repair_on_invalid_output,
    repair_on_soft_timeout,
    repair_on_timeout,
)
from caretaker.slot import FunctionSlot
from tests.sample_targets import always_fails, broken_divide, invalid_result


def test_policy_validation_rejects_unimplemented_snapshot_strategy() -> None:
    policy = RepairPolicy(state=StatePolicy(strategy=SnapshotStrategy.JSON))
    with pytest.raises(PolicyConfigurationError, match="DEEPCOPY"):
        repair(policy=policy)(always_fails)


def test_dangerous_definition_time_default_is_hard_disqualified() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source=(
                    "def always_fails(value: int = os.system('echo unsafe')) -> int:\n"
                    "    return value\n"
                ),
                explanation="Unsafe candidate",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    wrapped = repair(policy=RepairPolicy(), engine=engine)(always_fails)
    with pytest.raises(ValueError, match="broken"):
        wrapped(1)
    attempt = next(iter(engine.store.attempts.values()))
    assert attempt.score_card is not None
    assert attempt.score_card.eligible is False
    assert any("default" in item for item in attempt.score_card.disqualifications)


def test_function_slot_prevents_failed_version_reactivation_and_aba_flapping() -> None:
    def original(value: int) -> int:
        return value

    def candidate(value: int) -> int:
        return value + 1

    slot = FunctionSlot(
        target_id="slot-test",
        original=original,
        original_source="def original(value): return value\n",
        original_source_hash="A",
    )
    lease = slot.begin_repair()
    active = slot.activate(
        lease=lease,
        implementation=candidate,
        source="def candidate(value): return value + 1\n",
        source_hash="B",
        repair_attempt_id=__import__("uuid").uuid4(),
        candidate_id=__import__("uuid").uuid4(),
    )
    slot.rollback(active.number)
    allowed, reason = slot.can_activate_source(
        "B",
        prevent_failed_reactivation=True,
        detect_oscillation=True,
        oscillation_window_versions=5,
    )
    assert allowed is False
    assert "rolled back" in (reason or "")


def test_convenience_decorators_compile_to_repair_policies() -> None:
    provider = StaticRepairProvider(
        [CandidateProposal(source="def always_fails(value: int) -> int:\n    return value\n", explanation="fix")]
    )
    engine = RepairEngine(provider=provider)
    wrapped = repair_and_retry(
        engine=engine,
        replay_safety=ReplaySafety.PURE,
        policy=RepairPolicy(authority=RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS),
    )(always_fails)
    assert wrapped(7) == 7
    assert wrapped.__caretaker_target__.policy.retry.max_attempts == 1

    diagnosed = diagnose_only(engine=RepairEngine(provider=provider), target_id="tests:diagnose-always-fails")(always_fails)
    assert diagnosed.__caretaker_target__.policy.mode.name == "DIAGNOSE"
    observed = observe_only(engine=RepairEngine(provider=provider), target_id="tests:observe-always-fails")(always_fails)
    assert observed.__caretaker_target__.policy.mode.name == "OBSERVE"

    assert repair_on_exception(engine=RepairEngine(provider=provider), target_id="tests:exception-always-fails")(always_fails).__caretaker_target__.policy.triggers
    assert repair_on_soft_timeout(1.0, engine=RepairEngine(provider=provider), target_id="tests:timeout-always-fails")(always_fails).__caretaker_target__.policy.triggers
    with pytest.deprecated_call(match="soft elapsed-time trigger"):
        repair_on_timeout(1.0, engine=RepairEngine(provider=provider), target_id="tests:timeout-compat")(always_fails)
    assert repair_on_invalid_output(lambda value: True, engine=RepairEngine(provider=provider), target_id="tests:output-invalid-result")(invalid_result).__caretaker_target__.policy.triggers


def test_structured_comparator_is_used_for_differential_execution() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source=(
                    "def broken_divide(total: float, count: int) -> float:\n"
                    "    if count == 0:\n"
                    "        return 0.0\n"
                    "    return round(total / count, 3)\n"
                ),
                explanation="rounded repair",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    comparator = lambda left, right: ComparisonResult(
        equivalent=abs(left - right) < 0.01,
        reason="numerically equivalent",
    )
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        authority=RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS,
        observation=ObservationPolicy(
            initial_successful_executions=10,
            long_term_successful_executions=20,
            long_term_minimum_duration_seconds=0,
            differential_execution=DifferentialExecutionPolicy(
                mode=DifferentialExecutionMode.PURE_FUNCTION,
                observation_executions=5,
                comparator=comparator,
            ),
        ),
    )
    wrapped = repair(policy=policy, engine=engine)(broken_divide)
    assert wrapped(4.0, 0) == 0.0
    assert wrapped(2.0, 3.0) == pytest.approx(0.667)


def test_integrity_classification_controls_repair_eligibility() -> None:
    provider = StaticRepairProvider(
        [CandidateProposal(source="def always_fails(value: int) -> int:\n    return value\n", explanation="fix")]
    )
    protected_engine = RepairEngine(provider=provider)
    protected = repair(
        engine=protected_engine,
        integrity_class=IntegrityClass.PROTECTED,
    )(always_fails)
    with pytest.raises(ValueError):
        protected(1)
    assert protected.__caretaker_target__.support.capability.name == "DIAGNOSTIC_ONLY"
    assert not protected_engine.store.attempts

    allowed_policy = RepairPolicy(
        integrity=IntegrityRepairPolicy(allow_protected_automatic_repair=True),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        authority=RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS,
    )
    allowed_engine = RepairEngine(provider=provider)
    allowed = repair(
        policy=allowed_policy,
        engine=allowed_engine,
        integrity_class=IntegrityClass.PROTECTED,
    )(always_fails)
    assert allowed(2) == 2

    sealed_engine = RepairEngine(provider=provider)
    sealed = repair(engine=sealed_engine, integrity_class=IntegrityClass.SEALED)(always_fails)
    with pytest.raises(ValueError):
        sealed(1)
    assert sealed.__caretaker_target__.support.capability.name == "DIAGNOSTIC_ONLY"


def test_default_repair_authority_requires_operator_approval() -> None:
    assert RepairPolicy().authority is RepairAuthority.REQUIRE_OPERATOR_APPROVAL
