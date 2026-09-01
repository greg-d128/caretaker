from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    OperationContext,
    OperationContextStaleError,
    RegisteredCase,
    RepairEngine,
    RepairAuthority,
    RepairPolicy,
    RepairRolloutLedger,
    RepairRolloutPolicy,
    RepairRolloutStage,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
)
from caretaker.store import InMemoryRepairStore
from tests.sample_targets import broken_divide


def _context() -> OperationContext:
    return OperationContext(
        operation_id=uuid4(),
        target_id="tests.context.target",
        policy_snapshot_id=uuid4(),
        policy_fingerprint="policy-hash",
        authority_policy_generation=4,
        authority_policy_fingerprint="authority-hash",
        evidence_identity="incident:123",
        evidence_fingerprint="evidence-hash",
    )


def test_operation_context_is_immutable_and_has_stable_audit_identity() -> None:
    context = _context()

    with pytest.raises(FrozenInstanceError):
        context.target_id = "other"  # type: ignore[misc]

    restored = OperationContext(
        operation_id=context.operation_id,
        target_id=context.target_id,
        policy_snapshot_id=context.policy_snapshot_id,
        policy_fingerprint=context.policy_fingerprint,
        authority_policy_generation=context.authority_policy_generation,
        authority_policy_fingerprint=context.authority_policy_fingerprint,
        evidence_identity=context.evidence_identity,
        evidence_fingerprint=context.evidence_fingerprint,
    )
    assert context.fingerprint == restored.fingerprint
    with pytest.raises(OperationContextStaleError, match="policy_fingerprint"):
        context.assert_current(
            target_id=context.target_id,
            policy_fingerprint="changed-policy",
            authority_policy_generation=context.authority_policy_generation,
            authority_policy_fingerprint=context.authority_policy_fingerprint,
        )


def test_repair_admission_carries_one_context_to_episode_attempt_and_audit() -> None:
    store = InMemoryRepairStore()
    engine = RepairEngine(
        provider=StaticRepairProvider(
            [
                CandidateProposal(
                    source=(
                        "def broken_divide(total: float, count: int) -> float:\n"
                        "    if count == 0:\n"
                        "        return 0.0\n"
                        "    return total / count\n"
                    ),
                    explanation="repair the broken result",
                    generator_name="test",
                )
            ]
        ),
        store=store,
    )
    policy = RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
    )

    from caretaker import repair

    healed = repair(
        policy=policy,
        engine=engine,
        cases=(RegisteredCase("repair", args=(10.0, 0), expected=0.0),),
    )(broken_divide)
    assert healed(10.0, 0) == 0.0

    episode = next(iter(store.episodes.values()))
    attempt = next(iter(store.attempts.values()))
    assert episode.operation_context is not None
    assert attempt.operation_context == episode.operation_context
    started = next(event for event in store.events if event.event_type == "repair.episode_started")
    assert started.details["operation_context"] == episode.operation_context.as_dict()


def test_rollout_admission_binds_context_to_record_and_transition_audit() -> None:
    incident_id = uuid4()
    candidate_id = uuid4()
    policy_snapshot_id = uuid4()
    ledger = RepairRolloutLedger(policy=RepairRolloutPolicy(enabled=True))

    record = ledger.create(
        target_id="tests.rollout.target",
        incident_id=incident_id,
        candidate_id=candidate_id,
        candidate_source_hash="candidate-hash",
        base_source_hash="base-hash",
        policy_fingerprint="policy-hash",
        policy_snapshot_id=policy_snapshot_id,
        authority_fingerprint="authority-hash",
        authority_generation=7,
        proposed_by="advisory-engine",
    )

    assert record.operation_context is not None
    assert record.operation_context.operation_id == record.rollout_id
    assert record.operation_context.policy_snapshot_id == policy_snapshot_id
    transition = ledger.transitions(record.rollout_id)[0]
    assert transition.details["operation_context"] == record.operation_context.as_dict()
    assert record.stage is RepairRolloutStage.PROPOSED


def test_operator_approval_rejects_a_policy_changed_after_admission() -> None:
    from caretaker import repair

    engine = RepairEngine(
        provider=StaticRepairProvider(
            [
                CandidateProposal(
                    source=(
                        "def broken_divide(total: float, count: int) -> float:\n"
                        "    if count == 0:\n"
                        "        return 0.0\n"
                        "    return total / count\n"
                    ),
                    explanation="repair the broken divisor behavior",
                )
            ]
        )
    )
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=0, safety=ReplaySafety.PURE),
        authority=RepairAuthority.REQUIRE_OPERATOR_APPROVAL,
    )
    wrapped = repair(
        policy=policy,
        engine=engine,
        cases=(RegisteredCase("zero", args=(10.0, 0), expected=0.0),),
    )(broken_divide)

    with pytest.raises(ZeroDivisionError):
        wrapped(10.0, 0)
    pending = engine.pending_approvals()
    assert len(pending) == 1
    target = wrapped.__caretaker_target__
    changed_target = replace(
        target,
        policy=replace(
            target.policy,
            context=replace(target.policy.context, maximum_log_records=1),
        ),
    )
    engine.registry.register(changed_target)

    with pytest.raises(OperationContextStaleError, match="policy_fingerprint"):
        engine.approve_repair(pending[0].episode_id)
    assert target.slot.load().number == 0
