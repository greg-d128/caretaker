from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from caretaker import (
    EffectObservation,
    FunctionExecutionContract,
    InMemoryRepairStore,
    ObservationPolicy,
    RepairRolloutAuthority,
    RepairRolloutError,
    RepairRolloutExecutionError,
    RepairRolloutLedger,
    RepairRolloutPolicy,
    RepairRolloutStage,
    RolloutRoutingPolicy,
    decide_rollout_routing,
    execute_rollout,
    execute_slot_rollout,
)
from caretaker.domain import ReplaySafety, SideEffectClass
from caretaker.observation import ObservationManager
from caretaker.slot import FunctionSlot


def _ledger(**routing_changes: int) -> RepairRolloutLedger:
    return RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(**routing_changes),
        )
    )


def _record(ledger: RepairRolloutLedger):
    return ledger.create(
        target_id="example.target",
        incident_id=uuid4(),
        candidate_id=uuid4(),
        candidate_source_hash="candidate-hash",
        base_source_hash="base-hash",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        proposed_by="advisory-engine",
    )


def _advance(ledger: RepairRolloutLedger, record, stage: RepairRolloutStage):
    return ledger.advance(
        record.rollout_id,
        to_stage=stage,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason=f"advance to {stage.value}",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        validation_evidence_hash=("evidence-hash" if stage is RepairRolloutStage.VALIDATED else None),
    )


def _decide(ledger: RepairRolloutLedger, record, *, scope: str = "tenant", key: str = "tenant-1"):
    return decide_rollout_routing(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope=scope,
        routing_key=key,
    )


def _pure_contract() -> FunctionExecutionContract:
    return FunctionExecutionContract(
        side_effects=SideEffectClass.PURE,
        retry_safety=ReplaySafety.PURE,
    )


def _slot_and_record(ledger: RepairRolloutLedger):
    candidate_id = uuid4()
    slot = FunctionSlot(
        target_id="example.target",
        original=lambda value: value,
        original_source="deployed-source",
        original_source_hash="base-hash",
        execution_contract=_pure_contract(),
    )
    lease = slot.begin_repair()
    slot.activate(
        lease=lease,
        implementation=lambda value: value + 1,
        source="candidate-source",
        source_hash="candidate-hash",
        repair_attempt_id=uuid4(),
        candidate_id=candidate_id,
    )
    record = ledger.create(
        target_id="example.target",
        incident_id=uuid4(),
        candidate_id=candidate_id,
        candidate_source_hash="candidate-hash",
        base_source_hash="base-hash",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        proposed_by="advisory-engine",
    )
    return slot, record


def _execute(ledger: RepairRolloutLedger, record, deployed, candidate, **kwargs):
    return execute_rollout(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        deployed=deployed,
        candidate=candidate,
        args=(4,),
        kwargs={},
        contract=_pure_contract(),
        effect_observation=EffectObservation(complete=True),
        **kwargs,
    )


def test_shadow_selection_is_non_authoritative_and_stable() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    record = _advance(ledger, _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED), RepairRolloutStage.SHADOW)

    first = _decide(ledger, record)
    second = _decide(ledger, record)

    assert first.candidate_selected is True
    assert first.candidate_authoritative is False
    assert first.authoritative_implementation.value == "deployed"
    assert first.strategy == "shadow"
    assert first == second
    assert "tenant-1" not in first.routing_key_digest


def test_execute_rollout_shadow_returns_deployed_result() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    record = _advance(ledger, _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED), RepairRolloutStage.SHADOW)
    calls: list[str] = []

    result = _execute(
        ledger,
        record,
        lambda value: calls.append("deployed") or value,
        lambda value: calls.append("candidate") or value + 1,
    )

    assert result.result == 4
    assert result.candidate_executed is True
    assert result.candidate_authoritative is False
    assert result.shadow_result is not None
    assert calls == ["deployed", "candidate"]


def test_execute_rollout_canary_invokes_only_authoritative_candidate() -> None:
    ledger = _ledger(canary_percentage=100)
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    calls: list[str] = []

    result = _execute(
        ledger,
        record,
        lambda value: calls.append("deployed") or value,
        lambda value: calls.append("candidate") or value + 1,
    )

    assert result.result == 5
    assert result.candidate_executed is True
    assert result.candidate_authoritative is True
    assert result.shadow_result is None
    assert calls == ["candidate"]


def test_execute_rollout_zero_canary_percentage_keeps_deployed_path() -> None:
    ledger = _ledger(canary_percentage=0)
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    calls: list[str] = []

    result = _execute(
        ledger,
        record,
        lambda value: calls.append("deployed") or value,
        lambda value: calls.append("candidate") or value + 1,
    )

    assert result.result == 4
    assert result.candidate_executed is False
    assert result.candidate_authoritative is False
    assert calls == ["deployed"]


def test_execute_slot_rollout_binds_previous_and_current_versions() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    slot, record = _slot_and_record(ledger)
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.SHADOW)
    version_before = slot.load().number

    result = execute_slot_rollout(
        slot,
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        args=(4,),
        kwargs={},
        effect_observation=EffectObservation(complete=True),
    )

    assert result.result == 4
    assert result.shadow_result is not None
    assert result.shadow_result.candidate_result == 5
    assert result.candidate_authoritative is False
    assert slot.load().number == version_before


def test_execute_slot_rollout_rejects_stale_candidate_binding() -> None:
    ledger = _ledger(canary_percentage=100)
    slot, record = _slot_and_record(ledger)
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    with pytest.raises(RepairRolloutExecutionError, match="source"):
        execute_slot_rollout(
            slot,
            replace(record, candidate_source_hash="different-hash"),
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            args=(4,),
            kwargs={},
        )


def test_execute_slot_rollout_counts_only_authoritative_candidate_calls() -> None:
    ledger = _ledger(canary_percentage=100)
    slot, record = _slot_and_record(ledger)
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)
    store = InMemoryRepairStore()
    manager = ObservationManager(store)

    result = execute_slot_rollout(
        slot,
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        args=(4,),
        kwargs={},
        observation_manager=manager,
        observation_policy=ObservationPolicy(),
        call_id=uuid4(),
    )

    assert result.result == 5
    assert slot.observation() is not None
    assert slot.observation().successful_executions == 1
    assert len(store.observations) == 1
    observation = next(iter(store.observations.values()))
    assert observation.mode == "canary"
    assert observation.rollout_id == record.rollout_id
    assert observation.routing_decision_hash == result.decision.decision_hash


def test_execute_slot_rollout_does_not_count_shadow_as_acceptance() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    slot, record = _slot_and_record(ledger)
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.SHADOW)
    store = InMemoryRepairStore()
    manager = ObservationManager(store)

    result = execute_slot_rollout(
        slot,
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        args=(4,),
        kwargs={},
        effect_observation=EffectObservation(complete=True),
        observation_manager=manager,
        observation_policy=ObservationPolicy(),
        call_id=uuid4(),
    )

    assert result.result == 4
    assert slot.observation() is not None
    assert slot.observation().successful_executions == 0
    assert store.observations == {}


def test_execute_slot_rollout_applies_existing_failure_rollback_policy() -> None:
    ledger = _ledger(canary_percentage=100)
    candidate_id = uuid4()
    slot = FunctionSlot(
        target_id="example.target",
        original=lambda value: value,
        original_source_hash="base-hash",
        execution_contract=_pure_contract(),
    )
    lease = slot.begin_repair()

    def failing_candidate(value: int) -> int:
        raise ValueError(f"bad candidate: {value}")

    slot.activate(
        lease=lease,
        implementation=failing_candidate,
        source="candidate-source",
        source_hash="candidate-hash",
        repair_attempt_id=uuid4(),
        candidate_id=candidate_id,
    )
    record = ledger.create(
        target_id="example.target",
        incident_id=uuid4(),
        candidate_id=candidate_id,
        candidate_source_hash="candidate-hash",
        base_source_hash="base-hash",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        proposed_by="advisory-engine",
    )
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)
    store = InMemoryRepairStore()

    with pytest.raises(ValueError, match="bad candidate"):
        execute_slot_rollout(
            slot,
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            args=(4,),
            kwargs={},
            observation_manager=ObservationManager(store),
            observation_policy=ObservationPolicy(),
            call_id=uuid4(),
        )

    assert slot.load().number == 0
    assert len(store.observations) == 1
    failure = next(iter(store.observations.values()))
    assert failure.counted_as_failure is True
    assert failure.comparison["rolled_back"] is True
    assert failure.rollout_id == record.rollout_id


def test_canary_and_active_field_repair_can_select_candidate_explicitly() -> None:
    ledger = _ledger(canary_percentage=100, active_candidate_percentage=100)
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)

    canary = _advance(ledger, validated, RepairRolloutStage.CANARY)
    canary_decision = _decide(ledger, canary)
    assert canary_decision.candidate_selected is True
    assert canary_decision.candidate_authoritative is True
    assert canary_decision.authoritative_implementation.value == "candidate"

    active = _advance(ledger, canary, RepairRolloutStage.ACTIVE)
    active_decision = _decide(ledger, active)
    assert active_decision.candidate_selected is True
    assert active_decision.candidate_authoritative is True


def test_permanent_active_record_remains_deployed_authoritative() -> None:
    ledger = _ledger(active_candidate_percentage=100)
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    active = _advance(ledger, validated, RepairRolloutStage.ACTIVE)
    permanent = ledger.promote_permanent(
        active.rollout_id,
        authority_id="deployment-1",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        deployment_artifact_hash="deployment-hash",
        reason="accept deployment",
    )

    decision = _decide(ledger, permanent)
    assert decision.candidate_selected is False
    assert decision.candidate_authoritative is False
    assert decision.authoritative_implementation.value == "deployed"
    assert decision.reason.startswith("permanent deployment")


def test_routing_scope_changes_population_without_disclosing_key() -> None:
    ledger = _ledger(shadow_sample_percentage=50)
    record = _record(ledger)
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.SHADOW)

    tenant = _decide(ledger, record, scope="tenant")
    session = _decide(ledger, record, scope="session")
    assert tenant.routing_key_digest != session.routing_key_digest
    assert tenant.decision_hash != session.decision_hash


def test_routing_decision_can_emit_bounded_audit_evidence() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.SHADOW)
    events: list[tuple[str, dict]] = []

    decision = decide_rollout_routing(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        audit_event=lambda name, **fields: events.append((name, fields)),
    )

    assert len(events) == 1
    name, fields = events[0]
    assert name == "REPAIR_ROLLOUT_ROUTING_DECISION"
    assert fields["scope"]["routing_key_digest"] == decision.routing_key_digest
    assert "tenant-1" not in str(fields)
    assert fields["outcome"]["candidate_authoritative"] is False


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"canary_percentage": -1}, "from 0 through 100"),
        ({"active_candidate_percentage": 101}, "from 0 through 100"),
        ({"bucket_count": 99}, "bucket_count"),
    ],
)
def test_routing_policy_rejects_invalid_percentages_and_buckets(kwargs, message) -> None:
    with pytest.raises(ValueError, match=message):
        RolloutRoutingPolicy(**kwargs)


def test_routing_rejects_stale_context_and_terminal_rollouts() -> None:
    ledger = _ledger()
    record = _record(ledger)

    with pytest.raises(RepairRolloutError, match="stale"):
        decide_rollout_routing(
            record,
            policy=ledger.policy,
            policy_fingerprint="different-policy",
            routing_scope="tenant",
            routing_key="tenant-1",
        )

    retired = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    retired = _advance(ledger, retired, RepairRolloutStage.ACTIVE)
    retired = _advance(ledger, retired, RepairRolloutStage.RETIRED)
    with pytest.raises(RepairRolloutError, match="terminal"):
        _decide(ledger, retired)
