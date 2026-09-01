from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from caretaker import (
    EffectObservation,
    FunctionExecutionContract,
    InMemoryRepairStore,
    ObservationPolicy,
    RepairEngine,
    RepairRolloutAuthority,
    RepairRolloutCoordinator,
    RepairRolloutError,
    RepairRolloutExecutionError,
    RepairRolloutLedger,
    RepairRolloutPolicy,
    RepairRolloutStage,
    RolloutFailureAction,
    RepairPolicy,
    RolloutReadinessRequirements,
    RolloutRampPolicy,
    RolloutRampStep,
    RolloutRoutingPolicy,
    RolloutStageReadiness,
    SQLiteRepairStore,
    ShadowExecutionError,
    decide_rollout_routing,
    execute_rollout,
    execute_slot_rollout,
    repair,
    summarize_rollout_executions,
)
from caretaker.domain import ReplaySafety, SideEffectClass
from caretaker.observation import ObservationManager
from caretaker.registry import build_target
from caretaker.run import (
    _handle_rollout_advance_request,
    _handle_rollout_pause_request,
    _handle_rollout_percentage_request,
)
from caretaker.repair_rollout import _coerce_record
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


def _engine_slot_and_record(
    ledger: RepairRolloutLedger,
    final_stage: RepairRolloutStage = RepairRolloutStage.CANARY,
):
    store = InMemoryRepairStore()
    engine = RepairEngine(store=store)

    def deployed(value: int) -> int:
        return value

    target = build_target(
        deployed,
        policy=RepairPolicy(rollout=ledger.policy),
        target_id="example.target",
        execution_contract=_pure_contract(),
    )
    engine.register(target)
    candidate_id = uuid4()
    lease = target.slot.begin_repair()
    target.slot.activate(
        lease=lease,
        implementation=lambda value: value + 1,
        source="candidate-source",
        source_hash="candidate-hash",
        repair_attempt_id=uuid4(),
        candidate_id=candidate_id,
    )
    record = ledger.create(
        target_id=target.target_id,
        incident_id=uuid4(),
        candidate_id=candidate_id,
        candidate_source_hash="candidate-hash",
        base_source_hash=target.slot.previous().source_hash,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        proposed_by="advisory-engine",
    )
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    return engine, target, store, _advance(ledger, record, final_stage)


def _execute(ledger: RepairRolloutLedger, record, deployed, candidate, **kwargs):
    contract = kwargs.pop("contract", _pure_contract())
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
        contract=contract,
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


def test_candidate_authoritative_mirror_returns_candidate_and_records_comparison() -> None:
    ledger = _ledger(canary_percentage=100, candidate_mirror_percentage=100)
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )
    calls: list[str] = []
    store = InMemoryRepairStore()

    result = _execute(
        ledger,
        record,
        lambda value: calls.append("deployed") or value,
        lambda value: calls.append("candidate") or value + 1,
        execution_store=store,
    )

    assert result.result == 5
    assert result.candidate_authoritative is True
    assert result.decision.mirror_selected is True
    assert result.mirror_result is not None
    assert result.mirror_result.candidate_authoritative is True
    assert result.mirror_result.candidate_result == 5
    assert result.mirror_result.deployed_result == 4
    assert result.mirror_result.deployed_succeeded is True
    assert result.mirror_result.equivalent is False
    assert calls == ["candidate", "deployed"]
    observation = result.execution_observation
    assert observation is not None
    assert observation.mirror_executed is True
    assert observation.mirror_deployed_succeeded is True
    assert observation.mirror_equivalent is False
    summary = summarize_rollout_executions(
        record,
        store.all_rollout_executions(),
        policy_fingerprint="policy-hash",
    )
    assert summary.mirror_count == 1
    assert summary.mirror_mismatch_count == 1


def test_candidate_authoritative_mirror_requires_isolation_for_uncertain_effects() -> None:
    ledger = _ledger(canary_percentage=100, candidate_mirror_percentage=100)
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )
    calls: list[str] = []

    with pytest.raises(ShadowExecutionError, match="contract"):
        _execute(
            ledger,
            record,
            lambda value: calls.append("deployed") or value,
            lambda value: calls.append("candidate") or value + 1,
            contract=FunctionExecutionContract(
                side_effects=SideEffectClass.UNKNOWN,
                retry_safety=ReplaySafety.UNKNOWN,
            ),
        )

    assert calls == []


def test_candidate_authoritative_mirror_retains_candidate_when_deployed_comparison_fails() -> None:
    ledger = _ledger(canary_percentage=100, candidate_mirror_percentage=100)
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )

    def deployed(value: int) -> int:
        raise LookupError("comparison failure")

    result = _execute(ledger, record, deployed, lambda value: value + 1)

    assert result.result == 5
    assert result.candidate_authoritative is True
    assert result.mirror_result is not None
    assert result.mirror_result.deployed_succeeded is False
    assert isinstance(result.mirror_result.deployed_exception, LookupError)
    assert result.execution_observation is not None
    assert result.execution_observation.execution_state == "COMPLETED"
    assert result.execution_observation.mirror_deployed_exception_type == "LookupError"


def test_execute_rollout_can_derive_effect_gate_from_behavior_capture() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.SHADOW,
    )

    with pytest.raises(ShadowExecutionError, match="conflicts"):
        execute_rollout(
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            deployed=lambda value: value,
            candidate=lambda value: value + 1,
            args=(4,),
            kwargs={},
            contract=FunctionExecutionContract(side_effects=SideEffectClass.PURE),
            behavior_capture={
                "profile": {"network_destinations": ["api.example:443"]}
            },
            behavior_capture_complete=True,
        )


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


def test_execute_rollout_can_explicitly_fallback_to_deployed_for_pure_candidate() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            candidate_failure_action=RolloutFailureAction.FALLBACK_TO_DEPLOYED,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        )
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def candidate(value: int) -> int:
        raise RuntimeError(f"candidate secret: {value}")

    result = execute_rollout(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        deployed=lambda value: value,
        candidate=candidate,
        args=(4,),
        kwargs={},
        contract=_pure_contract(),
        effect_observation=EffectObservation(complete=True),
        audit_event=lambda *args, **kwargs: events.append((args, kwargs)),
    )

    assert result.result == 4
    assert result.fallback_used is True
    assert result.candidate_authoritative is False
    assert result.candidate_succeeded is False
    assert result.execution_observation is not None
    assert result.execution_observation.fallback_used is True
    assert result.execution_observation.exception_type == "RuntimeError"
    assert result.execution_observation.authoritative_implementation.value == "deployed"
    assert result.execution_observation.candidate_authoritative is False
    summary = summarize_rollout_executions(
        record,
        [result.execution_observation],
        policy_fingerprint="policy-hash",
    )
    assert summary.observation_count == 1
    assert summary.fallback_count == 1
    assert any(
        kwargs["outcome"]["state"] == "FALLBACK_SUCCEEDED"
        for _, kwargs in events
    )
    fallback_event = next(
        kwargs for _, kwargs in events
        if kwargs["outcome"]["state"] == "FALLBACK_SUCCEEDED"
    )
    assert fallback_event["outcome"]["fallback_used"] is True


def test_rollout_fallback_rejects_non_pure_contract() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            candidate_failure_action=RolloutFailureAction.FALLBACK_TO_DEPLOYED,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        )
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    with pytest.raises(RepairRolloutExecutionError, match="PURE"):
        execute_rollout(
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            deployed=lambda value: value,
            candidate=lambda value: (_ for _ in ()).throw(RuntimeError("failed")),
            args=(4,),
            kwargs={},
            contract=FunctionExecutionContract(side_effects=SideEffectClass.READ_ONLY),
            effect_observation=EffectObservation(complete=True),
        )


def test_rollout_can_fallback_for_read_only_contract_with_complete_effect_evidence() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            candidate_failure_action=RolloutFailureAction.FALLBACK_TO_DEPLOYED,
            allow_read_only_candidate_fallback=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        )
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    result = execute_rollout(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        deployed=lambda value: value,
        candidate=lambda value: (_ for _ in ()).throw(RuntimeError("candidate failed")),
        args=(4,),
        kwargs={},
        contract=FunctionExecutionContract(
            side_effects=SideEffectClass.READ_ONLY,
            retry_safety=ReplaySafety.IDEMPOTENT,
        ),
        effect_observation=EffectObservation(
            categories=("filesystem",),
            event_kinds=("FILE_READ",),
            event_count=1,
            complete=True,
        ),
    )

    assert result.result == 4
    assert result.fallback_used is True
    assert result.candidate_succeeded is False


def test_rollout_read_only_fallback_rejects_incomplete_effect_evidence() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            candidate_failure_action=RolloutFailureAction.FALLBACK_TO_DEPLOYED,
            allow_read_only_candidate_fallback=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        )
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    with pytest.raises(RepairRolloutExecutionError, match="complete effect evidence"):
        execute_rollout(
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            deployed=lambda value: value,
            candidate=lambda value: (_ for _ in ()).throw(RuntimeError("candidate failed")),
            args=(4,),
            kwargs={},
            contract=FunctionExecutionContract(side_effects=SideEffectClass.READ_ONLY),
            effect_observation=EffectObservation(complete=False),
        )


def test_rollout_fallback_rejects_observed_external_effects() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            candidate_failure_action=RolloutFailureAction.FALLBACK_TO_DEPLOYED,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        )
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    with pytest.raises(RepairRolloutExecutionError, match="externally visible effects"):
        execute_rollout(
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            deployed=lambda value: value,
            candidate=lambda value: (_ for _ in ()).throw(RuntimeError("failed")),
            args=(4,),
            kwargs={},
            contract=_pure_contract(),
            effect_observation=EffectObservation(
                complete=True,
                externally_visible_categories=("network",),
            ),
        )


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


def test_engine_invokes_registered_slot_rollout_and_records_observation() -> None:
    ledger = _ledger(canary_percentage=100)
    engine, target, store, record = _engine_slot_and_record(ledger)

    result = engine.invoke_rollout(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        args=(4,),
        effect_observation=EffectObservation(complete=True),
    )

    assert result.result == 5
    assert result.candidate_authoritative is True
    assert target.slot.observation() is not None
    assert target.slot.observation().successful_executions == 1
    assert len(store.observations) == 1


def test_engine_rollout_bridge_keeps_shadow_result_non_authoritative() -> None:
    ledger = _ledger(shadow_sample_percentage=100)
    engine, target, store, record = _engine_slot_and_record(
        ledger, final_stage=RepairRolloutStage.SHADOW
    )

    result = engine.invoke_rollout(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
        args=(4,),
        effect_observation=EffectObservation(complete=True),
    )

    assert result.result == 4
    assert result.shadow_result is not None
    assert result.shadow_result.candidate_result == 5
    assert result.candidate_authoritative is False
    assert target.slot.observation().successful_executions == 0
    assert store.observations == {}


def test_engine_rollout_bridge_rejects_unregistered_target() -> None:
    ledger = _ledger(canary_percentage=100)
    engine = RepairEngine()
    record = _record(ledger)

    with pytest.raises(KeyError, match="not registered"):
        engine.invoke_rollout(
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
            args=(4,),
        )


def test_engine_binds_rollout_to_callable_with_fresh_record_and_key() -> None:
    ledger = _ledger(canary_percentage=100)
    engine, target, store, record = _engine_slot_and_record(ledger)
    provider_calls: list[str] = []

    bound = engine.bind_rollout(
        lambda: provider_calls.append("loaded") or record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key=lambda args, kwargs: f"tenant-{args[0]}",
        effect_observation=EffectObservation(complete=True),
    )

    result = bound(4)

    assert result.result == 5
    assert provider_calls == ["loaded"]
    assert target.slot.observation().successful_executions == 1
    assert len(store.observations) == 1


def test_engine_binds_rollout_callable_with_existing_raw_result_contract() -> None:
    ledger = _ledger(canary_percentage=100)
    store = InMemoryRepairStore()
    engine = RepairEngine(store=store)

    def deployed(value: int) -> int:
        return value

    wrapped = repair(
        policy=RepairPolicy(rollout=ledger.policy),
        engine=engine,
        target_id="example.decorated-target",
        execution_contract=_pure_contract(),
    )(deployed)
    target = wrapped.__caretaker_target__
    candidate_id = uuid4()
    lease = target.slot.begin_repair()
    target.slot.activate(
        lease=lease,
        implementation=lambda value: value + 1,
        source="candidate-source",
        source_hash="candidate-hash",
        repair_attempt_id=uuid4(),
        candidate_id=candidate_id,
    )
    record = ledger.create(
        target_id=target.target_id,
        incident_id=uuid4(),
        candidate_id=candidate_id,
        candidate_source_hash="candidate-hash",
        base_source_hash=target.slot.previous().source_hash,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        proposed_by="advisory-engine",
    )
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    routed = engine.bind_rollout_callable(
        wrapped,
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key=lambda args, kwargs: f"tenant-{args[0]}",
        effect_observation=EffectObservation(complete=True),
    )

    assert routed(4) == 5
    assert routed.__name__ == deployed.__name__
    assert routed.__caretaker_rollout_bound__ is True
    assert target.slot.observation() is not None
    assert target.slot.observation().successful_executions == 1


def test_engine_rejects_rollout_binding_for_an_unrelated_callable() -> None:
    ledger = _ledger(canary_percentage=100)
    engine, _target, _store, record = _engine_slot_and_record(ledger)

    with pytest.raises(ValueError, match="decorated by this engine"):
        engine.bind_rollout_callable(
            lambda value: value,
            record,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
        )


def test_engine_rollout_binding_rejects_empty_resolved_key() -> None:
    ledger = _ledger(canary_percentage=100)
    engine, _target, _store, record = _engine_slot_and_record(ledger)
    bound = engine.bind_rollout(
        record,
        policy=ledger.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key=lambda args, kwargs: "",
    )

    with pytest.raises(ValueError, match="non-empty"):
        bound(4)


def test_execute_slot_rollout_can_require_supervisor_worker_context() -> None:
    ledger = _ledger(canary_percentage=100)
    slot, record = _slot_and_record(ledger)
    record = _advance(ledger, record, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    common = {
        "policy": ledger.policy,
        "policy_fingerprint": "policy-hash",
        "routing_scope": "tenant",
        "routing_key": "tenant-1",
        "args": (4,),
        "kwargs": {},
        "effect_observation": EffectObservation(complete=True),
        "coordinator": coordinator,
        "worker_id": "worker-1",
        "worker_process_id": 321,
    }
    with pytest.raises(PermissionError, match="acknowledged"):
        execute_slot_rollout(slot, record, **common)

    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-1",
        worker_process_id=321,
    )
    result = execute_slot_rollout(slot, record, **common)
    assert result.result == 5
    assert result.candidate_authoritative is True


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


def test_execute_slot_rollout_records_allowed_fallback_as_candidate_failure() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            candidate_failure_action=RolloutFailureAction.FALLBACK_TO_DEPLOYED,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        )
    )
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
        observation_manager=ObservationManager(store),
        observation_policy=ObservationPolicy(rollback_during_probation=False),
        call_id=uuid4(),
    )

    assert result.result == 4
    assert result.fallback_used is True
    assert slot.observation() is not None
    assert slot.observation().successful_executions == 0
    assert slot.observation().failed_executions == 1
    assert len(store.observations) == 1
    failure = next(iter(store.observations.values()))
    assert failure.counted_as_failure is True


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


def test_execute_rollout_emits_bounded_success_outcome() -> None:
    ledger = _ledger(canary_percentage=100)
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    events: list[tuple[str, dict]] = []

    result = _execute(
        ledger,
        record,
        lambda value: value,
        lambda value: "secret-result",
        audit_event=lambda name, **fields: events.append((name, fields)),
    )

    assert result.result == "secret-result"
    assert [name for name, _ in events] == [
        "REPAIR_ROLLOUT_ROUTING_DECISION",
        "REPAIR_ROLLOUT_EXECUTION_OUTCOME",
    ]
    outcome = events[1][1]
    assert outcome["outcome"]["state"] == "COMPLETED"
    assert outcome["outcome"]["candidate_authoritative"] is True
    assert "secret-result" not in str(outcome)


def test_execute_rollout_persists_bounded_execution_observation() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    execution_id = uuid4()

    result = _execute(
        ledger,
        record,
        lambda value: value,
        lambda value: "secret-result",
        execution_store=store,
        execution_id=execution_id,
    )

    observation = result.execution_observation
    assert observation is not None
    assert observation.observation_id == execution_id
    assert observation.rollout_id == record.rollout_id
    assert observation.candidate_id == record.candidate_id
    assert observation.execution_state == "COMPLETED"
    assert observation.candidate_authoritative is True
    assert observation.candidate_succeeded is True
    assert observation.exception_type is None
    assert len(store.all_rollout_executions()) == 1
    assert "secret-result" not in repr(observation)

    summary = ledger.execution_summary(
        record.rollout_id,
        policy_fingerprint="policy-hash",
    )
    assert summary.observation_count == 1
    assert summary.completed_count == 1
    assert summary.failed_count == 0
    assert summary.candidate_execution_count == 1
    assert summary.candidate_authoritative_count == 1
    assert summary.candidate_success_count == 1
    assert summary.stage_counts == {"canary": 1}
    assert summary.invalid_observation_count == 0

    store.record_rollout_execution(
        replace(
            observation,
            observation_id=uuid4(),
            content_hash="tampered",
        )
    )
    summary = ledger.execution_summary(
        record.rollout_id,
        policy_fingerprint="policy-hash",
    )
    assert summary.observation_count == 1
    assert summary.invalid_observation_count == 1


def test_sqlite_rollout_execution_observation_round_trip(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)

    result = _execute(
        ledger,
        record,
        lambda value: value,
        lambda value: "secret-result",
        execution_store=store,
        execution_id=uuid4(),
    )

    observation = result.execution_observation
    assert observation is not None
    persisted = store.all_rollout_executions()
    assert len(persisted) == 1
    assert persisted[0]["rollout_id"] == str(record.rollout_id)
    assert persisted[0]["candidate_id"] == str(record.candidate_id)
    assert persisted[0]["execution_state"] == "COMPLETED"
    assert "secret-result" not in str(persisted[0])
    summary = ledger.execution_summary(
        record.rollout_id,
        policy_fingerprint="policy-hash",
    )
    assert summary.observation_count == 1
    assert summary.stage_counts == {"canary": 1}


def test_sqlite_routing_percentage_update_survives_restart(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    policy = RepairRolloutPolicy(
        enabled=True,
        allow_operator_routing_changes=True,
        allow_operator_routing_increases=True,
        require_readiness_for_routing_increase=False,
        routing=RolloutRoutingPolicy(canary_percentage=10),
    )
    ledger = RepairRolloutLedger(policy=policy, store=store)
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    updated = ledger.update_routing_percentages(
        record.rollout_id,
        shadow_sample_percentage=40,
        canary_percentage=30,
        active_candidate_percentage=90,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="persist reviewed routing change",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )

    reopened = RepairRolloutLedger(policy=policy, store=store)
    persisted = reopened.get(updated.rollout_id)
    assert persisted.routing_policy == updated.routing_policy
    assert reopened.transitions(updated.rollout_id)[-1].details["new_routing"][
        "active_candidate_percentage"
    ] == 90
    shadow = _advance(reopened, persisted, RepairRolloutStage.SHADOW)
    assert _decide(reopened, shadow).configured_percentage == 40


def test_rollout_execution_summary_counts_candidate_failures_without_messages() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)

    def failing_candidate(value: int) -> int:
        raise RuntimeError(f"secret failure {value}")

    with pytest.raises(RuntimeError, match="secret failure"):
        _execute(
            ledger,
            record,
            lambda value: value,
            failing_candidate,
            execution_store=store,
            execution_id=uuid4(),
        )

    summary = ledger.execution_summary(
        record.rollout_id,
        policy_fingerprint="policy-hash",
    )
    assert summary.observation_count == 1
    assert summary.failed_count == 1
    assert summary.candidate_authoritative_count == 1
    assert summary.candidate_failure_count == 1
    assert "secret failure" not in str(store.all_rollout_executions()[0])


def test_rollout_operator_projection_is_bounded_and_read_only() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    proposed = _record(ledger)
    validated = _advance(ledger, proposed, RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    _execute(
        ledger,
        record,
        lambda value: value,
        lambda value: value + 1,
        execution_store=store,
        execution_id=uuid4(),
    )
    before = ledger.get(record.rollout_id)

    projection = ledger.operator_projection(
        policy_fingerprint="policy-hash",
        rollout_id=record.rollout_id,
        limit=1,
        transition_limit=2,
    )

    assert projection["read_only"] is True
    assert projection["authority_granted"] is False
    assert len(projection["records"]) == 1
    projected = projection["records"][0]
    assert projected["rollout_id"] == str(record.rollout_id)
    assert projected["stage"] == "canary"
    assert projected["execution_summary_status"] == "AVAILABLE"
    assert projected["execution_summary"]["completed_count"] == 1
    assert len(projection["transitions"]) == 2
    assert ledger.get(record.rollout_id) == before


def test_rollout_operator_projection_surfaces_stale_policy_evidence() -> None:
    ledger = _ledger(canary_percentage=100)
    record = _record(ledger)

    projection = ledger.operator_projection(policy_fingerprint="new-policy-hash")

    assert projection["records"][0]["execution_summary"] is None
    assert projection["records"][0]["execution_summary_status"] == "STALE_OR_UNAVAILABLE"
    assert "stale" in projection["records"][0]["execution_summary_reason"]


def test_supervisor_rollout_coordinator_requires_current_worker_ack() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    with pytest.raises(PermissionError, match="not acknowledged"):
        coordinator.route(
            rollout_id=record.rollout_id,
            worker_id="worker-a",
            worker_process_id=101,
            routing_scope="tenant",
            routing_key="tenant-1",
        )

    acknowledgement = coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=101,
    )
    assert acknowledgement.stage is RepairRolloutStage.CANARY
    assert acknowledgement.routing_policy_fingerprint
    decision = coordinator.route(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=101,
        routing_scope="tenant",
        routing_key="tenant-1",
    )
    assert decision.candidate_authoritative is True
    status = coordinator.status(record.rollout_id)
    assert status["rollouts"][0]["current_worker_count"] == 1
    assert status["rollouts"][0]["stale_acknowledgement_count"] == 0
    assert status["rollouts"][0]["execution_evidence"]["status"] == "AVAILABLE"
    assert status["rollouts"][0]["execution_evidence"]["summary"]["observation_count"] == 0

    _advance(ledger, record, RepairRolloutStage.ACTIVE)
    with pytest.raises(PermissionError, match="not acknowledged"):
        coordinator.route(
            rollout_id=record.rollout_id,
            worker_id="worker-a",
            worker_process_id=101,
            routing_scope="tenant",
            routing_key="tenant-1",
        )
    status = coordinator.status(record.rollout_id)
    assert status["rollouts"][0]["current_worker_count"] == 0
    assert status["rollouts"][0]["stale_acknowledgement_count"] == 1


def test_application_wide_route_allocations_are_shared_idempotent_and_bounded() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=50, bucket_count=100),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=401,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-b",
        worker_process_id=402,
    )

    first_id = uuid4()
    first = coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=401,
        routing_scope="tenant",
        routing_key="tenant-1",
        assignment_id=first_id,
    )
    second = coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-b",
        worker_process_id=402,
        routing_scope="tenant",
        routing_key="tenant-2",
        assignment_id=uuid4(),
    )
    assert first.assignment.sequence == 0
    assert second.assignment.sequence == 1
    assert first.decision.application_assignment_id == first_id
    assert first.decision.candidate_authoritative is True
    assert second.decision.candidate_authoritative is True

    repeated = coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=401,
        routing_scope="tenant",
        routing_key="tenant-1",
        assignment_id=first_id,
    )
    assert repeated.assignment == first.assignment
    assert repeated.decision == first.decision
    assert len(store.all_rollout_application_routes()) == 2

    for index in range(48):
        coordinator.route_application_wide(
            rollout_id=record.rollout_id,
            worker_id="worker-a",
            worker_process_id=401,
            routing_scope="tenant",
            routing_key=f"tenant-extra-{index}",
            assignment_id=uuid4(),
        )
    boundary = coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-b",
        worker_process_id=402,
        routing_scope="tenant",
        routing_key="tenant-boundary",
        assignment_id=uuid4(),
    )
    assert boundary.assignment.sequence == 50
    assert boundary.decision.candidate_authoritative is False
    status = coordinator.status(record.rollout_id)["rollouts"][0]["application_routing"]
    assert status["assignment_count"] == 51
    assert status["candidate_authoritative_count"] == 50
    assert status["cross_host_coordination"] is False


def test_application_wide_routes_survive_coordinator_restart(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=501,
    )
    first_id = uuid4()
    first = coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=501,
        routing_scope="tenant",
        routing_key="tenant-1",
        assignment_id=first_id,
    )

    reopened_ledger = RepairRolloutLedger(policy=ledger.policy, store=store)
    reopened = RepairRolloutCoordinator(
        reopened_ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    repeated = reopened.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=501,
        routing_scope="tenant",
        routing_key="tenant-1",
        assignment_id=first_id,
    )
    next_route = reopened.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=501,
        routing_scope="tenant",
        routing_key="tenant-2",
        assignment_id=uuid4(),
    )
    assert repeated.assignment == first.assignment
    assert next_route.assignment.sequence == 1
    assert len(store.all_rollout_application_routes()) == 2


def test_execute_rollout_uses_application_wide_supervisor_assignment() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=601,
    )
    assignment_id = uuid4()

    result = _execute(
        ledger,
        record,
        lambda value: value,
        lambda value: value + 1,
        coordinator=coordinator,
        worker_id="worker-a",
        worker_process_id=601,
        application_wide_routing=True,
        routing_assignment_id=assignment_id,
    )

    assert result.result == 5
    assert result.decision.application_assignment_id == assignment_id
    assert result.candidate_authoritative is True
    assert len(store.all_rollout_application_routes()) == 1


def test_application_wide_route_replay_is_bound_to_worker_and_key() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=701,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-b",
        worker_process_id=702,
    )
    assignment_id = uuid4()
    coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=701,
        routing_scope="tenant",
        routing_key="tenant-1",
        assignment_id=assignment_id,
    )

    with pytest.raises(PermissionError, match="another worker"):
        coordinator.route_application_wide(
            rollout_id=record.rollout_id,
            worker_id="worker-b",
            worker_process_id=702,
            routing_scope="tenant",
            routing_key="tenant-1",
            assignment_id=assignment_id,
        )
    with pytest.raises(RepairRolloutError, match="key does not match"):
        coordinator.route_application_wide(
            rollout_id=record.rollout_id,
            worker_id="worker-a",
            worker_process_id=701,
            routing_scope="tenant",
            routing_key="tenant-2",
            assignment_id=assignment_id,
        )


def test_application_wide_route_replay_is_invalidated_by_routing_policy_change() -> None:
    store = InMemoryRepairStore()
    policy = RepairRolloutPolicy(
        enabled=True,
        allow_operator_routing_changes=True,
        routing=RolloutRoutingPolicy(canary_percentage=100),
    )
    ledger = RepairRolloutLedger(policy=policy, store=store)
    record = _advance(
        ledger,
        _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED),
        RepairRolloutStage.CANARY,
    )
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=801,
    )
    assignment_id = uuid4()
    coordinator.route_application_wide(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=801,
        routing_scope="tenant",
        routing_key="tenant-1",
        assignment_id=assignment_id,
    )
    updated = ledger.update_routing_percentages(
        record.rollout_id,
        shadow_sample_percentage=0,
        canary_percentage=99,
        active_candidate_percentage=0,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="reduce canary allocation",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    coordinator.acknowledge_worker(
        rollout_id=updated.rollout_id,
        worker_id="worker-a",
        worker_process_id=801,
    )

    with pytest.raises(RepairRolloutError, match="stale"):
        coordinator.route_application_wide(
            rollout_id=updated.rollout_id,
            worker_id="worker-a",
            worker_process_id=801,
            routing_scope="tenant",
            routing_key="tenant-1",
            assignment_id=assignment_id,
        )


def test_rollout_coordinator_does_not_treat_missing_execution_store_as_progress() -> None:
    ledger = _ledger()
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    status = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    ).status(record.rollout_id)

    assert status["rollouts"][0]["execution_evidence"]["status"] == "UNAVAILABLE"
    assert status["rollouts"][0]["readiness"]["status"] == "NOT_CONFIGURED"


def test_rollout_readiness_requires_policy_thresholds_and_current_worker() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
            readiness=RolloutReadinessRequirements(
                minimum_observations=1,
                minimum_completed_observations=1,
                maximum_failed_observations=0,
                minimum_candidate_authoritative_observations=1,
                minimum_current_workers=1,
            ),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    before = coordinator.readiness(record.rollout_id)
    assert before["status"] == "NOT_READY"
    assert before["target_stage"] == "active"
    assert before["checks"]["current_workers"]["passed"] is False

    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=404,
    )
    result = _execute(
        ledger,
        record,
        lambda value: value,
        lambda value: value + 1,
        execution_store=store,
    )
    assert result.candidate_authoritative is True

    after = coordinator.readiness(record.rollout_id)
    assert after["status"] == "READY"
    assert after["checks"]["candidate_authoritative_observations"]["passed"] is True
    assert len(ledger.transitions(record.rollout_id)) == 3


def test_supervisor_advances_policy_defined_ramp_only_when_ready() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_adaptive_stage_progression=True,
            ramp=RolloutRampPolicy(
                steps=(
                    RolloutRampStep(
                        RepairRolloutStage.SHADOW,
                        shadow_sample_percentage=100,
                    ),
                    RolloutRampStep(
                        RepairRolloutStage.CANARY,
                        canary_percentage=20,
                    ),
                    RolloutRampStep(
                        RepairRolloutStage.ACTIVE,
                        active_candidate_percentage=100,
                    ),
                )
            ),
            readiness=RolloutReadinessRequirements(minimum_current_workers=0),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    shadow = coordinator.advance_if_ready(
        record.rollout_id,
        authority_id="supervisor-1",
        reason="policy-defined shadow evidence is ready",
    )
    assert shadow["status"] == "ADVANCED"
    assert shadow["authority_granted"] is False
    assert shadow["record"]["stage"] == "shadow"

    canary = coordinator.advance_if_ready(
        record.rollout_id,
        authority_id="supervisor-1",
        reason="policy-defined canary evidence is ready",
    )
    assert canary["status"] == "ADVANCED"
    assert canary["record"]["stage"] == "canary"
    assert canary["record"]["routing_policy"]["canary_percentage"] == 20


def test_supervisor_ramp_advancement_retains_unready_state_without_mutation() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_adaptive_stage_progression=True,
            readiness=RolloutReadinessRequirements(minimum_current_workers=1),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    result = coordinator.advance_if_ready(
        record.rollout_id,
        authority_id="supervisor-1",
        reason="wait for a worker",
    )
    assert result["status"] == "NOT_READY"
    assert result["authority_granted"] is False
    assert result["record"]["stage"] == "validated"
    assert len(ledger.transitions(record.rollout_id)) == 2


def test_stage_readiness_overrides_global_requirements_for_next_stage() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_adaptive_stage_progression=True,
            readiness=RolloutReadinessRequirements(minimum_current_workers=0),
            stage_readiness=(
                RolloutStageReadiness(
                    RepairRolloutStage.CANARY,
                    RolloutReadinessRequirements(minimum_observations=1),
                ),
            ),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    shadow = coordinator.advance_if_ready(
        record.rollout_id,
        authority_id="supervisor-1",
        reason="enter shadow",
    )
    assert shadow["status"] == "ADVANCED"

    readiness = coordinator.readiness(record.rollout_id)
    assert readiness["status"] == "NOT_READY"
    assert readiness["checks"]["observations"]["required"] == 1
    assert readiness["checks"]["observations"]["passed"] is False


def test_stage_readiness_rejects_duplicate_or_out_of_order_overrides() -> None:
    with pytest.raises(ValueError, match="more than one step"):
        RepairRolloutPolicy(
            stage_readiness=(
                RolloutStageReadiness(
                    RepairRolloutStage.SHADOW,
                    RolloutReadinessRequirements(minimum_observations=1),
                ),
                RolloutStageReadiness(
                    RepairRolloutStage.SHADOW,
                    RolloutReadinessRequirements(minimum_observations=2),
                ),
            )
        )
    with pytest.raises(ValueError, match="ordered"):
        RepairRolloutPolicy(
            stage_readiness=(
                RolloutStageReadiness(
                    RepairRolloutStage.CANARY,
                    RolloutReadinessRequirements(minimum_observations=1),
                ),
                RolloutStageReadiness(
                    RepairRolloutStage.SHADOW,
                    RolloutReadinessRequirements(minimum_observations=1),
                ),
            )
        )


def test_operator_rollout_advance_requires_confirmation_and_records_identity() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    with pytest.raises(PermissionError, match="confirm=true"):
        _handle_rollout_advance_request(
            ledger,
            coordinator,
            {
                "rollout_id": str(validated.rollout_id),
                "to_stage": "shadow",
                "reason": "begin reviewed shadow",
            },
            (500, 1000, 1000),
            policy_fingerprint="policy-hash",
            authority_fingerprint="authority-hash",
        )

    response = _handle_rollout_advance_request(
        ledger,
        coordinator,
        {
            "rollout_id": str(validated.rollout_id),
            "to_stage": "shadow",
            "reason": "begin reviewed shadow",
            "confirm": True,
        },
        (500, 1000, 1000),
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )

    assert response["record"]["stage"] == "shadow"
    assert response["transition"]["authority_id"] == "uid:1000"
    assert response["transition"]["authority_type"] == "operator"
    assert response["authority_granted"] is True


def test_operator_rollout_advance_requires_explicit_override_for_unready_rollout() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            readiness=RolloutReadinessRequirements(minimum_current_workers=1),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    request = {
        "rollout_id": str(validated.rollout_id),
        "to_stage": "shadow",
        "reason": "begin shadow after operator review",
        "confirm": True,
    }
    with pytest.raises(PermissionError, match="readiness"):
        _handle_rollout_advance_request(
            ledger,
            coordinator,
            request,
            (501, 1000, 1000),
            policy_fingerprint="policy-hash",
            authority_fingerprint="authority-hash",
        )

    request["override_readiness"] = True
    response = _handle_rollout_advance_request(
        ledger,
        coordinator,
        request,
        (501, 1000, 1000),
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    assert response["readiness"]["status"] == "NOT_READY"
    assert response["readiness_overridden"] is True


def test_operator_rollout_resume_requires_readiness_or_explicit_override() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            readiness=RolloutReadinessRequirements(minimum_current_workers=1),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.SHADOW)
    record = ledger.pause(
        record.rollout_id,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="hold for review",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    request = {
        "rollout_id": str(record.rollout_id),
        "reason": "resume after operator review",
        "confirm": True,
    }
    with pytest.raises(PermissionError, match="resume"):
        _handle_rollout_pause_request(
            ledger,
            coordinator,
            request,
            (503, 1000, 1000),
            paused=False,
            policy_fingerprint="policy-hash",
            authority_fingerprint="authority-hash",
        )

    request["override_readiness"] = True
    response = _handle_rollout_pause_request(
        ledger,
        coordinator,
        request,
        (503, 1000, 1000),
        paused=False,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    assert response["action"] == "resume"
    assert response["record"]["paused"] is False
    assert response["readiness"]["status"] == "NOT_READY"
    assert response["readiness_overridden"] is True


def test_operator_routing_percentage_update_is_bound_and_audited() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_operator_routing_changes=True,
            allow_operator_routing_increases=True,
            require_readiness_for_routing_increase=False,
            routing=RolloutRoutingPolicy(
                shadow_sample_percentage=50,
                canary_percentage=10,
                active_candidate_percentage=50,
                candidate_mirror_percentage=10,
            ),
        )
    )
    record = _record(ledger)
    validated = _advance(ledger, record, RepairRolloutStage.VALIDATED)

    updated = ledger.update_routing_percentages(
        validated.rollout_id,
        shadow_sample_percentage=75,
        canary_percentage=25,
        active_candidate_percentage=50,
        candidate_mirror_percentage=40,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="increase after reviewed evidence",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )

    assert updated.routing_policy == RolloutRoutingPolicy(
        shadow_sample_percentage=75,
        canary_percentage=25,
        active_candidate_percentage=50,
        candidate_mirror_percentage=40,
    )
    transition = ledger.transitions(updated.rollout_id)[-1]
    assert transition.action == "routing-update"
    assert transition.from_stage is RepairRolloutStage.VALIDATED
    assert transition.to_stage is RepairRolloutStage.VALIDATED
    assert transition.details["prior_routing"]["canary_percentage"] == 10
    assert transition.details["new_routing"]["canary_percentage"] == 25
    assert transition.details["prior_routing"]["candidate_mirror_percentage"] == 10
    assert transition.details["new_routing"]["candidate_mirror_percentage"] == 40

    shadow = _advance(ledger, updated, RepairRolloutStage.SHADOW)
    decision = _decide(ledger, shadow)
    assert decision.configured_percentage == 75


def test_routing_percentage_update_invalidates_worker_acknowledgements() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_operator_routing_changes=True,
            allow_operator_routing_increases=True,
            require_readiness_for_routing_increase=False,
            routing=RolloutRoutingPolicy(canary_percentage=10),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=101,
    )

    ledger.update_routing_percentages(
        record.rollout_id,
        shadow_sample_percentage=100,
        canary_percentage=25,
        active_candidate_percentage=100,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="adjust canary after review",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )

    status = coordinator.status(record.rollout_id)
    assert status["rollouts"][0]["current_worker_count"] == 0
    assert status["rollouts"][0]["stale_acknowledgement_count"] == 1
    with pytest.raises(PermissionError, match="not acknowledged"):
        coordinator.route(
            rollout_id=record.rollout_id,
            worker_id="worker-a",
            worker_process_id=101,
            routing_scope="tenant",
            routing_key="tenant-1",
        )

    coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=101,
    )
    decision = coordinator.route(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=101,
        routing_scope="tenant",
        routing_key="tenant-1",
    )
    assert decision.configured_percentage == 25


def test_routing_percentage_increase_requires_policy_and_readiness() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_operator_routing_changes=True,
            routing=RolloutRoutingPolicy(
                shadow_sample_percentage=50,
                canary_percentage=10,
                active_candidate_percentage=50,
            ),
        )
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)

    with pytest.raises(RepairRolloutError, match="increases are disabled"):
        ledger.update_routing_percentages(
            validated.rollout_id,
            shadow_sample_percentage=100,
            canary_percentage=10,
            active_candidate_percentage=100,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="unsafe increase",
            policy_fingerprint="policy-hash",
            authority_fingerprint="authority-hash",
            readiness_status="READY",
        )

    ready_policy = replace(
        ledger.policy,
        allow_operator_routing_increases=True,
    )
    ready_ledger = RepairRolloutLedger(policy=ready_policy)
    ready_record = _advance(
        ready_ledger,
        _record(ready_ledger),
        RepairRolloutStage.VALIDATED,
    )
    with pytest.raises(RepairRolloutError, match="requires ready evidence"):
        ready_ledger.update_routing_percentages(
            ready_record.rollout_id,
            shadow_sample_percentage=100,
            canary_percentage=10,
            active_candidate_percentage=100,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="increase without evidence",
            policy_fingerprint="policy-hash",
            authority_fingerprint="authority-hash",
            readiness_status="NOT_READY",
        )


def test_operator_routing_percentage_control_uses_supervisor_readiness() -> None:
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            allow_operator_routing_changes=True,
            allow_operator_routing_increases=True,
            routing=RolloutRoutingPolicy(canary_percentage=10),
        )
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    response = _handle_rollout_percentage_request(
        ledger,
        coordinator,
        {
            "rollout_id": str(record.rollout_id),
            "shadow_sample_percentage": 50,
            "canary_percentage": 20,
            "active_candidate_percentage": 100,
            "reason": "operator reviewed canary increase",
            "confirm": True,
        },
        (1234, 1001, 1001),
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    assert response["authority_granted"] is True
    assert response["action"] == "routing-update"
    assert response["record"]["routing_policy"]["canary_percentage"] == 20
    assert response["transition"]["details"]["new_routing"]["canary_percentage"] == 20


def test_operator_rollout_safety_actions_do_not_require_readiness() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            readiness=RolloutReadinessRequirements(minimum_current_workers=1),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.SHADOW)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)
    record = _advance(ledger, record, RepairRolloutStage.ACTIVE)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    response = _handle_rollout_advance_request(
        ledger,
        coordinator,
        {
            "rollout_id": str(record.rollout_id),
            "to_stage": "revoked",
            "reason": "incident requires immediate rollback",
            "incident_id": str(uuid4()),
            "confirm": True,
        },
        (502, 1000, 1000),
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )

    assert response["record"]["stage"] == "revoked"
    assert response["readiness"]["status"] == "NOT_READY"


def test_paused_rollout_persists_and_blocks_routing_until_resumed(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, record, RepairRolloutStage.CANARY)

    paused = ledger.pause(
        record.rollout_id,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="investigate canary mismatch",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    assert paused.paused is True
    assert ledger.transitions(record.rollout_id)[-1].action == "pause"
    with pytest.raises(RepairRolloutError, match="paused"):
        decide_rollout_routing(
            paused,
            policy=ledger.policy,
            policy_fingerprint="policy-hash",
            routing_scope="tenant",
            routing_key="tenant-1",
        )
    with pytest.raises(RepairRolloutError, match="paused"):
        ledger.advance(
            paused.rollout_id,
            to_stage=RepairRolloutStage.ACTIVE,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="must not skip pause",
            policy_fingerprint="policy-hash",
            authority_fingerprint="authority-hash",
        )

    reopened = RepairRolloutLedger(
        policy=ledger.policy,
        store=store,
    )
    assert reopened.get(record.rollout_id).paused is True
    resumed = reopened.resume(
        record.rollout_id,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="canary review complete",
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
    )
    assert resumed.paused is False
    assert [item.action for item in reopened.transitions(record.rollout_id)][-2:] == [
        "pause",
        "resume",
    ]
    decision = decide_rollout_routing(
        resumed,
        policy=reopened.policy,
        policy_fingerprint="policy-hash",
        routing_scope="tenant",
        routing_key="tenant-1",
    )
    assert decision.candidate_authoritative is True


def test_malformed_persisted_pause_state_fails_closed() -> None:
    with pytest.raises(RepairRolloutError, match="paused state must be a boolean"):
        _coerce_record({"paused": "false"})


def test_sqlite_rollout_worker_acknowledgement_survives_coordinator_restart(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(
            enabled=True,
            routing=RolloutRoutingPolicy(canary_percentage=100),
        ),
        store=store,
    )
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    coordinator = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )
    acknowledgement = coordinator.acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=202,
    )
    reopened_ledger = RepairRolloutLedger(
        policy=ledger.policy,
        store=store,
    )
    reopened = RepairRolloutCoordinator(
        reopened_ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    )

    assert store.all_rollout_worker_acknowledgements()[0]["content_hash"] == acknowledgement.content_hash
    decision = reopened.route(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=202,
        routing_scope="tenant",
        routing_key="tenant-1",
    )
    assert decision.candidate_authoritative is True


def test_rollout_coordinator_reports_tampered_acknowledgement_as_invalid() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        store=store,
    )
    record = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    acknowledgement = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    ).acknowledge_worker(
        rollout_id=record.rollout_id,
        worker_id="worker-a",
        worker_process_id=303,
    )
    store.record_rollout_worker_acknowledgement(
        replace(
            acknowledgement,
            acknowledgement_id=uuid4(),
            content_hash="tampered",
        )
    )

    status = RepairRolloutCoordinator(
        ledger,
        policy_fingerprint="policy-hash",
        authority_fingerprint="authority-hash",
        store=store,
    ).status(record.rollout_id)

    assert status["rollouts"][0]["current_worker_count"] == 1
    assert status["rollouts"][0]["invalid_acknowledgement_count"] == 1


def test_execute_rollout_emits_failure_type_without_exception_message() -> None:
    ledger = _ledger(canary_percentage=100)
    validated = _advance(ledger, _record(ledger), RepairRolloutStage.VALIDATED)
    record = _advance(ledger, validated, RepairRolloutStage.CANARY)
    events: list[tuple[str, dict]] = []

    def failing_candidate(value: int) -> int:
        raise RuntimeError(f"secret failure {value}")

    with pytest.raises(RuntimeError, match="secret failure"):
        _execute(
            ledger,
            record,
            lambda value: value,
            failing_candidate,
            audit_event=lambda name, **fields: events.append((name, fields)),
        )

    outcome = events[-1][1]
    assert outcome["outcome"]["state"] == "FAILED"
    assert outcome["details"]["exception_type"] == "RuntimeError"
    assert "secret failure" not in str(outcome)


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
