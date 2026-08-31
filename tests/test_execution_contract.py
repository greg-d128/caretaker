from __future__ import annotations

from uuid import uuid4

import pytest

from caretaker import (
    EffectObservation,
    FunctionExecutionContract,
    ReplaySafety,
    SideEffectClass,
    assess_shadow_eligibility,
)
from caretaker.domain import DifferentialExecutionMode
from caretaker.engine import RepairEngine
from caretaker.evidence.models import (
    BehaviorEvent,
    BehaviorEventKind,
    CodeIdentity,
    EventOutcome,
    ResourceIdentity,
)
from caretaker.policy import (
    DifferentialExecutionPolicy,
    PolicyConfigurationError,
    RepairPolicy,
)
from caretaker.registry import build_target


def _event(kind: BehaviorEventKind) -> BehaviorEvent:
    return BehaviorEvent.create(
        event_kind=kind,
        operation=kind.name.lower(),
        code_identity=CodeIdentity(None, None, "tests.execution_contract", "target"),
        run_id=uuid4(),
        process_id=1,
        thread_id=1,
        target_id="tests.execution_contract:target",
        resource=(
            ResourceIdentity("network", "api.example:443", "connect")
            if kind is BehaviorEventKind.NETWORK_CONNECT
            else ResourceIdentity("file", "/tmp/output", "open")
            if kind is BehaviorEventKind.FILE_WRITE
            else None
        ),
        outcome=EventOutcome.SUCCEEDED,
    )


def test_function_execution_contract_is_attached_to_target_and_slot() -> None:
    def target(value: int) -> int:
        return value + 1

    declared = FunctionExecutionContract(
        side_effects=SideEffectClass.READ_ONLY,
        retry_safety=ReplaySafety.IDEMPOTENT,
    )
    registered = build_target(
        target,
        policy=RepairPolicy(),
        execution_contract=declared,
    )

    assert registered.execution_contract is declared
    assert registered.slot.execution_contract is declared
    assert registered.slot.snapshot()["execution_contract"] == {
        "side_effects": "READ_ONLY",
        "retry_safety": "IDEMPOTENT",
    }


def test_authority_policy_refresh_preserves_execution_contract() -> None:
    def target(value: int) -> int:
        return value + 1

    declared = FunctionExecutionContract(side_effects=SideEffectClass.READ_ONLY)
    engine = RepairEngine()
    registered = build_target(target, policy=RepairPolicy(), execution_contract=declared)
    engine.register(registered)
    engine.refresh_authority_policy()

    refreshed = engine.registry.get(registered.target_id)
    assert refreshed.execution_contract is declared
    assert refreshed.slot.execution_contract is declared


def test_pure_function_acknowledgement_preserves_legacy_contract_metadata() -> None:
    def target(value: int) -> int:
        return value + 1

    from dataclasses import replace

    policy = RepairPolicy()
    policy = replace(
        policy,
        observation=replace(
            policy.observation,
            differential_execution=DifferentialExecutionPolicy(
                mode=DifferentialExecutionMode.PURE_FUNCTION,
                pure_function_confirmed=True,
            ),
        ),
    )
    registered = build_target(target, policy=policy)

    assert registered.execution_contract.side_effects is SideEffectClass.PURE
    assert registered.execution_contract.retry_safety is ReplaySafety.UNKNOWN


def test_differential_execution_rejects_non_pure_function_contract() -> None:
    def target(value: int) -> int:
        return value + 1

    from dataclasses import replace

    policy = replace(
        RepairPolicy(),
        observation=replace(
            RepairPolicy().observation,
            differential_execution=DifferentialExecutionPolicy(
                mode=DifferentialExecutionMode.PURE_FUNCTION,
                pure_function_confirmed=True,
            ),
        ),
    )
    with pytest.raises(PolicyConfigurationError, match="isolation adapter"):
        build_target(
            target,
            policy=policy,
            execution_contract=FunctionExecutionContract(
                side_effects=SideEffectClass.SIDE_EFFECTING,
            ),
        )


def test_effect_observation_identifies_network_and_mutating_filesystem_activity() -> None:
    observation = EffectObservation.from_events(
        (_event(BehaviorEventKind.NETWORK_CONNECT), _event(BehaviorEventKind.FILE_WRITE)),
        complete=True,
    )

    assert observation.categories == ("filesystem", "network")
    assert observation.externally_visible_categories == ("filesystem", "network")
    assert "FILE_WRITE" in observation.event_kinds


def test_pure_contract_is_rejected_when_behavior_observes_resource_activity() -> None:
    decision = assess_shadow_eligibility(
        FunctionExecutionContract(side_effects=SideEffectClass.PURE),
        EffectObservation.from_events((_event(BehaviorEventKind.NETWORK_CONNECT),), complete=True),
    )

    assert not decision.eligible
    assert decision.requires_isolation
    assert "conflicts" in decision.reason


def test_read_only_contract_allows_complete_read_only_observation() -> None:
    decision = assess_shadow_eligibility(
        FunctionExecutionContract(side_effects=SideEffectClass.READ_ONLY),
        EffectObservation.from_events((_event(BehaviorEventKind.FILE_READ),), complete=True),
    )

    assert decision.eligible
    assert not decision.requires_isolation


def test_read_only_contract_rejects_observed_mutating_activity() -> None:
    decision = assess_shadow_eligibility(
        FunctionExecutionContract(side_effects=SideEffectClass.READ_ONLY),
        EffectObservation.from_events((_event(BehaviorEventKind.FILE_WRITE),), complete=True),
    )

    assert not decision.eligible
    assert decision.requires_isolation
    assert decision.observed_external_effects == ("filesystem",)


def test_missing_effect_coverage_never_proves_purity() -> None:
    decision = assess_shadow_eligibility(
        FunctionExecutionContract(side_effects=SideEffectClass.PURE),
        EffectObservation(complete=False),
    )

    assert not decision.eligible
    assert decision.requires_isolation
    assert "incomplete" in decision.reason


def test_unknown_and_idempotent_contracts_require_isolation() -> None:
    for side_effects in (SideEffectClass.UNKNOWN, SideEffectClass.IDEMPOTENT):
        decision = assess_shadow_eligibility(
            FunctionExecutionContract(side_effects=side_effects),
            EffectObservation(complete=True),
        )
        assert not decision.eligible
        assert decision.requires_isolation
