from __future__ import annotations

import pytest

from caretaker import (
    EffectObservation,
    FunctionExecutionContract,
    ReplaySafety,
    ShadowExecutionError,
    SideEffectClass,
    shadow_execute,
)


class VerifiedAdapter:
    adapter_id = "test-isolation"
    isolation_verified = True

    def execute(self, implementation, args, kwargs):
        return implementation(*args, **kwargs)


class UnverifiedAdapter(VerifiedAdapter):
    isolation_verified = False


def _pure_contract() -> FunctionExecutionContract:
    return FunctionExecutionContract(
        side_effects=SideEffectClass.PURE,
        retry_safety=ReplaySafety.PURE,
    )


def test_shadow_always_returns_original_result_and_preserves_candidate_evidence() -> None:
    calls: list[str] = []

    def original(value: int) -> int:
        calls.append("original")
        return value

    def candidate(value: int) -> int:
        calls.append("candidate")
        return value + 1

    result = shadow_execute(
        original=original,
        candidate=candidate,
        args=(4,),
        kwargs={},
        contract=_pure_contract(),
        effect_observation=EffectObservation(complete=True),
    )

    assert result.result == 4
    assert result.original_result == 4
    assert result.candidate_result == 5
    assert result.equivalent is False
    assert result.candidate_authoritative is False
    assert calls == ["original", "candidate"]


def test_shadow_requires_verified_isolation_for_uncertain_effects() -> None:
    contract = FunctionExecutionContract(
        side_effects=SideEffectClass.SIDE_EFFECTING,
        retry_safety=ReplaySafety.IDEMPOTENT,
    )

    with pytest.raises(ShadowExecutionError, match="safe duplicate execution"):
        shadow_execute(
            original=lambda: "original",
            candidate=lambda: "candidate",
            args=(),
            kwargs={},
            contract=contract,
            effect_observation=EffectObservation(complete=True),
        )

    result = shadow_execute(
        original=lambda: "original",
        candidate=lambda: "candidate",
        args=(),
        kwargs={},
        contract=contract,
        effect_observation=EffectObservation(complete=True),
        isolation_adapter=VerifiedAdapter(),
    )
    assert result.result == "original"
    assert result.adapter_id == "test-isolation"
    assert result.isolation_verified is True


def test_shadow_rejects_unverified_isolation_adapter() -> None:
    with pytest.raises(ShadowExecutionError, match="verified isolation"):
        shadow_execute(
            original=lambda: 1,
            candidate=lambda: 2,
            args=(),
            kwargs={},
            contract=FunctionExecutionContract(),
            isolation_adapter=UnverifiedAdapter(),
        )


def test_shadow_candidate_failure_never_replaces_original() -> None:
    result = shadow_execute(
        original=lambda: "safe",
        candidate=lambda: (_ for _ in ()).throw(ValueError("candidate failure")),
        args=(),
        kwargs={},
        contract=_pure_contract(),
        effect_observation=EffectObservation(complete=True),
    )

    assert result.result == "safe"
    assert result.original_succeeded is True
    assert result.candidate_succeeded is False
    assert isinstance(result.candidate_exception, ValueError)
