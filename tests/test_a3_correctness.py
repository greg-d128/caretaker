from __future__ import annotations

import logging
from dataclasses import replace

import pytest

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    InMemoryRepairStore,
    InvalidOutputError,
    ObservationPolicy,
    OutputValidationTrigger,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    TimeoutTrigger,
    ValidationCheckKind,
    ValidationPolicy,
    ValidationResult,
    repair,
)
from caretaker.provider import CandidateBatch, RepairRequest
from tests.sample_targets import (
    always_fails,
    broken_divide,
    invalid_result,
    logged_failure,
    reset_retry_counter,
    slow_result,
)


def test_repaired_output_is_revalidated_against_output_contract() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="def invalid_result(value: int) -> int:\n    return -2\n",
                explanation="Still invalid on purpose",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    policy = RepairPolicy.automatic(
        triggers=(OutputValidationTrigger(validator=lambda value: value >= 0, name="nonnegative"),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
    )
    wrapped = repair(policy=policy, engine=engine)(invalid_result)

    with pytest.raises(RuntimeError, match="validator"):
        wrapped(4)
    assert wrapped.__caretaker_target__.slot.load().number == 0
    attempt = next(iter(engine.store.attempts.values()))
    assert attempt.retry is not None
    assert attempt.retry.contract_validated is False


def test_repaired_output_is_revalidated_against_timeout_contract() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source=(
                    "def slow_result(value: int) -> int:\n"
                    "    time.sleep(0.01)\n"
                    "    return value\n"
                ),
                explanation="Still too slow on purpose",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    policy = RepairPolicy.automatic(
        triggers=(TimeoutTrigger(seconds=0.005),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
    )
    wrapped = repair(policy=policy, engine=engine)(slow_result)

    # The original slow call produced a usable result, but the proposed repair is
    # rejected and rolled back because it still violates the timeout contract.
    assert wrapped(3) == 3
    assert wrapped.__caretaker_target__.slot.load().number == 0
    attempt = next(iter(engine.store.attempts.values()))
    assert attempt.retry is not None
    assert attempt.retry.contract_validated is False


def test_retry_policy_performs_multiple_attempts_and_backoff_path() -> None:
    reset_retry_counter()
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source=(
                    "def always_fails(value: int) -> int:\n"
                    "    if retry_gate():\n"
                    "        raise ValueError('first repaired attempt fails')\n"
                    "    return value * 2\n"
                ),
                explanation="Succeeds on the second repaired execution",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    policy = RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(
            max_attempts=2,
            safety=ReplaySafety.PURE,
            backoff_seconds=0.001,
        ),
    )
    wrapped = repair(policy=policy, engine=engine)(always_fails)

    assert wrapped(5) == 10
    attempt = next(iter(engine.store.attempts.values()))
    assert attempt.retry is not None
    assert attempt.retry.attempts_made == 2
    assert len(attempt.retry.failure_summaries) == 1


def test_generated_tests_are_preserved_and_run_as_advisory_evidence() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="def always_fails(value: int) -> int:\n    return value * 2\n",
                explanation="Fix",
                generated_tests=("assert candidate(3) == 6",),
            )
        ]
    )
    store = InMemoryRepairStore()
    engine = RepairEngine(provider=provider, store=store)
    policy = RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        validation=ValidationPolicy(run_generated_tests=True),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
    )
    wrapped = repair(policy=policy, engine=engine)(always_fails)

    assert wrapped(4) == 8
    candidate = next(iter(store.candidates.values()))
    assert len(candidate.generated_tests) == 1
    attempt = next(iter(store.attempts.values()))
    generated = [
        check
        for check in attempt.validation_results
        if check.kind is ValidationCheckKind.GENERATED_TESTS
    ]
    assert generated and generated[0].outcome.name == "PASSED"


class CapturingProvider:
    name = "capturing"
    model_name = None
    supports_synthesis = False

    def __init__(self) -> None:
        self.request: RepairRequest | None = None

    def generate(self, request: RepairRequest) -> CandidateBatch:
        self.request = request
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version="capture-v1",
            prompt_text="capture",
            candidates=(
                CandidateProposal(
                    source="def logged_failure(value: int) -> int:\n    return value\n",
                    explanation="Fix",
                ),
            ),
        )

    def synthesize(self, request, candidates):
        raise NotImplementedError


def test_correlated_logs_are_redacted_and_included_in_repair_request() -> None:
    provider = CapturingProvider()
    engine = RepairEngine(provider=provider)
    app_logger = logging.getLogger("caretaker-test.application")
    app_logger.addHandler(engine.log_handler)
    app_logger.setLevel(logging.WARNING)
    policy = RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
    )
    wrapped = repair(policy=policy, engine=engine)(logged_failure)
    try:
        assert wrapped(9) == 9
    finally:
        app_logger.removeHandler(engine.log_handler)

    assert provider.request is not None
    assert "processing value=9" in provider.request.logs_summary
    assert "super-secret-token" not in provider.request.logs_summary
    assert "token=<redacted>" in provider.request.logs_summary


def test_structured_validator_reason_and_evidence_are_preserved() -> None:
    policy = RepairPolicy(
        triggers=(
            OutputValidationTrigger(
                validator=lambda value: ValidationResult(
                    valid=False,
                    reason="value is outside the domain contract",
                    evidence={"observed": value},
                ),
                name="domain",
            ),
        ),
        mode=replace(RepairPolicy(), enabled=False).mode,
    )
    # A provider is intentionally absent; the incident is still captured.
    wrapped = repair(policy=replace(policy, enabled=False))(invalid_result)
    with pytest.raises(InvalidOutputError, match="outside the domain contract") as captured:
        wrapped(1)
    assert any("observed" in note for note in getattr(captured.value, "__notes__", ()))
