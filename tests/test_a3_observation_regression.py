from __future__ import annotations

import pytest

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
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
from caretaker.provider import CandidateBatch, RepairRequest
from tests.sample_targets import broken_divide


class SequentialProvider:
    name = "sequential-a3"
    model_name = None
    supports_synthesis = False

    def __init__(self, sources: list[str]) -> None:
        self.sources = sources
        self.calls = 0

    def generate(self, request: RepairRequest) -> CandidateBatch:
        source = self.sources[min(self.calls, len(self.sources) - 1)]
        self.calls += 1
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version="sequential-v1",
            prompt_text="sequential",
            candidates=(CandidateProposal(source=source, explanation="candidate"),),
        )

    def synthesize(self, request, candidates):
        raise NotImplementedError


def test_observation_failure_budget_rolls_back_only_after_budget_is_exceeded() -> None:
    candidate = (
        "def broken_divide(total: float, count: int) -> float:\n"
        "    if count == 0:\n"
        "        return 0.0\n"
        "    if total < 0:\n"
        "        raise ValueError('negative unsupported')\n"
        "    return total / count\n"
    )
    engine = RepairEngine(provider=StaticRepairProvider([CandidateProposal(source=candidate, explanation="fix")]))
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=10,
            long_term_successful_executions=20,
            long_term_minimum_duration_seconds=0,
            probation_failure_budget=1,
            rollback_during_probation=True,
        ),
    )
    wrapped = repair(policy=policy, engine=engine)(broken_divide)
    assert wrapped(4.0, 0) == 0.0
    assert wrapped.__caretaker_target__.slot.load().number == 1

    with pytest.raises(ValueError):
        wrapped(-4.0, 2.0)
    assert wrapped.__caretaker_target__.slot.load().number == 1

    with pytest.raises(ValueError):
        wrapped(-4.0, 2.0)
    assert wrapped.__caretaker_target__.slot.load().number == 0


def test_successful_repair_becomes_regression_case_for_later_candidates() -> None:
    provider = SequentialProvider(
        [
            (
                "def broken_divide(total: float, count: int) -> float:\n"
                "    if count == 0:\n"
                "        return 0.0\n"
                "    if total == 999:\n"
                "        raise ValueError('new edge')\n"
                "    return total / count\n"
            ),
            "def broken_divide(total: float, count: int) -> float:\n    return 1.0\n",
        ]
    )
    store = InMemoryRepairStore()
    engine = RepairEngine(provider=provider, store=store)
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=10,
            long_term_successful_executions=20,
            long_term_minimum_duration_seconds=0,
            probation_failure_budget=1,
        ),
    )
    wrapped = repair(policy=policy, engine=engine)(broken_divide)
    assert wrapped(4.0, 0) == 0.0
    assert engine.regression.cases_for_target(wrapped.__caretaker_target__.target_id)

    with pytest.raises(ValueError, match="new edge"):
        wrapped(999.0, 1.0)
    assert provider.calls == 2
    second_attempt = sorted(store.attempts.values(), key=lambda item: item.created_at)[-1]
    registered_checks = [
        check for check in second_attempt.validation_results if check.kind.name == "REGISTERED_TESTS"
    ]
    assert registered_checks and registered_checks[0].outcome.name == "FAILED"
    assert wrapped.__caretaker_target__.slot.load().number == 1
