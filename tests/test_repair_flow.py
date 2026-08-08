from __future__ import annotations

from caretaker import (
    CandidateProposal,
    CandidateSelectionPolicy,
    ExceptionTrigger,
    ObservationPolicy,
    RegisteredCase,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    repair,
)
from caretaker.domain import SlotState
from caretaker.store import InMemoryRepairStore
from tests.sample_targets import broken_divide


def test_multiple_candidates_are_validated_scored_and_best_is_activated() -> None:
    bad = CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    return -1.0
""",
        explanation="Incorrect candidate included to exercise selection.",
        generator_name="test",
    )
    good = CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count
""",
        explanation="Handle the zero divisor while preserving normal behavior.",
        generator_name="test",
    )
    store = InMemoryRepairStore()
    engine = RepairEngine(
        provider=StaticRepairProvider([bad, good]),
        store=store,
    )
    policy = RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(
            snapshot_arguments=True,
            restore_before_retry=True,
        ),
        retry=RetryPolicy(
            max_attempts=1,
            safety=ReplaySafety.PURE,
        ),
        observation=ObservationPolicy(
            initial_successful_executions=2,
            long_term_successful_executions=3,
            long_term_minimum_duration_seconds=0,
        ),
        selection=CandidateSelectionPolicy(minimum_total_score=70),
    )
    healed = repair(
        policy=policy,
        engine=engine,
        cases=(
            RegisteredCase("zero", args=(10.0, 0), expected=0.0),
            RegisteredCase("normal", args=(8.0, 2), expected=4.0),
        ),
    )(broken_divide)

    assert healed(10.0, 0) == 0.0
    assert healed(8.0, 2) == 4.0
    assert healed(9.0, 3) == 3.0

    target = healed.__caretaker_target__
    assert target.slot.load().number == 1
    assert target.slot.state is SlotState.LONG_TERM_ACCEPTED
    assert len(store.incidents) == 1
    assert len(store.candidates) == 2
    assert len(store.attempts) == 2
    selected = [attempt for attempt in store.attempts.values() if attempt.activation and attempt.activation.succeeded]
    assert len(selected) == 1
    assert selected[0].score_card is not None
    assert selected[0].score_card.eligible


def test_policy_snapshot_contains_human_readable_effective_policy() -> None:
    policy = RepairPolicy(
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.IDEMPOTENT),
        state=StatePolicy(snapshot_arguments=True, snapshot_globals=("cache",)),
    )
    snapshot = policy.snapshot()
    assert len(snapshot.fingerprint) == 64
    assert "maximum attempts: 1" in snapshot.human_readable_policy
    assert "snapshot globals: cache" in snapshot.human_readable_policy
    assert snapshot.canonical_policy["retry"]["safety"] == "IDEMPOTENT"
