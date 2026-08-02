from caretaker import (
    CandidateProposal,
    CandidateSelectionPolicy,
    CandidateSynthesisPolicy,
    ExceptionTrigger,
    RegisteredCase,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    ScoringPolicy,
    StatePolicy,
    StaticRepairProvider,
    repair,
)
from caretaker.store import InMemoryRepairStore
from tests.sample_targets import broken_divide


def test_optional_candidate_synthesis_is_revalidated_and_can_be_selected() -> None:
    first = CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    if count == 0:
        result = 0.0
    else:
        result = total / count
    if result == 0.0:
        return 0.0
    return result
""",
        explanation="Valid but unnecessarily complex.",
    )
    second = CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    values = [0.0 if count == 0 else total / count]
    return values[0]
""",
        explanation="Valid but allocates an unnecessary list.",
    )
    synthesized = CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    return 0.0 if count == 0 else total / count
""",
        explanation="Consolidated minimal repair.",
    )
    store = InMemoryRepairStore()
    engine = RepairEngine(
        provider=StaticRepairProvider([first, second], synthesized=synthesized),
        store=store,
    )
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        selection=CandidateSelectionPolicy(
            minimum_total_score=70,
            synthesis=CandidateSynthesisPolicy(enabled=True),
        ),
        scoring=ScoringPolicy(
            performance_weight=0.0,
            maintainability_weight=0.15,
        ),
    )
    healed = repair(
        policy=policy,
        engine=engine,
        cases=(
            RegisteredCase("zero", args=(1.0, 0), expected=0.0),
            RegisteredCase("normal", args=(8.0, 2), expected=4.0),
        ),
    )(broken_divide)

    assert healed(1.0, 0) == 0.0
    selected_attempt = next(
        attempt for attempt in store.attempts.values()
        if attempt.activation and attempt.activation.succeeded
    )
    selected_candidate = store.candidates[selected_attempt.candidate_id]
    assert selected_candidate.lineage is not None
    assert len(selected_candidate.lineage.parent_candidate_ids) == 2
    assert len(store.candidates) == 3
