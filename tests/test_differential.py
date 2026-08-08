from caretaker import (
    CandidateProposal,
    DifferentialExecutionMode,
    DifferentialExecutionPolicy,
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
from tests.sample_targets import broken_divide


def test_pure_function_can_use_differential_observation() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="""
def broken_divide(total: float, count: int) -> float:
    return 0.0 if count == 0 else total / count
""",
                explanation="Handle zero count.",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    policy = RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=3,
            long_term_successful_executions=10,
            long_term_minimum_duration_seconds=0,
            differential_execution=DifferentialExecutionPolicy(
                mode=DifferentialExecutionMode.PURE_FUNCTION,
                observation_executions=3,
            ),
        ),
    )
    healed = repair(
        policy=policy,
        engine=engine,
        cases=(
            RegisteredCase("zero", args=(4.0, 0), expected=0.0),
            RegisteredCase("normal", args=(4.0, 2), expected=2.0),
        ),
    )(broken_divide)

    assert healed(4.0, 0) == 0.0  # repair retry
    assert healed(4.0, 0) == 0.0  # original fails, candidate succeeds in shadow mode
    assert healed(4.0, 2) == 2.0  # both succeed with equivalent output
    observation = healed.__caretaker_target__.slot.observation()
    assert observation is not None
    assert observation.successful_executions == 3
