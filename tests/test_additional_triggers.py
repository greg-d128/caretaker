from __future__ import annotations

from caretaker import (
    CandidateProposal,
    ObservationPolicy,
    OutputValidationTrigger,
    RegisteredCase,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    TimeoutTrigger,
    repair,
)
from tests.sample_targets import bad_payload, slow_identity


def valid_payload(value: object) -> bool:
    return isinstance(value, dict) and set(value) == {"value"}


def test_output_validation_can_trigger_repair_and_retry() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="""
def bad_payload(value: int) -> dict[str, int]:
    return {"value": value}
""",
                explanation="Return the documented payload shape.",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    policy = RepairPolicy(
        triggers=(
            OutputValidationTrigger(
                validator=valid_payload,
                name="payload-shape",
            ),
        ),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=1,
            long_term_successful_executions=2,
            long_term_minimum_duration_seconds=0,
        ),
    )
    healed = repair(
        policy=policy,
        engine=engine,
        cases=(RegisteredCase("shape", args=(3,), expected={"value": 3}),),
    )(bad_payload)

    assert healed(3) == {"value": 3}
    assert healed(4) == {"value": 4}


def test_soft_timeout_can_trigger_a_faster_replacement() -> None:
    provider = StaticRepairProvider(
        [
            CandidateProposal(
                source="""
def slow_identity(value: int) -> int:
    return value
""",
                explanation="Remove unnecessary blocking delay.",
            )
        ]
    )
    engine = RepairEngine(provider=provider)
    policy = RepairPolicy(
        triggers=(TimeoutTrigger(seconds=0.005, mode="soft"),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
    )
    healed = repair(
        policy=policy,
        engine=engine,
        cases=(RegisteredCase("identity", args=(7,), expected=7),),
    )(slow_identity)

    assert healed(7) == 7
    assert healed.__caretaker_target__.slot.load().number == 1
