from __future__ import annotations

import logging

from caretaker import (
    CandidateProposal,
    CorrelatedLogHandler,
    ExceptionTrigger,
    ObservationPolicy,
    RegisteredCase,
    RepairAuthority,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    repair,
)
from examples.demo_target import divide


logging.basicConfig(level=logging.INFO)

provider = StaticRepairProvider(
    [
        CandidateProposal(
            source="""
def divide(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count
""",
            explanation="Treat an empty group as a zero per-item value.",
            generator_name="demonstration-provider",
        )
    ]
)
engine = RepairEngine(provider=provider)
logging.getLogger().addHandler(engine.log_handler)

policy = RepairPolicy(
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
        long_term_successful_executions=4,
        long_term_minimum_duration_seconds=0,
    ),
    # This example deliberately demonstrates unattended activation. Production
    # policies default to explicit operator approval.
    authority=RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS,
)

safe_divide = repair(
    policy=policy,
    engine=engine,
    cases=(
        RegisteredCase("zero items", args=(10.0, 0), expected=0.0),
        RegisteredCase("normal division", args=(10.0, 2), expected=5.0),
    ),
)(divide)


if __name__ == "__main__":
    print("First call fails, is repaired, and is retried:", safe_divide(10.0, 0))
    print("Later call uses the repaired implementation:", safe_divide(10.0, 2))
    target = safe_divide.__caretaker_target__
    print("Active function version:", target.slot.load().number)
    print("Slot state:", target.slot.state.name)
