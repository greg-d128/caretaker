from __future__ import annotations

from dataclasses import replace

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    RegisteredCase,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    repair,
)
from caretaker.engine import ResolutionKind
from caretaker.logging.models import RepairAuthority
from tests.sample_targets import broken_divide


def test_manual_repair_proposes_then_requires_explicit_approval():
    proposal = CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count
""",
        explanation="validated manual repair",
    )
    engine = RepairEngine(provider=StaticRepairProvider([proposal]))
    policy = RepairPolicy(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=0, safety=ReplaySafety.PURE),
        authority=RepairAuthority.REQUIRE_OPERATOR_APPROVAL,
    )
    wrapped = repair(
        policy=policy,
        engine=engine,
        cases=(
            RegisteredCase("zero", args=(10.0, 0), expected=0.0),
            RegisteredCase("normal", args=(8.0, 2), expected=4.0),
        ),
    )(broken_divide)
    try:
        wrapped(10.0, 0)
    except ZeroDivisionError:
        pass
    else:
        raise AssertionError("manual approval mode must not deploy during the failed call")
    pending = engine.pending_approvals()
    assert len(pending) == 1
    target = wrapped.__caretaker_target__
    assert target.slot.load().number == 0
    activated = engine.approve_repair(pending[0].episode_id)
    assert activated.number == 1
    assert wrapped(10.0, 0) == 0.0
