from __future__ import annotations

import pytest

from caretaker import (
    CandidateProposal,
    ExceptionTrigger,
    ObservationPolicy,
    RepairEngine,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    StaticRepairProvider,
    ValidationBackendUnavailableAction,
    ValidationIsolationLevel,
    ValidationPolicy,
    repair,
)
from caretaker.validation import ProcessValidationBackend, SubprocessValidationBackend
from tests.sample_targets import broken_divide


def _candidate() -> CandidateProposal:
    return CandidateProposal(
        source="""
def broken_divide(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count
""",
        explanation="safe test candidate",
    )


def _policy(action: ValidationBackendUnavailableAction) -> RepairPolicy:
    return RepairPolicy.automatic(
        triggers=(ExceptionTrigger(),),
        state=StatePolicy(snapshot_arguments=True, restore_before_retry=True),
        retry=RetryPolicy(max_attempts=1, safety=ReplaySafety.PURE),
        observation=ObservationPolicy(
            initial_successful_executions=1,
            long_term_successful_executions=1,
            long_term_minimum_duration_seconds=0,
        ),
        validation=ValidationPolicy(
            minimum_isolation=ValidationIsolationLevel.VM,
            backend_unavailable_action=action,
        ),
    )


def test_process_backend_advertises_process_isolation() -> None:
    backend = ProcessValidationBackend()
    capabilities = backend.capabilities()
    assert capabilities.name == "process"
    assert capabilities.isolation_level is ValidationIsolationLevel.PROCESS
    assert capabilities.separate_kernel is False
    assert backend.available() == (True, None)
    assert ProcessValidationBackend is SubprocessValidationBackend


def test_required_vm_never_silently_downgrades_to_process() -> None:
    engine = RepairEngine(provider=StaticRepairProvider([_candidate()]))
    wrapped = repair(policy=_policy(ValidationBackendUnavailableAction.FAIL_REPAIR), engine=engine)(broken_divide)

    with pytest.raises(ZeroDivisionError):
        wrapped(10.0, 0)

    attempts = tuple(engine.store.all_attempts()) if hasattr(engine.store, "all_attempts") else tuple(engine.store.attempts.values())
    assert attempts
    report_attempt = attempts[-1]
    assert report_attempt.score_card is not None
    assert report_attempt.score_card.eligible is False
    assert any("requires at least VM" in item for item in report_attempt.score_card.disqualifications)


def test_backend_unavailable_policy_can_require_explicit_operator_approval() -> None:
    engine = RepairEngine(provider=StaticRepairProvider([_candidate()]))
    wrapped = repair(
        policy=_policy(ValidationBackendUnavailableAction.REQUIRE_OPERATOR_APPROVAL),
        engine=engine,
    )(broken_divide)

    with pytest.raises(ZeroDivisionError):
        wrapped(10.0, 0)

    pending = engine.pending_approvals()
    assert len(pending) == 1
    assert "validation isolation backend is unavailable" in pending[0].reason.lower()
    # No candidate has been deployed merely because PROCESS was available.
    assert wrapped.__caretaker_target__.slot.load().number == 0
