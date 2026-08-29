from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
from uuid import uuid4

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
from caretaker.domain import (
    ArtifactFile,
    CandidateGeneratorKind,
    RepairArtifact,
    RepairArtifactKind,
    RepairCandidate,
    utcnow,
)
from caretaker.logging import ControlSocketServer
from caretaker.validation import (
    SubprocessValidationBackend,
    _write_worker_request,
    assess_candidate_source,
)


def boundary_target(total: float, count: int) -> float:
    return total / count


def _candidate_source() -> str:
    return """\
def boundary_target(total: float, count: int) -> float:
    if count == 0:
        return 0.0
    return total / count
"""


def _approval_policy() -> RepairPolicy:
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
            backend_unavailable_action=(
                ValidationBackendUnavailableAction.REQUIRE_OPERATOR_APPROVAL
            ),
        ),
    )


def _repair_candidate(target) -> RepairCandidate:
    source = _candidate_source()
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return RepairCandidate(
        candidate_id=uuid4(),
        generation_id=uuid4(),
        episode_id=uuid4(),
        incident_id=uuid4(),
        target_id=target.target_id,
        created_at=utcnow(),
        base_function_version=0,
        base_source_hash=target.slot.load().source_hash,
        artifact=RepairArtifact(
            kind=RepairArtifactKind.FUNCTION_REPLACEMENT,
            files=(
                ArtifactFile(
                    relative_path="__candidate__.py",
                    operation="replace-function",
                    content=source,
                    content_hash=source_hash,
                ),
            ),
            entrypoint="boundary_target",
            artifact_hash=source_hash,
        ),
        explanation="local trust-boundary regression candidate",
        generator_kind=CandidateGeneratorKind.DETERMINISTIC,
        generator_name="test",
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known security debt: operator approval currently authorizes activation when "
        "the policy-required validation isolation was never obtained."
    ),
)
def test_operator_approval_cannot_substitute_for_required_validation() -> None:
    engine = RepairEngine(
        provider=StaticRepairProvider(
            [CandidateProposal(source=_candidate_source(), explanation="local test")]
        )
    )
    wrapped = repair(policy=_approval_policy(), engine=engine)(boundary_target)

    with pytest.raises(ZeroDivisionError):
        wrapped(10.0, 0)

    pending = engine.pending_approvals()
    assert len(pending) == 1
    engine.approve_repair(pending[0].episode_id)

    # Approval may authorize a separately labelled override in a future design,
    # but it must not satisfy the security invariant "required validation passed".
    assert wrapped.__caretaker_target__.slot.load().number == 0


def test_validation_request_transport_rejects_arbitrary_python_objects(
    tmp_path: Path,
) -> None:
    class OpaqueApplicationObject:
        pass

    with pytest.raises((TypeError, ValueError)):
        _write_worker_request(
            tmp_path,
            {"mode": "function", "registered_cases": (OpaqueApplicationObject(),)},
        )


def test_worker_result_must_prove_all_mandatory_validation_checks() -> None:
    class IncompleteResultBackend(SubprocessValidationBackend):
        def _run_worker(self, payload, *, timeout_seconds):
            return {
                "eligible": True,
                "checks": [],
                "measurements": {},
                "risk_findings": [],
                "hard_disqualifications": [],
                "review_required_findings": [],
            }

    engine = RepairEngine(provider=StaticRepairProvider([]))
    wrapped = repair(policy=RepairPolicy.automatic(), engine=engine)(boundary_target)
    target = wrapped.__caretaker_target__
    report = IncompleteResultBackend().validate_candidate(
        _repair_candidate(target),
        target,
        timeout_seconds=1.0,
    )

    assert report.eligible is False


def test_static_gate_rejects_dynamic_dunder_attribute_access() -> None:
    assessment = assess_candidate_source(
        """\
def boundary_target(total: float, count: int) -> float:
    return getattr(total, "__class__")(0.0)
"""
    )

    assert assessment.hard_disqualifications


def test_static_gate_rejects_computed_dunder_attribute_access() -> None:
    assessment = assess_candidate_source(
        """\
def boundary_target(total: float, count: int) -> float:
    return getattr(total, "__" + "class__")(0.0)
"""
    )

    assert assessment.hard_disqualifications


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known trust-boundary gap: local administrative control currently authenticates "
        "Unix peers by UID/GID only, which does not distinguish the supervised application "
        "from an independent operator when both use the same account."
    ),
)
def test_admin_control_supports_authorization_independent_of_application_uid() -> None:
    parameters = inspect.signature(ControlSocketServer.__init__).parameters
    independent_authorizers = {
        "allowed_pids",
        "peer_authorizer",
        "credential_verifier",
        "authorization_verifier",
    }
    assert independent_authorizers.intersection(parameters)
