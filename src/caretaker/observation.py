from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

from .contracts import Comparator, normalize_comparison_result
from .domain import CandidateState, ObservationRecord, utcnow
from .policy import ObservationPolicy
from .slot import FunctionSlot, FunctionVersion
from .shadow import (
    ShadowExecutionAdapter,
    ShadowExecutionResult,
    shadow_execute,
)
from .execution import EffectObservation, FunctionExecutionContract
from .state import exception_evidence, value_snapshot
from .store import RepairStore


class DifferentialMismatchError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class DifferentialResult:
    result: Any
    original_result: Any
    candidate_result: Any
    candidate_succeeded: bool
    original_succeeded: bool
    equivalent: bool | None
    state_equivalent: bool | None = None
    decision_reason: str = ""
    comparison_evidence: dict[str, Any] | None = None
    original_exception: BaseException | None = None
    candidate_exception: BaseException | None = None


@dataclass(frozen=True, slots=True)
class ObservationFailureDecision:
    rolled_back: bool
    state: CandidateState | None
    failure_rate: float
    reason: str


class ObservationManager:
    def __init__(self, store: RepairStore) -> None:
        self.store = store

    def record_success(
        self,
        *,
        slot: FunctionSlot,
        call_id: UUID,
        policy: ObservationPolicy,
        output: Any,
        mode: str = "canary",
        rollout_id: UUID | None = None,
        routing_decision_hash: str | None = None,
    ) -> None:
        version = slot.load()
        if version.candidate_id is None:
            return
        session = slot.record_observation_success(acceptance=policy)
        if session is None:
            return
        self.store.record_observation(
            ObservationRecord(
                observation_id=uuid4(),
                target_id=slot.target_id,
                candidate_id=version.candidate_id,
                function_version=version.number,
                call_id=call_id,
                occurred_at=utcnow(),
                mode=mode,
                original_outcome=None,
                candidate_outcome={"succeeded": True, "output": value_snapshot(output)},
                comparison=None,
                counted_as_success=True,
                counted_as_failure=False,
                decision_reason=f"candidate call succeeded; state is {session.state.name}",
                rollout_id=rollout_id,
                routing_decision_hash=routing_decision_hash,
            )
        )

    def record_failure(
        self,
        *,
        slot: FunctionSlot,
        call_id: UUID,
        exception: BaseException,
        policy: ObservationPolicy,
        mode: str = "canary",
        rollout_id: UUID | None = None,
        routing_decision_hash: str | None = None,
    ) -> ObservationFailureDecision:
        version = slot.load()
        if version.candidate_id is None:
            return ObservationFailureDecision(False, None, 0.0, "active version is not a candidate")
        before = slot.observation()
        session = slot.record_observation_failure()
        if session is None:
            return ObservationFailureDecision(False, None, 0.0, "no observation session")
        total = session.successful_executions + session.failed_executions
        failure_rate = session.failed_executions / max(1, total)
        rollback = False
        reason = "candidate call failed during observation"
        prior_state = before.state if before is not None else CandidateState.ACTIVE_PROBATION
        in_probation = (
            before is None
            or before.successful_executions < policy.initial_successful_executions
            or prior_state is CandidateState.ACTIVE_PROBATION
        )
        if in_probation:
            rollback = (
                policy.rollback_during_probation
                and session.failed_executions > policy.probation_failure_budget
            )
            if rollback:
                reason = "probation failure budget exceeded"
        else:
            budget_exceeded = session.failed_executions > policy.long_term_maximum_failures
            rate_exceeded = failure_rate > policy.long_term_failure_rate
            rollback = policy.rollback_after_acceptance and (budget_exceeded or rate_exceeded)
            if rollback:
                reason = "accepted-candidate long-term failure budget exceeded"
            elif budget_exceeded or rate_exceeded:
                reason = "candidate degraded; long-term failure budget exceeded without automatic rollback"
        if rollback and slot.load().number == version.number:
            slot.rollback(version.number)
        self.store.record_observation(
            ObservationRecord(
                observation_id=uuid4(),
                target_id=slot.target_id,
                candidate_id=version.candidate_id,
                function_version=version.number,
                call_id=call_id,
                occurred_at=utcnow(),
                mode=mode,
                original_outcome=None,
                candidate_outcome={
                    "succeeded": False,
                    "exception": exception_evidence(exception, capture_locals=False),
                },
                comparison={
                    "failure_rate": failure_rate,
                    "failure_count": session.failed_executions,
                    "success_count": session.successful_executions,
                    "rolled_back": rollback,
                },
                counted_as_success=False,
                counted_as_failure=True,
                decision_reason=reason,
                rollout_id=rollout_id,
                routing_decision_hash=routing_decision_hash,
            )
        )
        return ObservationFailureDecision(
            rolled_back=rollback,
            state=session.state,
            failure_rate=failure_rate,
            reason=reason,
        )

    def differential_execute(
        self,
        *,
        current: FunctionVersion,
        previous: FunctionVersion,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        comparator: Comparator | None = None,
    ) -> DifferentialResult:
        original_args = copy.deepcopy(args)
        original_kwargs = copy.deepcopy(kwargs)
        candidate_args = copy.deepcopy(args)
        candidate_kwargs = copy.deepcopy(kwargs)

        original_exception: BaseException | None = None
        candidate_exception: BaseException | None = None
        try:
            original_result = previous.implementation(*original_args, **original_kwargs)
            original_succeeded = True
        except BaseException as exc:
            original_exception = exc
            original_result = None
            original_succeeded = False

        try:
            candidate_result = current.implementation(*candidate_args, **candidate_kwargs)
            candidate_succeeded = True
        except BaseException as exc:
            candidate_exception = exc
            candidate_result = None
            candidate_succeeded = False

        if not original_succeeded and candidate_succeeded:
            return DifferentialResult(
                result=candidate_result,
                original_result=original_result,
                candidate_result=candidate_result,
                candidate_succeeded=True,
                original_succeeded=False,
                equivalent=None,
                decision_reason="original failed and candidate succeeded",
                original_exception=original_exception,
            )
        if original_succeeded and not candidate_succeeded:
            return DifferentialResult(
                result=original_result,
                original_result=original_result,
                candidate_result=candidate_result,
                candidate_succeeded=False,
                original_succeeded=True,
                equivalent=None,
                decision_reason="candidate failed and original succeeded",
                candidate_exception=candidate_exception,
            )
        if not original_succeeded and not candidate_succeeded:
            return DifferentialResult(
                result=None,
                original_result=original_result,
                candidate_result=candidate_result,
                candidate_succeeded=False,
                original_succeeded=False,
                equivalent=None,
                decision_reason="both original and candidate failed",
                original_exception=original_exception,
                candidate_exception=candidate_exception,
            )
        raw = comparator(original_result, candidate_result) if comparator else original_result == candidate_result
        comparison = normalize_comparison_result(raw)
        equivalent = comparison.equivalent
        try:
            state_equivalent = (
                original_args == candidate_args
                and original_kwargs == candidate_kwargs
            )
        except Exception:
            state_equivalent = False
        reason = (
            comparison.reason
            or (
                "both versions returned equivalent outputs"
                if equivalent
                else "both versions succeeded but returned different outputs"
            )
        )
        if equivalent and not state_equivalent:
            reason += "; argument state changes differed"
        return DifferentialResult(
            result=candidate_result if equivalent else original_result,
            original_result=original_result,
            candidate_result=candidate_result,
            candidate_succeeded=True,
            original_succeeded=True,
            equivalent=equivalent,
            state_equivalent=state_equivalent,
            decision_reason=reason,
            comparison_evidence={
                **dict(comparison.evidence),
                "argument_state_equivalent": state_equivalent,
            },
        )

    def shadow_execute(
        self,
        *,
        current: FunctionVersion,
        previous: FunctionVersion,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        contract: FunctionExecutionContract,
        effect_observation: EffectObservation | None = None,
        isolation_adapter: ShadowExecutionAdapter | None = None,
        comparator: Comparator | None = None,
        audit_event: Any | None = None,
    ) -> ShadowExecutionResult:
        """Execute the candidate without allowing it to author the result."""

        return shadow_execute(
            original=previous.implementation,
            candidate=current.implementation,
            args=args,
            kwargs=kwargs,
            contract=contract,
            effect_observation=effect_observation,
            isolation_adapter=isolation_adapter,
            comparator=comparator,
            audit_event=audit_event,
        )
