"""Original-authoritative shadow and candidate-authoritative mirror primitives.

Shadow execution is deliberately narrower than rollout.  It produces evidence
about a candidate while the deployed implementation remains authoritative.  A
candidate with uncertain or observed external effects must run through an
explicit application-provided isolation adapter.

Candidate-authoritative mirroring is the complementary, opt-in operation: the
candidate result is returned and the deployed implementation is run only as a
comparison oracle.  The comparison invocation is isolated whenever the
contract/evidence gate does not establish safe duplicate execution.
"""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .contracts import Comparator, normalize_comparison_result
from .execution import (
    EffectObservation,
    FunctionExecutionContract,
    ShadowEligibility,
    assess_shadow_eligibility,
)


class ShadowExecutionError(RuntimeError):
    """Raised when a candidate cannot be run safely as shadow work."""


class ShadowExecutionAdapter(Protocol):
    """Application-owned boundary for candidate execution.

    ``isolation_verified`` must only be true when the adapter can prevent the
    candidate's effects from reaching the authoritative application state.  A
    label or candidate claim is not sufficient evidence for this property.
    """

    adapter_id: str
    isolation_verified: bool

    def execute(
        self,
        implementation: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class ShadowExecutionResult:
    """Evidence from one original-authoritative shadow invocation."""

    result: Any
    original_result: Any
    candidate_result: Any
    original_succeeded: bool
    candidate_succeeded: bool
    equivalent: bool | None
    decision_reason: str
    comparison_evidence: Mapping[str, Any] | None = None
    original_exception: BaseException | None = None
    candidate_exception: BaseException | None = None
    adapter_id: str | None = None
    isolation_verified: bool = False
    eligibility: ShadowEligibility | None = None

    @property
    def candidate_authoritative(self) -> bool:
        """Shadow results can never become the application result."""

        return False


@dataclass(frozen=True, slots=True)
class MirroredExecutionResult:
    """Evidence from one candidate-authoritative mirrored invocation.

    ``result`` is the candidate result.  The deployed invocation is comparison
    evidence only and can never replace it.  If the candidate fails, the
    deployed comparison is not attempted; callers may apply their normal
    candidate-failure policy.
    """

    result: Any
    candidate_result: Any
    deployed_result: Any
    candidate_succeeded: bool
    deployed_succeeded: bool | None
    equivalent: bool | None
    decision_reason: str
    comparison_evidence: Mapping[str, Any] | None = None
    candidate_exception: BaseException | None = None
    deployed_exception: BaseException | None = None
    adapter_id: str | None = None
    isolation_verified: bool = False
    eligibility: ShadowEligibility | None = None

    @property
    def candidate_authoritative(self) -> bool:
        return True


def shadow_execute(
    *,
    original: Callable[..., Any],
    candidate: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: FunctionExecutionContract,
    effect_observation: EffectObservation | None = None,
    isolation_adapter: ShadowExecutionAdapter | None = None,
    comparator: Comparator | None = None,
    audit_event: Callable[..., Any] | None = None,
) -> ShadowExecutionResult:
    """Run a candidate as non-authoritative shadow work.

    The deployed implementation runs normally and its result is always
    returned.  The candidate receives an independent input copy.  If the
    contract/evidence assessment requires isolation, an adapter must explicitly
    attest that its boundary is verified; an unverified adapter is rejected.
    """

    eligibility = assess_shadow_eligibility(contract, effect_observation)
    adapter_id: str | None = None
    isolation_verified = False
    if isolation_adapter is not None:
        adapter_id = str(getattr(isolation_adapter, "adapter_id", "")).strip() or None
        if not adapter_id:
            raise ShadowExecutionError("shadow isolation adapter identity is required")
        if not bool(getattr(isolation_adapter, "isolation_verified", False)):
            raise ShadowExecutionError(
                "shadow isolation adapter must provide verified isolation"
            )
        isolation_verified = True
    elif not eligibility.eligible:
        raise ShadowExecutionError(eligibility.reason)

    original_exception: BaseException | None = None
    candidate_exception: BaseException | None = None
    try:
        original_result = original(*copy.deepcopy(args), **copy.deepcopy(kwargs))
        original_succeeded = True
    except BaseException as exc:
        original_result = None
        original_succeeded = False
        original_exception = exc

    candidate_args = copy.deepcopy(args)
    candidate_kwargs = copy.deepcopy(kwargs)
    try:
        if isolation_adapter is None:
            candidate_result = candidate(*candidate_args, **candidate_kwargs)
        else:
            candidate_result = isolation_adapter.execute(
                candidate, candidate_args, candidate_kwargs
            )
        candidate_succeeded = True
    except BaseException as exc:
        candidate_result = None
        candidate_succeeded = False
        candidate_exception = exc

    equivalent: bool | None = None
    comparison_evidence: dict[str, Any] = {
        "candidate_authoritative": False,
        "isolation_verified": isolation_verified,
    }
    if original_succeeded and candidate_succeeded:
        raw = comparator(original_result, candidate_result) if comparator else original_result == candidate_result
        comparison = normalize_comparison_result(raw)
        equivalent = comparison.equivalent
        comparison_evidence.update(comparison.evidence)
        reason = comparison.reason or (
            "shadow candidate returned equivalent output"
            if equivalent
            else "shadow candidate returned a different output"
        )
    elif candidate_succeeded:
        reason = "original failed; candidate result is evidence only"
    elif original_succeeded:
        reason = "candidate failed during shadow execution; original result retained"
    else:
        reason = "both original and candidate failed during shadow execution"

    result = ShadowExecutionResult(
        result=original_result,
        original_result=original_result,
        candidate_result=candidate_result,
        original_succeeded=original_succeeded,
        candidate_succeeded=candidate_succeeded,
        equivalent=equivalent,
        decision_reason=reason,
        comparison_evidence=comparison_evidence,
        original_exception=original_exception,
        candidate_exception=candidate_exception,
        adapter_id=adapter_id,
        isolation_verified=isolation_verified,
        eligibility=eligibility,
    )
    if audit_event is not None:
        audit_event(
            "SHADOW_EXECUTION_DECISION",
            actor={"type": "caretaker", "id": "shadow-executor"},
            scope={"adapter_id": adapter_id} if adapter_id else {},
            outcome={
                "state": "COMPLETED",
                "candidate_authoritative": False,
                "candidate_succeeded": candidate_succeeded,
                "original_succeeded": original_succeeded,
                "equivalent": equivalent,
                "isolation_verified": isolation_verified,
            },
            details={
                "decision_reason": reason[:256],
                "evidence_complete": eligibility.evidence_complete,
                "observed_effects": list(eligibility.observed_effects),
                "observed_external_effects": list(
                    eligibility.observed_external_effects
                ),
            },
        )
    return result


def mirrored_execute(
    *,
    candidate: Callable[..., Any],
    deployed: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: FunctionExecutionContract,
    effect_observation: EffectObservation | None = None,
    isolation_adapter: ShadowExecutionAdapter | None = None,
    comparator: Comparator | None = None,
) -> MirroredExecutionResult:
    """Run a candidate authoritatively and deployed code as comparison evidence.

    The candidate executes first and its result is always authoritative when it
    succeeds.  The deployed comparison receives an independent deep copy of
    inputs and is passed through the verified application-owned adapter when
    duplicate execution is not otherwise eligible.  A comparison mismatch or
    deployed exception is evidence only and never causes an automatic switch.
    """

    eligibility = assess_shadow_eligibility(contract, effect_observation)
    adapter_id: str | None = None
    isolation_verified = False
    if isolation_adapter is not None:
        adapter_id = str(getattr(isolation_adapter, "adapter_id", "")).strip() or None
        if not adapter_id:
            raise ShadowExecutionError("shadow isolation adapter identity is required")
        if not bool(getattr(isolation_adapter, "isolation_verified", False)):
            raise ShadowExecutionError(
                "shadow isolation adapter must provide verified isolation"
            )
        isolation_verified = True
    elif not eligibility.eligible:
        raise ShadowExecutionError(eligibility.reason)

    try:
        candidate_result = candidate(*copy.deepcopy(args), **copy.deepcopy(kwargs))
    except BaseException as exc:
        return MirroredExecutionResult(
            result=None,
            candidate_result=None,
            deployed_result=None,
            candidate_succeeded=False,
            deployed_succeeded=None,
            equivalent=None,
            decision_reason="candidate failed before deployed comparison",
            comparison_evidence={
                "candidate_authoritative": True,
                "deployed_comparison_attempted": False,
                "isolation_verified": isolation_verified,
            },
            candidate_exception=exc,
            adapter_id=adapter_id,
            isolation_verified=isolation_verified,
            eligibility=eligibility,
        )

    deployed_exception: BaseException | None = None
    try:
        deployed_args = copy.deepcopy(args)
        deployed_kwargs = copy.deepcopy(kwargs)
        if isolation_adapter is None:
            deployed_result = deployed(*deployed_args, **deployed_kwargs)
        else:
            deployed_result = isolation_adapter.execute(
                deployed, deployed_args, deployed_kwargs
            )
        deployed_succeeded = True
    except BaseException as exc:
        deployed_result = None
        deployed_succeeded = False
        deployed_exception = exc

    equivalent: bool | None = None
    comparison_evidence: dict[str, Any] = {
        "candidate_authoritative": True,
        "deployed_comparison_attempted": True,
        "isolation_verified": isolation_verified,
    }
    if deployed_succeeded:
        raw = comparator(candidate_result, deployed_result) if comparator else candidate_result == deployed_result
        comparison = normalize_comparison_result(raw)
        equivalent = comparison.equivalent
        comparison_evidence.update(comparison.evidence)
        reason = comparison.reason or (
            "deployed comparison returned equivalent output"
            if equivalent
            else "deployed comparison returned a different output"
        )
    else:
        reason = "deployed comparison failed; candidate result retained"

    return MirroredExecutionResult(
        result=candidate_result,
        candidate_result=candidate_result,
        deployed_result=deployed_result,
        candidate_succeeded=True,
        deployed_succeeded=deployed_succeeded,
        equivalent=equivalent,
        decision_reason=reason,
        comparison_evidence=comparison_evidence,
        deployed_exception=deployed_exception,
        adapter_id=adapter_id,
        isolation_verified=isolation_verified,
        eligibility=eligibility,
    )
