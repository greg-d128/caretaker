"""Original-authoritative shadow execution primitives.

Shadow execution is deliberately narrower than rollout.  It produces evidence
about a candidate while the deployed implementation remains authoritative.  A
candidate with uncertain or observed external effects must run through an
explicit application-provided isolation adapter.
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
