from __future__ import annotations

"""Low-overhead adaptive instrumentation for Caretaker targets and dependencies.

The lightweight wrapper records only threshold counters and elapsed time until policy
promotes a target.  Promotion can enable Guard behavior observation or the existing
full Repair wrapper.  Demotion is independently policy controlled and uses short-term
and long-term acceptance criteria analogous to repaired-function acceptance.
"""

import functools
import hashlib
import inspect
import importlib
import importlib.machinery
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import weakref
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import Any, TypeVar, overload
from uuid import uuid4

from .acceptance import AcceptanceCriteria, long_term_accepted, short_term_accepted
from .adaptive_aggregation import AdaptiveObservationBatcher, SupervisorAdaptiveAggregationStore
from .domain import CandidateState
from .runtime import set_runtime_context

F = TypeVar("F", bound=Callable[..., Any])
_DEPENDENCY_BINDING = object()
_DEPENDENCY_RUNTIME = threading.local()
_STATE_CHECKPOINT_CALLS = 100
_STATE_CHECKPOINT_SECONDS = 30.0
_ADAPTIVE_WORKER_ID = f"{os.getpid()}-{uuid4().hex}"


def _authority_context():
    from .authority import get_authority_runtime_context
    return get_authority_runtime_context()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InstrumentationLevel(Enum):
    """Current observation/execution intensity.

    ``REPAIR`` is retained for API compatibility, but lifecycle stage is the source
    of truth for whether Caretaker is investigating, repairing, or validating a
    candidate.  This keeps observation intensity separate from repair acceptance.
    """

    LIGHTWEIGHT = 0
    BEHAVIOR = 1
    REPAIR = 2


class AdaptiveLifecycleStage(Enum):
    """End-to-end adaptive repair lifecycle.

    The two behavior stages deliberately have different names internally even though
    both are presented to operators as BEHAVIOR.  The first gathers evidence for a
    possible repair; the second observes the newly activated candidate before it is
    allowed to progress through validation and long-term acceptance.
    """

    LIGHTWEIGHT = "lightweight"
    PRE_REPAIR_BEHAVIOR = "pre-repair-behavior"
    REPAIR = "repair"
    POST_REPAIR_BEHAVIOR = "post-repair-behavior"
    VALIDATION = "validation"
    LONG_TERM_ACCEPTANCE = "long-term-acceptance"

    @property
    def operator_label(self) -> str:
        if self in {
            AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR,
            AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR,
        }:
            return "BEHAVIOR"
        return self.name


class AcceptanceState(Enum):
    NONE = "none"
    PROBATION = "probation"
    SHORT_TERM_ACCEPTED = "short-term-accepted"
    LONG_TERM_ACCEPTED = "long-term-accepted"


@dataclass(frozen=True, slots=True)
class ExceptionPromotionPolicy:
    enabled: bool = True
    occurrences: int = 2
    window_seconds: float = 3600.0
    promote_to: InstrumentationLevel = InstrumentationLevel.REPAIR


@dataclass(frozen=True, slots=True)
class SoftTimingPromotionPolicy:
    enabled: bool = False
    seconds: float = 1.0
    occurrences: int = 3
    window_seconds: float = 1800.0
    promote_to: InstrumentationLevel = InstrumentationLevel.BEHAVIOR


@dataclass(frozen=True, slots=True)
class BehaviorSamplingPolicy:
    """Call-count sampling rates for low-overhead behavioral observation.

    A value of zero disables periodic sampling at that level. Randomization is
    applied only once per code generation so the hot path is an integer increment
    and comparison rather than a clock or random-number operation.
    """

    enabled: bool = True
    lightweight_every_calls: int = 10_000
    behavior_every_calls: int = 10
    randomize_initial_offset: bool = True


@dataclass(frozen=True, slots=True)
class RepairEvidencePolicy:
    """Evidence required before a repair-requesting signal may enter REPAIR."""

    enabled: bool = True
    minimum_behavior_samples: int = 20
    minimum_observation_calls: int = 100
    minimum_duration_seconds: float = 30.0
    require_problem_reproduction: bool = True


@dataclass(frozen=True, slots=True)
class InstrumentationDemotionPolicy(AcceptanceCriteria):
    """Acceptance criteria required before promoted observation may step down.

    The thresholds are inherited from the same ``AcceptanceCriteria`` used by
    repaired-function observation.  Only the action after acceptance differs:
    this policy controls observation demotion rather than candidate rollback.
    """

    enabled: bool = False
    initial_successful_executions: int = 10
    long_term_successful_executions: int = 100
    long_term_minimum_duration_seconds: float = 3600.0
    probation_failure_budget: int = 0
    long_term_maximum_failures: int = 1
    long_term_failure_rate: float = 0.001
    stepwise: bool = True


@dataclass(frozen=True, slots=True)
class AdaptiveAggregationPolicy:
    """Optional worker batching for supervisor-owned adaptive evidence."""

    enabled: bool = False
    flush_after_observations: int = 64
    flush_interval_seconds: float = 5.0


@dataclass(frozen=True, slots=True)
class LightweightPolicy:
    exception: ExceptionPromotionPolicy = field(default_factory=ExceptionPromotionPolicy)
    soft_timing: SoftTimingPromotionPolicy = field(default_factory=SoftTimingPromotionPolicy)
    sampling: BehaviorSamplingPolicy = field(default_factory=BehaviorSamplingPolicy)
    repair_evidence: RepairEvidencePolicy = field(default_factory=RepairEvidencePolicy)
    demotion: InstrumentationDemotionPolicy = field(default_factory=InstrumentationDemotionPolicy)
    aggregation: AdaptiveAggregationPolicy = field(default_factory=AdaptiveAggregationPolicy)
    initial_level: InstrumentationLevel = InstrumentationLevel.LIGHTWEIGHT
    behavior_executions: int = 100
    persist_state: bool = True


@dataclass(slots=True)
class AdaptiveInstrumentationState:
    target_id: str
    code_hash: str
    level: InstrumentationLevel
    stage: AdaptiveLifecycleStage = AdaptiveLifecycleStage.LIGHTWEIGHT
    acceptance: AcceptanceState = AcceptanceState.NONE
    promoted_at: str | None = None
    promotion_reason: str | None = None
    promotion_requested_by: str | None = None
    promotion_authority_generation: str | None = None
    promotion_authority_fingerprint: str | None = None
    promotion_outcome: str | None = None
    promotion_outcome_at: str | None = None
    promotion_snapshot_id: str | None = None
    short_term_accepted_at: str | None = None
    long_term_accepted_at: str | None = None
    successful_executions: int = 0
    probation_failures: int = 0
    long_term_successes: int = 0
    long_term_failures: int = 0
    last_transition_at: str | None = None
    behavior_started_at: str | None = None
    behavior_observation_calls: int = 0
    behavior_samples: int = 0
    repair_evidence_samples: int = 0
    problem_reproductions: int = 0
    repair_requested: bool = False
    repair_request_reason: str | None = None
    repair_evidence_satisfied_at: str | None = None
    repair_candidate_id: str | None = None
    repair_candidate_version: int | None = None
    post_repair_behavior_started_at: str | None = None
    validation_started_at: str | None = None
    sampling_call_counter: int = 0
    recent_diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def public_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "code_hash": self.code_hash,
            "level": self.level.name,
            "stage": self.stage.value,
            "stage_label": self.stage.operator_label,
            "acceptance": self.acceptance.value,
            "promoted_at": self.promoted_at,
            "promotion_reason": self.promotion_reason,
            "promotion_requested_by": self.promotion_requested_by,
            "promotion_authority_generation": self.promotion_authority_generation,
            "promotion_authority_fingerprint": self.promotion_authority_fingerprint,
            "promotion_outcome": self.promotion_outcome,
            "promotion_outcome_at": self.promotion_outcome_at,
            "promotion_snapshot_id": self.promotion_snapshot_id,
            "short_term_accepted_at": self.short_term_accepted_at,
            "long_term_accepted_at": self.long_term_accepted_at,
            "successful_executions": self.successful_executions,
            "probation_failures": self.probation_failures,
            "long_term_successes": self.long_term_successes,
            "long_term_failures": self.long_term_failures,
            "last_transition_at": self.last_transition_at,
            "behavior_started_at": self.behavior_started_at,
            "behavior_observation_calls": self.behavior_observation_calls,
            "behavior_samples": self.behavior_samples,
            "repair_evidence_samples": self.repair_evidence_samples,
            "problem_reproductions": self.problem_reproductions,
            "repair_requested": self.repair_requested,
            "repair_request_reason": self.repair_request_reason,
            "repair_evidence_satisfied_at": self.repair_evidence_satisfied_at,
            "repair_candidate_id": self.repair_candidate_id,
            "repair_candidate_version": self.repair_candidate_version,
            "post_repair_behavior_started_at": self.post_repair_behavior_started_at,
            "validation_started_at": self.validation_started_at,
            "sampling_call_counter": self.sampling_call_counter,
            "recent_diagnostics": list(self.recent_diagnostics),
        }


_STATE_REGISTRY: dict[str, AdaptiveInstrumentationState] = {}
_STATE_REGISTRY_LOCK = threading.RLock()
_CONTROLLER_REGISTRY: weakref.WeakValueDictionary[str, Any] = weakref.WeakValueDictionary()


def adaptive_states() -> tuple[Mapping[str, Any], ...]:
    with _STATE_REGISTRY_LOCK:
        return tuple(
            state.public_dict()
            for _, state in sorted(_STATE_REGISTRY.items(), key=lambda item: item[0])
        )


def get_adaptive_state(target_id: str) -> Mapping[str, Any] | None:
    with _STATE_REGISTRY_LOCK:
        state = _STATE_REGISTRY.get(target_id)
        return None if state is None else state.public_dict()


def get_adaptive_controller(target_id: str) -> Any | None:
    """Return a live adaptive controller for an application-registered target.

    The registry is deliberately weak: it provides an operator/Guard lookup for
    wrappers that are still installed without retaining application targets or
    changing their lifecycle.
    """
    with _STATE_REGISTRY_LOCK:
        return _CONTROLLER_REGISTRY.get(target_id)


def adaptive_aggregation_status() -> tuple[Mapping[str, Any], ...]:
    """Return worker batcher context for supervisor reconciliation."""
    with _STATE_REGISTRY_LOCK:
        controllers = tuple(_CONTROLLER_REGISTRY.values())
    return tuple(
        controller.aggregation_status()
        for controller in controllers
        if hasattr(controller, "aggregation_status")
    )


def _initial_stage(level: InstrumentationLevel) -> AdaptiveLifecycleStage:
    if level is InstrumentationLevel.LIGHTWEIGHT:
        return AdaptiveLifecycleStage.LIGHTWEIGHT
    if level is InstrumentationLevel.REPAIR:
        return AdaptiveLifecycleStage.REPAIR
    return AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR


def _loaded_stage(data: Mapping[str, Any]) -> AdaptiveLifecycleStage:
    raw = data.get("stage")
    if raw is not None:
        try:
            return AdaptiveLifecycleStage(str(raw))
        except ValueError:
            pass
    # Backward-compatible migration for adaptive state written before lifecycle
    # stages were explicit.
    try:
        level = InstrumentationLevel[str(data.get("level", "LIGHTWEIGHT"))]
    except KeyError:
        level = InstrumentationLevel.LIGHTWEIGHT
    return _initial_stage(level)


def validate_lightweight_policy(policy: LightweightPolicy) -> None:
    errors: list[str] = []
    for name, promotion in (("exception", policy.exception), ("soft_timing", policy.soft_timing)):
        if promotion.occurrences <= 0:
            errors.append(f"{name}.occurrences must be greater than zero")
        if promotion.window_seconds <= 0:
            errors.append(f"{name}.window_seconds must be greater than zero")
        if promotion.promote_to is InstrumentationLevel.LIGHTWEIGHT:
            errors.append(f"{name}.promote_to must be BEHAVIOR or REPAIR")
    if policy.soft_timing.seconds <= 0:
        errors.append("soft_timing.seconds must be greater than zero")
    if policy.behavior_executions <= 0:
        errors.append("behavior_executions must be greater than zero")
    sampling = policy.sampling
    if sampling.lightweight_every_calls < 0:
        errors.append("sampling.lightweight_every_calls cannot be negative")
    if sampling.behavior_every_calls < 0:
        errors.append("sampling.behavior_every_calls cannot be negative")
    evidence = policy.repair_evidence
    if evidence.minimum_behavior_samples < 0:
        errors.append("repair_evidence.minimum_behavior_samples cannot be negative")
    if evidence.minimum_observation_calls < 0:
        errors.append("repair_evidence.minimum_observation_calls cannot be negative")
    if evidence.minimum_duration_seconds < 0:
        errors.append("repair_evidence.minimum_duration_seconds cannot be negative")
    if (
        evidence.enabled
        and evidence.minimum_behavior_samples == 0
        and evidence.minimum_observation_calls == 0
        and evidence.minimum_duration_seconds == 0
        and not evidence.require_problem_reproduction
    ):
        errors.append(
            "repair_evidence must require at least one post-promotion observation "
            "before automatic repair"
        )
    demotion = policy.demotion
    if demotion.initial_successful_executions < 0:
        errors.append("demotion.initial_successful_executions cannot be negative")
    if demotion.long_term_successful_executions < demotion.initial_successful_executions:
        errors.append("demotion.long_term_successful_executions cannot be lower than the initial threshold")
    if demotion.long_term_minimum_duration_seconds < 0:
        errors.append("demotion.long_term_minimum_duration_seconds cannot be negative")
    if demotion.probation_failure_budget < 0:
        errors.append("demotion.probation_failure_budget cannot be negative")
    if demotion.long_term_maximum_failures < 0:
        errors.append("demotion.long_term_maximum_failures cannot be negative")
    if not 0 <= demotion.long_term_failure_rate <= 1:
        errors.append("demotion.long_term_failure_rate must be between 0 and 1")
    aggregation = policy.aggregation
    if not 1 <= aggregation.flush_after_observations <= 1000:
        errors.append("aggregation.flush_after_observations must be between 1 and 1000")
    if aggregation.flush_interval_seconds < 0:
        errors.append("aggregation.flush_interval_seconds cannot be negative")
    if errors:
        raise ValueError("Invalid LightweightPolicy: " + "; ".join(errors))


class _AdaptiveController:
    def __init__(
        self,
        function: Callable[..., Any],
        *,
        target_id: str,
        policy: LightweightPolicy,
        repair_policy: Any | None,
        engine: Any | None,
        behavior_binding: Any,
        state_directory: str | Path | None,
        allow_repair_promotion: bool,
    ) -> None:
        self.function = function
        self.target_id = target_id
        self.declared_policy = policy
        self.repair_policy = repair_policy
        self.engine = engine
        self.behavior_binding = behavior_binding
        self.allow_repair_promotion = allow_repair_promotion
        self.code_hash = _function_hash(function)
        self._code_object = getattr(function, "__code__", None)
        self._state_directory = state_directory
        self._lock = threading.RLock()
        self._exception_events: deque[float] = deque()
        self._timing_events: deque[float] = deque()
        self._managed_wrapper: Callable[..., Any] | None = None
        self._behavior_registered = False
        self._behavior_lease_remaining = 0
        self._dirty_state_calls = 0
        self._last_checkpoint_monotonic = time.monotonic()
        self._authority_fingerprint: str | None = None
        self._stale_persisted_state = False
        self._aggregation_batcher: AdaptiveObservationBatcher | None = None
        self.policy = self._effective_policy()
        validate_lightweight_policy(self.policy)
        self._policy_fingerprint = _policy_hash(self.policy)
        self._state_path = _state_path(target_id, self.code_hash, self._state_directory) if self.policy.persist_state else None
        loaded = self._load_state()
        if loaded is None:
            self.state = AdaptiveInstrumentationState(
                target_id=target_id,
                code_hash=self.code_hash,
                level=self.policy.initial_level,
                stage=_initial_stage(self.policy.initial_level),
            )
            self._initialize_generation_state()
            if self._stale_persisted_state:
                # Replace state written under a different policy/authority generation
                # immediately so a later restart cannot resurrect stale escalation or
                # acceptance counters. Ordinary fresh LIGHTWEIGHT initialization still
                # performs no filesystem write.
                self._persist()
        else:
            self.state = loaded
            if self.state.level.value >= InstrumentationLevel.BEHAVIOR.value and self.state.behavior_started_at is None:
                self.state.behavior_started_at = utcnow_iso()
        self._configure_aggregation_batcher()
        with _STATE_REGISTRY_LOCK:
            _CONTROLLER_REGISTRY[self.target_id] = self
        self._publish_state()

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        dependency_boundary = not self.allow_repair_promotion
        dependency_depth = int(getattr(_DEPENDENCY_RUNTIME, "depth", 0))
        if dependency_boundary and dependency_depth:
            # Caretaker's own telemetry can call an instrumented dependency while
            # observing another dependency. The inner call must always retain a
            # non-instrumented path or Guard/evidence storage can recurse into itself.
            return self.function(*args, **kwargs)

        if dependency_boundary:
            _DEPENDENCY_RUNTIME.depth = dependency_depth + 1
        try:
            with self._lock:
                self._refresh_generation_if_needed()
                self._refresh_policy_if_needed()
                self._sync_repair_lifecycle()
                level = self.state.level
                stage = self.state.stage
                sample_behavior = self._advance_sampling_counter(level)
                if level is InstrumentationLevel.BEHAVIOR:
                    self.state.behavior_observation_calls += 1
                    self._record_aggregation(behavior_observation_calls=1)

            timing_enabled = self.policy.soft_timing.enabled
            started = time.perf_counter() if timing_enabled else None
            failed = False
            transitioned_during_call = False
            try:
                if stage is AdaptiveLifecycleStage.REPAIR and self.allow_repair_promotion:
                    result = self._repair_call(*args, **kwargs)
                elif stage in {
                    AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR,
                    AdaptiveLifecycleStage.VALIDATION,
                    AdaptiveLifecycleStage.LONG_TERM_ACCEPTANCE,
                } and self.allow_repair_promotion:
                    # Candidate execution must continue through the Repair wrapper so
                    # FunctionSlot observation/rollback semantics remain authoritative.
                    # Adaptive BEHAVIOR sampling adds lifecycle evidence but never
                    # bypasses the active repaired implementation.
                    if sample_behavior:
                        self._record_behavior_sample(InstrumentationLevel.BEHAVIOR)
                    result = self._repair_call(*args, **kwargs)
                elif sample_behavior:
                    result = self._behavior_call(level, *args, **kwargs)
                else:
                    result = self.function(*args, **kwargs)
                return result
            except BaseException as exc:
                failed = True
                transitioned_during_call = self._observe_exception(exc, observed_level=level)
                raise
            finally:
                elapsed = (time.perf_counter() - started) if started is not None else 0.0
                timing_breach, timing_transition = (
                    self._observe_timing(elapsed, observed_level=level)
                    if timing_enabled
                    else (False, False)
                )
                transitioned_during_call = transitioned_during_call or timing_transition
                repair_transition = self._maybe_promote_repair()
                transitioned_during_call = transitioned_during_call or repair_transition
                lifecycle_transition = self._sync_repair_lifecycle()
                transitioned_during_call = transitioned_during_call or lifecycle_transition
                if not transitioned_during_call:
                    self._observe_acceptance(success=(not failed and not timing_breach))
        finally:
            if dependency_boundary:
                _DEPENDENCY_RUNTIME.depth = dependency_depth

    def _engine(self) -> Any:
        if self.engine is not None:
            return self.engine
        from .decorators.api import get_default_engine
        self.engine = get_default_engine()
        return self.engine

    def _resolve_guard_binding(self) -> tuple[Any | None, Any]:
        engine = self._engine()
        guard = getattr(engine, "guard", None)
        if guard is None:
            try:
                from .operator import get_operator_runtime_registry
                guards = get_operator_runtime_registry().guard_engines()
                guard = guards[0] if guards else None
            except Exception:
                guard = None
        binding = self.behavior_binding
        if binding is _DEPENDENCY_BINDING:
            from .guard.policy import GuardBinding
            binding = GuardBinding(
                enabled=True,
                observe_network=True,
                observe_filesystem=True,
                observe_subprocesses=True,
                observe_imports=True,
            )
            self.behavior_binding = binding
        return guard, binding

    def _register_behavior_target(self, guard: Any, binding: Any) -> None:
        kwargs: dict[str, Any] = {"periodic": self.allow_repair_promotion}
        try:
            parameters = inspect.signature(guard.register_target).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "monitoring_configuration" in parameters:
            kwargs["monitoring_configuration"] = {
                "adaptive_monitoring_fingerprint": _monitoring_policy_hash(self.policy),
            }
        guard.register_target(self.target_id, self.function, binding, **kwargs)

    def prepare_guard_registration(self) -> bool:
        """Register the behavior target before Guard hooks are installed.

        Dependency-module instrumentation is normally installed during application
        initialization.  Pre-registering the original callable lets Guard build its
        post-load identity and inspection state before global hooks become active,
        while still leaving the dependency on the cheap LIGHTWEIGHT call path.
        """
        with self._lock:
            guard, binding = self._resolve_guard_binding()
            if guard is None or not binding.enabled:
                return False
            if not self._behavior_registered:
                self._register_behavior_target(guard, binding)
                self._behavior_registered = True
            return True

    def _ensure_behavior_lease(self, guard: Any, binding: Any) -> bool:
        if guard is None or not binding.enabled:
            return False
        if not self._behavior_registered:
            self._register_behavior_target(guard, binding)
            self._behavior_registered = True
        if self._behavior_lease_remaining <= 0:
            from .guard.models import GuardMode
            guard.request_instrumentation(
                self.target_id,
                GuardMode.RESEARCH,
                execution_count=self.policy.behavior_executions,
                reason=self.state.promotion_reason or "adaptive lightweight behavior sample",
            )
            self._behavior_lease_remaining = max(1, self.policy.behavior_executions)
        return True

    def _behavior_call(self, observed_level: InstrumentationLevel, *args: Any, **kwargs: Any) -> Any:
        guard, binding = self._resolve_guard_binding()
        if not self._ensure_behavior_lease(guard, binding):
            return self.function(*args, **kwargs)
        call_id = uuid4()
        tokens = set_runtime_context(
            target_id=self.target_id,
            call_id=call_id,
            operation="adaptive-behavior-call",
            observation_stage=observed_level.name,
            monitoring_fingerprint=_monitoring_policy_hash(self.policy),
        )
        started = time.perf_counter()
        succeeded = False
        guard.before_call(self.target_id, self.function, call_id, candidate_id=None)
        self._behavior_lease_remaining = max(0, self._behavior_lease_remaining - 1)
        self._record_behavior_sample(observed_level)
        try:
            result = self.function(*args, **kwargs)
            succeeded = True
            return result
        finally:
            guard.after_call(
                self.target_id,
                self.function,
                call_id,
                candidate_id=None,
                succeeded=succeeded,
                elapsed_seconds=time.perf_counter() - started,
                result=result if succeeded else None,
            )
            tokens.reset()

    def _repair_call(self, *args: Any, **kwargs: Any) -> Any:
        if self._managed_wrapper is None:
            from .decorators.api import repair
            if self.repair_policy is None:
                from .policy import DEFAULT_POLICY
                selected_policy = DEFAULT_POLICY
            else:
                selected_policy = self.repair_policy
            self._managed_wrapper = repair(
                policy=selected_policy,
                engine=self._engine(),
                target_id=self.target_id,
            )(self.function)
        return self._managed_wrapper(*args, **kwargs)

    def _repair_target(self) -> Any | None:
        if not self.allow_repair_promotion:
            return None
        try:
            registry = getattr(self._engine(), "registry", None)
            if registry is None:
                return None
            finder = getattr(registry, "find", None)
            if finder is None:
                return None
            return finder(self.target_id)
        except Exception:
            return None

    def _sync_repair_lifecycle(self) -> bool:
        """Mirror FunctionSlot candidate state into the adaptive lifecycle.

        FunctionSlot remains authoritative for candidate activation, rollback, short-
        term validation, and long-term acceptance.  The adaptive controller owns only
        the surrounding observation intensity and the pre-repair evidence gate.
        """
        target = self._repair_target()
        if target is None:
            return False
        try:
            version = target.slot.load()
        except Exception:
            return False

        candidate_id = getattr(version, "candidate_id", None)
        candidate_state = getattr(version, "candidate_state", None)
        stage = self.state.stage

        if candidate_id is None:
            if stage in {
                AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR,
                AdaptiveLifecycleStage.VALIDATION,
                AdaptiveLifecycleStage.LONG_TERM_ACCEPTANCE,
            }:
                # The candidate was rolled back or superseded. Return to behavioral
                # investigation rather than pretending the repaired lifecycle remains
                # accepted. A future signal may request a new repair episode.
                return self._transition_stage(
                    AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR,
                    level=InstrumentationLevel.BEHAVIOR,
                    reason="repair candidate no longer active; returned to behavior observation",
                    clear_candidate=True,
                )
            return False

        candidate_text = str(candidate_id)
        candidate_version = int(getattr(version, "number", 0))
        self.state.repair_candidate_id = candidate_text
        self.state.repair_candidate_version = candidate_version

        if candidate_state is CandidateState.LONG_TERM_ACCEPTED:
            changed = self._transition_stage(
                AdaptiveLifecycleStage.LONG_TERM_ACCEPTANCE,
                level=(
                    InstrumentationLevel.LIGHTWEIGHT
                    if self.policy.demotion.enabled
                    else InstrumentationLevel.BEHAVIOR
                ),
                reason="repair candidate reached long-term acceptance",
            )
            if self.state.long_term_accepted_at is None:
                self.state.long_term_accepted_at = utcnow_iso()
                changed = True
            if changed:
                self._persist()
                self._publish_state()
            return changed

        if candidate_state is CandidateState.INITIALLY_VALIDATED:
            return self._transition_stage(
                AdaptiveLifecycleStage.VALIDATION,
                level=InstrumentationLevel.BEHAVIOR,
                reason="repair candidate passed post-repair behavior probation",
            )

        # ACTIVE_PROBATION and DEGRADED both remain in post-repair BEHAVIOR. A
        # degraded candidate may subsequently be rolled back by ObservationManager.
        if candidate_state in {CandidateState.ACTIVE_PROBATION, CandidateState.DEGRADED}:
            return self._transition_stage(
                AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR,
                level=InstrumentationLevel.BEHAVIOR,
                reason="repair candidate active; collecting post-repair behavior",
            )
        return False

    def _transition_stage(
        self,
        stage: AdaptiveLifecycleStage,
        *,
        level: InstrumentationLevel,
        reason: str,
        clear_candidate: bool = False,
    ) -> bool:
        changed = self.state.stage is not stage or self.state.level is not level
        if not changed and not clear_candidate:
            return False
        now = utcnow_iso()
        self.state.stage = stage
        self.state.level = level
        self.state.last_transition_at = now
        self.state.promotion_reason = reason
        self.state.sampling_call_counter = 0
        self._behavior_lease_remaining = 0

        if stage is AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR:
            self.state.behavior_started_at = now
            self.state.post_repair_behavior_started_at = None
            self.state.validation_started_at = None
            self.state.long_term_accepted_at = None
        elif stage is AdaptiveLifecycleStage.REPAIR:
            self.state.acceptance = AcceptanceState.NONE
        elif stage is AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR:
            if self.state.post_repair_behavior_started_at is None:
                self.state.post_repair_behavior_started_at = now
            self.state.validation_started_at = None
            self.state.long_term_accepted_at = None
            self.state.acceptance = AcceptanceState.PROBATION
            self.state.repair_requested = False
        elif stage is AdaptiveLifecycleStage.VALIDATION:
            if self.state.validation_started_at is None:
                self.state.validation_started_at = now
            self.state.acceptance = AcceptanceState.SHORT_TERM_ACCEPTED
        elif stage is AdaptiveLifecycleStage.LONG_TERM_ACCEPTANCE:
            self.state.acceptance = AcceptanceState.LONG_TERM_ACCEPTED

        if clear_candidate:
            self.state.repair_candidate_id = None
            self.state.repair_candidate_version = None
            self.state.post_repair_behavior_started_at = None
            self.state.validation_started_at = None
            self.state.long_term_accepted_at = None
            self.state.acceptance = AcceptanceState.PROBATION
            self.state.repair_requested = False
            self.state.repair_request_reason = None

        self._persist()
        self._publish_state()
        return True

    def _observe_exception(
        self,
        exception: BaseException,
        *,
        observed_level: InstrumentationLevel,
    ) -> bool:
        now = time.time()
        transitioned = False
        with self._lock:
            self._record_aggregation(exception_count=1, event_kind="exception")
            if observed_level.value >= InstrumentationLevel.BEHAVIOR.value:
                self._diagnostic({
                    "timestamp": utcnow_iso(),
                    "kind": "exception",
                    "exception_type": type(exception).__name__,
                })
                if observed_level is InstrumentationLevel.BEHAVIOR:
                    self._record_problem_reproduction("exception")
            policy = self.policy.exception
            if policy.enabled:
                self._append_window(self._exception_events, now, policy.window_seconds)
                self._persist_event_state()
                if len(self._exception_events) >= policy.occurrences:
                    transitioned = self._request_signal_escalation(
                        policy.promote_to,
                        f"{policy.occurrences} exceptions within {policy.window_seconds:g}s",
                    )
        return transitioned

    def _observe_timing(
        self,
        elapsed: float,
        *,
        observed_level: InstrumentationLevel,
    ) -> tuple[bool, bool]:
        policy = self.policy.soft_timing
        if not policy.enabled or elapsed <= policy.seconds:
            return False, False
        now = time.time()
        transitioned = False
        with self._lock:
            self._record_aggregation(timing_breach_count=1, event_kind="timing")
            if observed_level.value >= InstrumentationLevel.BEHAVIOR.value:
                self._diagnostic({
                    "timestamp": utcnow_iso(),
                    "kind": "soft-timing-breach",
                    "elapsed_seconds": elapsed,
                    "threshold_seconds": policy.seconds,
                })
                if observed_level is InstrumentationLevel.BEHAVIOR:
                    self._record_problem_reproduction("soft-timing-breach")
            self._append_window(self._timing_events, now, policy.window_seconds)
            self._persist_event_state()
            if len(self._timing_events) >= policy.occurrences:
                transitioned = self._request_signal_escalation(
                    policy.promote_to,
                    f"{policy.occurrences} soft timing breaches > {policy.seconds:g}s within {policy.window_seconds:g}s",
                )
        return True, transitioned

    def _request_signal_escalation(self, requested: InstrumentationLevel, reason: str) -> bool:
        """Turn a detection signal into investigation first, never directly into repair."""
        if self.state.stage in {
            AdaptiveLifecycleStage.REPAIR,
            AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR,
            AdaptiveLifecycleStage.VALIDATION,
            AdaptiveLifecycleStage.LONG_TERM_ACCEPTANCE,
        }:
            # Once a repair episode has started, FunctionSlot/ObservationManager own
            # candidate failure and rollback decisions. Adaptive signals remain
            # diagnostics rather than opening a competing repair state machine.
            return False

        # When supervisor aggregation is enabled, process-local workers only
        # collect evidence. The supervisor evaluates application-wide thresholds
        # and issues a context-bound Behavior request; this prevents each worker
        # from independently promoting the same target and double-counting the
        # transition.
        if self._aggregation_batcher is not None:
            return False

        if requested is InstrumentationLevel.REPAIR and self.allow_repair_promotion:
            self.state.repair_requested = True
            self.state.repair_request_reason = reason
        elif requested is InstrumentationLevel.REPAIR:
            requested = InstrumentationLevel.BEHAVIOR

        if self.state.stage is AdaptiveLifecycleStage.LIGHTWEIGHT:
            return self._promote(InstrumentationLevel.BEHAVIOR, reason)
        if self.state.stage is AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR:
            self._persist()
            self._publish_state()
        return False

    def request_behavior_promotion(
        self,
        reason: str,
        *,
        requested_by: str | None = None,
    ) -> bool:
        """Promote this target to pre-repair Behavior on an authorized request.

        This is intentionally narrower than the signal path: it never accepts a
        requested level and therefore cannot turn an operator request into Repair.
        The effective lightweight policy and authority generation are refreshed
        before changing state, just as they are for an application signal.
        """
        with self._lock:
            self._refresh_generation_if_needed()
            self._refresh_policy_if_needed()
            if self.state.stage is not AdaptiveLifecycleStage.LIGHTWEIGHT:
                return False
            if self.state.level is not InstrumentationLevel.LIGHTWEIGHT:
                return False
            authority = _authority_context().effective
            self.state.promotion_requested_by = requested_by
            self.state.promotion_authority_generation = str(authority.generation)
            self.state.promotion_authority_fingerprint = authority.fingerprint
            self.state.promotion_outcome = "ACTIVE"
            self.state.promotion_outcome_at = None
            self.state.promotion_snapshot_id = None
            return self._promote(
                InstrumentationLevel.BEHAVIOR,
                reason,
            )

    def apply_supervisor_transition(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Validate and apply one supervisor-issued Behavior transition.

        The request is evidence coordination, not a grant of Repair authority.
        Exact target, code, policy, monitoring, and authority context must match
        this worker's current episode before the local state can change.
        """
        if not isinstance(request, Mapping):
            raise ValueError("supervisor transition request must be an object")
        request_id = str(request.get("request_id") or "").strip()
        if not request_id:
            raise ValueError("supervisor transition request requires request_id")
        if str(request.get("requested_level") or "").upper() != "BEHAVIOR":
            raise PermissionError("supervisor transition may request Behavior only")
        with self._lock:
            self._refresh_generation_if_needed()
            self._refresh_policy_if_needed()
            expected = {
                "target_id": self.target_id,
                "generation_id": self.code_hash,
                "code_hash": self.code_hash,
                "monitoring_fingerprint": _monitoring_policy_hash(self.policy),
                "policy_fingerprint": self._policy_fingerprint,
                "authority_policy_generation": str(_authority_context().effective.generation),
                "authority_policy_fingerprint": self._authority_fingerprint,
            }
            for name, value in expected.items():
                if str(request.get(name) or "") != str(value or ""):
                    raise PermissionError(
                        f"supervisor transition {name} does not match worker context"
                    )
            if self.state.level.value >= InstrumentationLevel.BEHAVIOR.value:
                return {
                    "request_id": request_id,
                    "applied": True,
                    "changed": False,
                    "observed_level": self.state.level.name,
                }
            changed = self.request_behavior_promotion(
                str(request.get("reason") or "supervisor adaptive threshold")[:512],
                requested_by=f"SUPERVISOR:{request_id}"[:200],
            )
            return {
                "request_id": request_id,
                "applied": self.state.level is InstrumentationLevel.BEHAVIOR,
                "changed": changed,
                "observed_level": self.state.level.name,
            }

    def record_behavior_promotion_outcome(
        self,
        outcome: str,
        *,
        snapshot_id: str | None = None,
    ) -> bool:
        """Persist the bounded collection outcome for an explicit promotion."""
        normalized = str(outcome).strip().upper()
        if normalized not in {"ACTIVE", "CAPTURED", "DEFERRED", "FAILED", "SUPERSEDED"}:
            raise ValueError("behavior promotion outcome is invalid")
        with self._lock:
            if self.state.promotion_requested_by is None:
                return False
            changed = (
                self.state.promotion_outcome != normalized
                or (snapshot_id is not None and self.state.promotion_snapshot_id != snapshot_id)
            )
            if not changed:
                return False
            self.state.promotion_outcome = normalized
            self.state.promotion_outcome_at = utcnow_iso()
            if snapshot_id is not None:
                self.state.promotion_snapshot_id = str(snapshot_id)[:128]
            self._persist()
            self._publish_state()
            return True

    def _maybe_promote_repair(self) -> bool:
        with self._lock:
            if (
                self.state.level is not InstrumentationLevel.BEHAVIOR
                or not self.state.repair_requested
                or not self.allow_repair_promotion
            ):
                return False
            evidence = self.policy.repair_evidence
            if not evidence.enabled or not self._repair_evidence_sufficient(evidence):
                return False
            now = utcnow_iso()
            self.state.repair_evidence_satisfied_at = now
            reason = self.state.repair_request_reason or "repair-requesting lightweight signal"
            return self._promote(
                InstrumentationLevel.REPAIR,
                f"evidence sufficient after behavioral observation: {reason}",
            )

    def _repair_evidence_sufficient(self, policy: RepairEvidencePolicy) -> bool:
        if self.state.repair_evidence_samples < policy.minimum_behavior_samples:
            return False
        if self.state.behavior_observation_calls < policy.minimum_observation_calls:
            return False
        if policy.require_problem_reproduction and self.state.problem_reproductions <= 0:
            return False
        started = self.state.behavior_started_at
        if started is None:
            return False
        try:
            started_at = datetime.fromisoformat(started).timestamp()
        except ValueError:
            return False
        return (time.time() - started_at) >= policy.minimum_duration_seconds

    def _record_problem_reproduction(self, kind: str) -> None:
        self.state.problem_reproductions += 1
        self._record_aggregation(problem_reproductions=1)
        self._diagnostic({
            "timestamp": utcnow_iso(),
            "kind": "repair-evidence-reproduction",
            "signal": kind,
            "count": self.state.problem_reproductions,
        })

    def _promote(self, requested: InstrumentationLevel, reason: str) -> bool:
        if requested is InstrumentationLevel.REPAIR and not self.allow_repair_promotion:
            requested = InstrumentationLevel.BEHAVIOR
        if requested.value <= self.state.level.value:
            return False
        now = utcnow_iso()
        previous = self.state.level
        self.state.level = requested
        self.state.stage = (
            AdaptiveLifecycleStage.REPAIR
            if requested is InstrumentationLevel.REPAIR
            else AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR
        )
        self.state.acceptance = (
            AcceptanceState.NONE
            if requested is InstrumentationLevel.REPAIR
            else AcceptanceState.PROBATION
        )
        self.state.promoted_at = now
        self.state.promotion_reason = reason
        self.state.short_term_accepted_at = None
        self.state.long_term_accepted_at = None
        self.state.successful_executions = 0
        self.state.probation_failures = 0
        self.state.long_term_successes = 0
        self.state.long_term_failures = 0
        self.state.last_transition_at = now
        self.state.sampling_call_counter = 0
        self._behavior_lease_remaining = 0
        if previous is InstrumentationLevel.LIGHTWEIGHT and requested is InstrumentationLevel.BEHAVIOR:
            self.state.behavior_started_at = now
            self.state.behavior_observation_calls = 0
            self.state.repair_evidence_samples = 0
            self.state.problem_reproductions = 0
            self.state.repair_evidence_satisfied_at = None
        if requested is InstrumentationLevel.REPAIR:
            self.state.repair_requested = False
        self._exception_events.clear()
        self._timing_events.clear()
        self._persist()
        self._publish_state()
        return True

    def _initialize_generation_state(self) -> None:
        if self.state.level.value >= InstrumentationLevel.BEHAVIOR.value:
            self.state.behavior_started_at = utcnow_iso()
        interval = self._sample_interval(self.state.level)
        if (
            self.policy.sampling.enabled
            and self.policy.sampling.randomize_initial_offset
            and interval > 1
        ):
            self.state.sampling_call_counter = secrets.randbelow(interval)

    def _sample_interval(self, level: InstrumentationLevel) -> int:
        sampling = self.policy.sampling
        if not sampling.enabled:
            return 0
        if level is InstrumentationLevel.LIGHTWEIGHT:
            return sampling.lightweight_every_calls
        if level is InstrumentationLevel.BEHAVIOR:
            return sampling.behavior_every_calls
        return 0

    def _advance_sampling_counter(self, level: InstrumentationLevel) -> bool:
        interval = self._sample_interval(level)
        if interval <= 0:
            return False
        self.state.sampling_call_counter += 1
        if self.state.sampling_call_counter < interval:
            return False
        self.state.sampling_call_counter = 0
        return True

    def _record_behavior_sample(self, observed_level: InstrumentationLevel) -> None:
        with self._lock:
            self.state.behavior_samples += 1
            increments = {"behavior_samples": 1}
            if observed_level is InstrumentationLevel.BEHAVIOR:
                self.state.repair_evidence_samples += 1
                increments["repair_evidence_samples"] = 1
                self._checkpoint_state()
            self._record_aggregation(**increments)
            self._publish_state()

    def _observe_acceptance(self, *, success: bool) -> None:
        with self._lock:
            # Adaptive acceptance is only for a non-repair behavioral promotion.
            # Once repair is requested/active, FunctionSlot candidate observation is
            # the single authoritative acceptance state machine.
            if (
                self.state.stage is not AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR
                or self.state.repair_requested
            ):
                return
            if success:
                self._record_acceptance_success()
                self._record_aggregation(successful_executions=1)
            else:
                self._record_acceptance_failure()
                self._record_aggregation(failed_executions=1)
            self._checkpoint_state()
            self._publish_state()

    def _record_acceptance_success(self) -> None:
        policy = self.policy.demotion
        if self.state.acceptance in {AcceptanceState.NONE, AcceptanceState.PROBATION}:
            self.state.acceptance = AcceptanceState.PROBATION
            self.state.successful_executions += 1
            if short_term_accepted(
                successful_executions=self.state.successful_executions,
                failed_executions=self.state.probation_failures,
                criteria=policy,
            ):
                self.state.acceptance = AcceptanceState.SHORT_TERM_ACCEPTED
                self.state.short_term_accepted_at = utcnow_iso()
                self.state.long_term_successes = self.state.successful_executions
                self.state.long_term_failures = self.state.probation_failures
        elif self.state.acceptance is AcceptanceState.SHORT_TERM_ACCEPTED:
            self.state.long_term_successes += 1
            if self._long_term_accepted(policy):
                self.state.acceptance = AcceptanceState.LONG_TERM_ACCEPTED
                self.state.long_term_accepted_at = utcnow_iso()
                if policy.enabled:
                    self._demote(policy)

    def _record_acceptance_failure(self) -> None:
        policy = self.policy.demotion
        if self.state.level is InstrumentationLevel.LIGHTWEIGHT:
            return
        if self.state.acceptance in {AcceptanceState.NONE, AcceptanceState.PROBATION}:
            self.state.acceptance = AcceptanceState.PROBATION
            self.state.probation_failures += 1
            if self.state.probation_failures > policy.probation_failure_budget:
                self.state.successful_executions = 0
                self.state.probation_failures = 0
                self.state.promoted_at = utcnow_iso()
        else:
            self.state.long_term_failures += 1
            total = self.state.long_term_successes + self.state.long_term_failures
            failure_rate = self.state.long_term_failures / total if total else 0.0
            if (
                self.state.long_term_failures > policy.long_term_maximum_failures
                or failure_rate > policy.long_term_failure_rate
            ):
                self.state.acceptance = AcceptanceState.PROBATION
                self.state.short_term_accepted_at = None
                self.state.long_term_accepted_at = None
                self.state.successful_executions = 0
                self.state.probation_failures = 0
                self.state.long_term_successes = 0
                self.state.long_term_failures = 0
                self.state.promoted_at = utcnow_iso()

    def _long_term_accepted(self, policy: InstrumentationDemotionPolicy) -> bool:
        start = self.state.short_term_accepted_at
        if start is None:
            return False
        try:
            accepted_at = datetime.fromisoformat(start)
        except ValueError:
            return False
        return long_term_accepted(
            successful_executions=self.state.long_term_successes,
            failed_executions=self.state.long_term_failures,
            started_at=accepted_at,
            criteria=policy,
        )

    def _demote(self, policy: InstrumentationDemotionPolicy) -> None:
        current = self.state.level
        if current is InstrumentationLevel.LIGHTWEIGHT:
            return
        if policy.stepwise and current is InstrumentationLevel.REPAIR:
            next_level = InstrumentationLevel.BEHAVIOR
        else:
            next_level = InstrumentationLevel.LIGHTWEIGHT
        now = utcnow_iso()
        self.state.level = next_level
        self.state.stage = (
            AdaptiveLifecycleStage.LIGHTWEIGHT
            if next_level is InstrumentationLevel.LIGHTWEIGHT
            else AdaptiveLifecycleStage.PRE_REPAIR_BEHAVIOR
        )
        self.state.acceptance = AcceptanceState.NONE if next_level is InstrumentationLevel.LIGHTWEIGHT else AcceptanceState.PROBATION
        self.state.promoted_at = None if next_level is InstrumentationLevel.LIGHTWEIGHT else now
        self.state.promotion_reason = "policy-controlled demotion after long-term acceptance"
        self.state.short_term_accepted_at = None
        self.state.long_term_accepted_at = None
        self.state.successful_executions = 0
        self.state.probation_failures = 0
        self.state.long_term_successes = 0
        self.state.long_term_failures = 0
        self.state.last_transition_at = now
        self.state.sampling_call_counter = 0
        self.state.repair_requested = False
        self.state.repair_request_reason = None
        self.state.repair_evidence_satisfied_at = None
        self.state.behavior_observation_calls = 0
        self.state.repair_evidence_samples = 0
        self.state.problem_reproductions = 0
        self.state.behavior_started_at = now if next_level is InstrumentationLevel.BEHAVIOR else None
        self._behavior_lease_remaining = 0
        self._persist()
        self._publish_state()

    def _diagnostic(self, item: dict[str, Any]) -> None:
        self.state.recent_diagnostics.append(item)
        if len(self.state.recent_diagnostics) > 20:
            del self.state.recent_diagnostics[:-20]

    def _refresh_generation_if_needed(self) -> None:
        current_code = getattr(self.function, "__code__", None)
        if current_code is self._code_object:
            return
        if self._aggregation_batcher is not None:
            self._aggregation_batcher.flush()
        self._code_object = current_code
        self.code_hash = _function_hash(self.function)
        self._exception_events.clear()
        self._timing_events.clear()
        self._managed_wrapper = None
        self._behavior_registered = False
        self._behavior_lease_remaining = 0
        self._state_path = (
            _state_path(self.target_id, self.code_hash, self._state_directory)
            if self.policy.persist_state
            else None
        )
        self._stale_persisted_state = False
        loaded = self._load_state()
        if loaded is None:
            self.state = AdaptiveInstrumentationState(
                target_id=self.target_id,
                code_hash=self.code_hash,
                level=self.policy.initial_level,
                stage=_initial_stage(self.policy.initial_level),
            )
            self._initialize_generation_state()
            if self._stale_persisted_state:
                self._persist()
        else:
            self.state = loaded
            if self.state.level.value >= InstrumentationLevel.BEHAVIOR.value and self.state.behavior_started_at is None:
                self.state.behavior_started_at = utcnow_iso()
        self._sync_aggregation_batcher()
        self._publish_state()

    def _refresh_policy_if_needed(self) -> None:
        authority_fingerprint = _authority_context().effective.fingerprint
        if authority_fingerprint == self._authority_fingerprint:
            return

        if self._aggregation_batcher is not None:
            self._aggregation_batcher.flush()

        previous_authority = self._authority_fingerprint
        previous_policy_fingerprint = self._policy_fingerprint
        previous_state_path = self._state_path
        effective = self._effective_policy()
        validate_lightweight_policy(effective)
        effective_policy_fingerprint = _policy_hash(effective)
        self.policy = effective
        self._policy_fingerprint = effective_policy_fingerprint
        self._state_path = (
            _state_path(self.target_id, self.code_hash, self._state_directory)
            if self.policy.persist_state
            else None
        )

        if (
            previous_authority == self._authority_fingerprint
            and previous_policy_fingerprint == effective_policy_fingerprint
        ):
            return

        # Authority/policy generations are part of adaptive-state provenance. A
        # pre-repair escalation accumulated under an older authority must not grant
        # observation or repair privileges under a new one. An already-active repair
        # candidate remains owned by FunctionSlot/RepairEngine, so preserve only that
        # candidate lifecycle and discard the adaptive trigger/evidence episode.
        self._exception_events.clear()
        self._timing_events.clear()
        self._behavior_lease_remaining = 0
        self._dirty_state_calls = 0
        preserve_candidate = bool(
            self.state.repair_candidate_id
            and self.state.stage in {
                AdaptiveLifecycleStage.POST_REPAIR_BEHAVIOR,
                AdaptiveLifecycleStage.VALIDATION,
                AdaptiveLifecycleStage.LONG_TERM_ACCEPTANCE,
            }
        )
        if preserve_candidate:
            self.state.sampling_call_counter = 0
            self.state.behavior_observation_calls = 0
            self.state.repair_evidence_samples = 0
            self.state.problem_reproductions = 0
            self.state.repair_requested = False
            self.state.repair_request_reason = None
            self.state.repair_evidence_satisfied_at = None
            self.state.last_transition_at = utcnow_iso()
        else:
            self.state = AdaptiveInstrumentationState(
                target_id=self.target_id,
                code_hash=self.code_hash,
                level=self.policy.initial_level,
                stage=_initial_stage(self.policy.initial_level),
                promotion_reason="effective authority/policy changed; adaptive episode reset",
                last_transition_at=utcnow_iso(),
            )
            self._initialize_generation_state()

        if previous_state_path is not None and self._state_path is None:
            try:
                previous_state_path.unlink()
            except FileNotFoundError:
                pass
        self._persist()
        self._sync_aggregation_batcher()
        self._publish_state()

    def _effective_policy(self) -> LightweightPolicy:
        context = _authority_context()
        policy = context.apply(self.declared_policy, prefix="lightweight", target_id=self.target_id)
        self._authority_fingerprint = context.effective.fingerprint
        return policy

    def _aggregation_root(self) -> Path:
        if self._state_directory is None:
            return Path(os.environ.get("CARETAKER_DATA_DIR", "./caretaker-data"))
        return Path(self._state_directory).parent

    def _aggregation_context(self) -> dict[str, str]:
        return {
            "target_id": self.target_id,
            # Code identity is the current adaptive generation identity. A code
            # change causes a new hash and therefore a new supervisor aggregate.
            "generation_id": self.code_hash,
            "code_hash": self.code_hash,
            "monitoring_fingerprint": _monitoring_policy_hash(self.policy),
            "policy_fingerprint": self._policy_fingerprint,
            "authority_policy_generation": str(_authority_context().effective.generation),
            "authority_policy_fingerprint": self._authority_fingerprint or "",
        }

    def _configure_aggregation_batcher(self) -> None:
        if not self.policy.aggregation.enabled:
            self._aggregation_batcher = None
            return
        context = self._aggregation_context()
        self._aggregation_batcher = AdaptiveObservationBatcher(
            SupervisorAdaptiveAggregationStore(self._aggregation_root()),
            worker_id=_ADAPTIVE_WORKER_ID,
            worker_pid=os.getpid(),
            flush_after_observations=self.policy.aggregation.flush_after_observations,
            flush_interval_seconds=self.policy.aggregation.flush_interval_seconds,
            **context,
        )

    def _rebind_aggregation_batcher(self) -> None:
        if self._aggregation_batcher is not None:
            self._aggregation_batcher.rebind(**self._aggregation_context())

    def _sync_aggregation_batcher(self) -> None:
        if not self.policy.aggregation.enabled:
            if self._aggregation_batcher is not None:
                self._aggregation_batcher.flush()
            self._aggregation_batcher = None
        elif self._aggregation_batcher is None:
            self._configure_aggregation_batcher()
        else:
            self._rebind_aggregation_batcher()

    def aggregation_status(self) -> dict[str, Any]:
        promotion_policy = {
            "exception": {
                "enabled": self.policy.exception.enabled,
                "occurrences": self.policy.exception.occurrences,
                "window_seconds": self.policy.exception.window_seconds,
                "promote_to": self.policy.exception.promote_to.name,
            },
            "soft_timing": {
                "enabled": self.policy.soft_timing.enabled,
                "occurrences": self.policy.soft_timing.occurrences,
                "window_seconds": self.policy.soft_timing.window_seconds,
                "promote_to": self.policy.soft_timing.promote_to.name,
            },
            "repair_evidence": {
                "enabled": self.policy.repair_evidence.enabled,
                "minimum_behavior_samples": self.policy.repair_evidence.minimum_behavior_samples,
                "minimum_observation_calls": self.policy.repair_evidence.minimum_observation_calls,
                "minimum_duration_seconds": self.policy.repair_evidence.minimum_duration_seconds,
                "require_problem_reproduction": self.policy.repair_evidence.require_problem_reproduction,
            },
        }
        batcher = self._aggregation_batcher
        if batcher is None:
            return {
                "enabled": False,
                "target_id": self.target_id,
                "generation_id": self.code_hash,
                "policy_fingerprint": self._policy_fingerprint,
                "authority_policy_generation": str(
                    _authority_context().effective.generation
                ),
                "authority_policy_fingerprint": self._authority_fingerprint,
                "promotion_policy": promotion_policy,
            }
        return {
            "enabled": True,
            **batcher.status(),
            **batcher.context,
            "promotion_policy": promotion_policy,
        }

    def _record_aggregation(self, **increments: int) -> None:
        batcher = self._aggregation_batcher
        if batcher is None:
            return
        try:
            batcher.record(**increments)
        except Exception:
            # Aggregation is optional evidence. It cannot make an application
            # invocation fail or alter the adaptive authority boundary.
            return

    @staticmethod
    def _append_window(events: deque[float], now: float, window_seconds: float) -> None:
        cutoff = now - window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        events.append(now)

    def _load_state(self) -> AdaptiveInstrumentationState | None:
        if self._state_path is None or not self._state_path.exists():
            return None
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            if data.get("target_id") != self.target_id or data.get("code_hash") != self.code_hash:
                return None
            if (
                data.get("policy_fingerprint") != self._policy_fingerprint
                or data.get("authority_fingerprint") != self._authority_fingerprint
            ):
                self._stale_persisted_state = True
                return None
            now = time.time()
            exception_window = self.policy.exception.window_seconds
            timing_window = self.policy.soft_timing.window_seconds
            self._exception_events.extend(
                float(item) for item in data.get("exception_events", ())
                if float(item) >= now - exception_window
            )
            self._timing_events.extend(
                float(item) for item in data.get("timing_events", ())
                if float(item) >= now - timing_window
            )
            return AdaptiveInstrumentationState(
                target_id=self.target_id,
                code_hash=self.code_hash,
                level=InstrumentationLevel[str(data["level"])],
                stage=_loaded_stage(data),
                acceptance=AcceptanceState(str(data.get("acceptance", "none"))),
                promoted_at=data.get("promoted_at"),
                promotion_reason=data.get("promotion_reason"),
                promotion_requested_by=data.get("promotion_requested_by"),
                promotion_authority_generation=data.get("promotion_authority_generation"),
                promotion_authority_fingerprint=data.get("promotion_authority_fingerprint"),
                promotion_outcome=data.get("promotion_outcome"),
                promotion_outcome_at=data.get("promotion_outcome_at"),
                promotion_snapshot_id=data.get("promotion_snapshot_id"),
                short_term_accepted_at=data.get("short_term_accepted_at"),
                long_term_accepted_at=data.get("long_term_accepted_at"),
                successful_executions=int(data.get("successful_executions", 0)),
                probation_failures=int(data.get("probation_failures", 0)),
                long_term_successes=int(data.get("long_term_successes", 0)),
                long_term_failures=int(data.get("long_term_failures", 0)),
                last_transition_at=data.get("last_transition_at"),
                behavior_started_at=data.get("behavior_started_at"),
                behavior_observation_calls=int(data.get("behavior_observation_calls", 0)),
                behavior_samples=int(data.get("behavior_samples", 0)),
                repair_evidence_samples=int(data.get("repair_evidence_samples", 0)),
                problem_reproductions=int(data.get("problem_reproductions", 0)),
                repair_requested=bool(data.get("repair_requested", False)),
                repair_request_reason=data.get("repair_request_reason"),
                repair_evidence_satisfied_at=data.get("repair_evidence_satisfied_at"),
                repair_candidate_id=data.get("repair_candidate_id"),
                repair_candidate_version=(
                    int(data["repair_candidate_version"])
                    if data.get("repair_candidate_version") is not None
                    else None
                ),
                post_repair_behavior_started_at=data.get("post_repair_behavior_started_at"),
                validation_started_at=data.get("validation_started_at"),
                sampling_call_counter=int(data.get("sampling_call_counter", 0)),
                recent_diagnostics=[dict(item) for item in data.get("recent_diagnostics", ())][-20:],
            )
        except Exception:
            return None

    def _checkpoint_state(self, *, force: bool = False) -> None:
        """Batch durable progress checkpoints off the ordinary promoted hot path.

        Transitions and threshold violations still call ``_persist`` immediately.
        Routine behavior-sample and acceptance progress is checkpointed periodically
        so promoted instrumentation does not perform an fsync on every successful call.
        """
        if self._state_path is None:
            return
        self._dirty_state_calls += 1
        now = time.monotonic()
        if (
            not force
            and self._dirty_state_calls < _STATE_CHECKPOINT_CALLS
            and (now - self._last_checkpoint_monotonic) < _STATE_CHECKPOINT_SECONDS
        ):
            return
        self._persist()
        self._dirty_state_calls = 0
        self._last_checkpoint_monotonic = now

    def _persist_event_state(self) -> None:
        # Persist only noteworthy threshold events. Healthy LIGHTWEIGHT calls still
        # perform no Caretaker filesystem I/O, while rolling windows survive restart.
        self._persist()

    def _persist(self) -> None:
        if self._state_path is None:
            return
        self._dirty_state_calls = 0
        self._last_checkpoint_monotonic = time.monotonic()
        self._state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = self.state.public_dict()
        payload["policy_fingerprint"] = self._policy_fingerprint
        payload["authority_fingerprint"] = self._authority_fingerprint
        payload["exception_events"] = list(self._exception_events)
        payload["timing_events"] = list(self._timing_events)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=".adaptive-", dir=str(self._state_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._state_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _publish_state(self) -> None:
        with _STATE_REGISTRY_LOCK:
            _STATE_REGISTRY[self.target_id] = self.state


def _function_hash(function: Callable[..., Any]) -> str:
    parts: list[bytes] = []
    try:
        source = inspect.getsource(function)
    except (OSError, TypeError):
        source = None
    if source is not None:
        parts.append(source.encode("utf-8"))
    code = getattr(function, "__code__", None)
    if code is not None:
        parts.append(code.co_code)
        parts.append(repr(code.co_consts).encode("utf-8", "backslashreplace"))
        parts.append(repr(code.co_names).encode("utf-8", "backslashreplace"))
    if not parts:
        parts.append(repr(function).encode("utf-8", "backslashreplace"))
    return hashlib.sha256(b"\0".join(parts)).hexdigest()


def _policy_hash(policy: LightweightPolicy) -> str:
    def normalize(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.name
        if hasattr(value, "__dataclass_fields__"):
            return {key: normalize(item) for key, item in asdict(value).items()}
        if isinstance(value, dict):
            return {str(key): normalize(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [normalize(item) for item in value]
        return value

    encoded = json.dumps(normalize(policy), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()



def _monitoring_policy_hash(policy: LightweightPolicy) -> str:
    payload = {
        "sampling": {
            "enabled": policy.sampling.enabled,
            "lightweight_every_calls": policy.sampling.lightweight_every_calls,
            "behavior_every_calls": policy.sampling.behavior_every_calls,
            "randomize_initial_offset": policy.sampling.randomize_initial_offset,
        },
        "behavior_executions": policy.behavior_executions,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

def _state_path(target_id: str, code_hash: str, directory: str | Path | None) -> Path:
    if directory is None:
        root = Path(os.environ.get("CARETAKER_DATA_DIR", "./caretaker-data")) / "adaptive"
    else:
        root = Path(directory)
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", target_id).strip("-") or "target"
    target_hash = hashlib.sha256(target_id.encode("utf-8")).hexdigest()[:10]
    return root / f"{safe}-{target_hash}-{code_hash[:16]}.json"


DEFAULT_LIGHTWEIGHT_POLICY = LightweightPolicy()
DEFAULT_DEPENDENCY_POLICY = LightweightPolicy(
    exception=ExceptionPromotionPolicy(
        enabled=True,
        occurrences=2,
        window_seconds=3600.0,
        promote_to=InstrumentationLevel.BEHAVIOR,
    ),
    soft_timing=SoftTimingPromotionPolicy(enabled=False),
    demotion=InstrumentationDemotionPolicy(enabled=True),
)


@overload
def lightweight(function: F) -> F: ...


@overload
def lightweight(
    function: None = None,
    *,
    policy: LightweightPolicy | None = None,
    repair_policy: Any | None = None,
    engine: Any | None = None,
    target_id: str | None = None,
    behavior_binding: Any | None = None,
    state_directory: str | Path | None = None,
    allow_repair_promotion: bool = True,
) -> Callable[[F], F]: ...


def lightweight(
    function: F | None = None,
    *,
    policy: LightweightPolicy | None = None,
    repair_policy: Any | None = None,
    engine: Any | None = None,
    target_id: str | None = None,
    behavior_binding: Any | None = None,
    state_directory: str | Path | None = None,
    allow_repair_promotion: bool = True,
) -> F | Callable[[F], F]:
    """Start with low-cost threshold monitoring and promote only when policy requires it."""

    def decorate(original: F) -> F:
        resolved_target_id = target_id or f"{original.__module__}:{original.__qualname__}"
        selected_policy = policy or DEFAULT_LIGHTWEIGHT_POLICY
        selected_repair_policy = repair_policy
        if behavior_binding is not None:
            selected_binding = behavior_binding
        elif selected_repair_policy is not None:
            selected_binding = selected_repair_policy.guard
        else:
            selected_binding = _DEPENDENCY_BINDING
        controller = _AdaptiveController(
            original,
            target_id=resolved_target_id,
            policy=selected_policy,
            repair_policy=selected_repair_policy,
            engine=engine,
            behavior_binding=selected_binding,
            state_directory=state_directory,
            allow_repair_promotion=allow_repair_promotion,
        )

        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return controller.invoke(*args, **kwargs)

        setattr(wrapper, "__caretaker_adaptive__", controller)
        return wrapper  # type: ignore[return-value]

    if function is not None:
        return decorate(function)
    return decorate


def lightweight_on_exception(
    *,
    occurrences: int = 2,
    window_seconds: float = 3600.0,
    promote_to: InstrumentationLevel = InstrumentationLevel.REPAIR,
    policy: LightweightPolicy | None = None,
    **kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_LIGHTWEIGHT_POLICY
    configured = replace(
        base,
        exception=replace(
            base.exception,
            enabled=True,
            occurrences=occurrences,
            window_seconds=window_seconds,
            promote_to=promote_to,
        ),
    )
    return lightweight(policy=configured, **kwargs)


def lightweight_on_soft_timeout(
    seconds: float,
    *,
    occurrences: int = 3,
    window_seconds: float = 1800.0,
    promote_to: InstrumentationLevel = InstrumentationLevel.REPAIR,
    policy: LightweightPolicy | None = None,
    **kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_LIGHTWEIGHT_POLICY
    configured = replace(
        base,
        soft_timing=replace(
            base.soft_timing,
            enabled=True,
            seconds=seconds,
            occurrences=occurrences,
            window_seconds=window_seconds,
            promote_to=promote_to,
        ),
    )
    return lightweight(policy=configured, **kwargs)


def lightweight_dependency(
    function: F | None = None,
    *,
    policy: LightweightPolicy | None = None,
    target_id: str | None = None,
    engine: Any | None = None,
    state_directory: str | Path | None = None,
) -> F | Callable[[F], F]:
    """Instrument a Caretaker dependency boundary without permitting self-repair.

    Dependency boundaries default to LIGHTWEIGHT and may promote to BEHAVIOR, but
    never to generated Caretaker self-modification.  This prevents recursive repair
    loops if a dependency used by Caretaker itself is unhealthy.
    """
    return lightweight(
        function,
        policy=policy or DEFAULT_DEPENDENCY_POLICY,
        target_id=target_id,
        engine=engine,
        state_directory=state_directory,
        behavior_binding=_DEPENDENCY_BINDING,
        allow_repair_promotion=False,
    )


DependencyFunctionReference = (
    Callable[..., Any]
    | tuple[ModuleType | str, str]
    | str
)


@dataclass(slots=True)
class LightweightDependencySlot:
    """A reversible module attribute replaced by a lightweight dependency wrapper."""

    module: ModuleType
    attribute_name: str
    target_id: str
    original: Callable[..., Any]
    wrapper: Callable[..., Any]
    controller: _AdaptiveController
    active: bool = True

    @property
    def module_name(self) -> str:
        return self.module.__name__

    @property
    def installed(self) -> bool:
        return self.active and getattr(self.module, self.attribute_name, None) is self.wrapper

    def restore(self) -> bool:
        """Restore the original only if this slot still owns the module attribute."""
        if not self.active:
            return False
        restored = False
        if getattr(self.module, self.attribute_name, None) is self.wrapper:
            setattr(self.module, self.attribute_name, self.original)
            restored = True
        self.active = False
        return restored


@dataclass(slots=True)
class DependencyInstrumentation:
    """Installed lightweight dependency slots created during application startup."""

    slots: tuple[LightweightDependencySlot, ...]
    skipped: tuple[str, ...] = ()

    @property
    def target_ids(self) -> tuple[str, ...]:
        return tuple(slot.target_id for slot in self.slots)

    def restore(self) -> int:
        restored = 0
        for slot in reversed(self.slots):
            restored += int(slot.restore())
        return restored

    def __enter__(self) -> DependencyInstrumentation:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.restore()


def _resolve_dependency_module(module: ModuleType | str) -> ModuleType:
    if isinstance(module, ModuleType):
        return module
    if isinstance(module, str) and module:
        return importlib.import_module(module)
    raise TypeError("dependency modules must be module objects or importable module names")


def _module_function_candidates(
    module: ModuleType,
    *,
    include_private: bool,
    owned_only: bool,
    exclude: frozenset[str],
) -> tuple[tuple[str, Callable[..., Any]], ...]:
    candidates: list[tuple[str, Callable[..., Any]]] = []
    for name, value in tuple(vars(module).items()):
        if name in exclude or (name.startswith("_") and not include_private):
            continue
        if not (inspect.isfunction(value) or inspect.isbuiltin(value)):
            continue
        if owned_only and getattr(value, "__module__", None) != module.__name__:
            continue
        candidates.append((name, value))
    return tuple(candidates)


def _resolve_dependency_function(
    reference: DependencyFunctionReference,
) -> tuple[ModuleType, str, Callable[..., Any]]:
    if isinstance(reference, tuple):
        if len(reference) != 2:
            raise ValueError("dependency function tuples must be (module, attribute_name)")
        module = _resolve_dependency_module(reference[0])
        name = reference[1]
        if not isinstance(name, str) or not name:
            raise TypeError("dependency function attribute names must be non-empty strings")
        function = getattr(module, name)
        if not callable(function) or inspect.isclass(function):
            raise TypeError(f"{module.__name__}.{name} is not an instrumentable function")
        return module, name, function

    if isinstance(reference, str):
        if ":" not in reference:
            raise ValueError(
                "string dependency function references must use 'module:attribute' syntax"
            )
        module_name, name = reference.rsplit(":", 1)
        return _resolve_dependency_function((module_name, name))

    if not callable(reference) or inspect.isclass(reference):
        raise TypeError("dependency functions must be callables, module/name tuples, or module:attribute strings")

    module_name = getattr(reference, "__module__", None)
    if not isinstance(module_name, str) or not module_name:
        raise ValueError(
            "cannot infer the defining module for this callable; pass (module, attribute_name) instead"
        )
    module = _resolve_dependency_module(module_name)
    preferred_name = getattr(reference, "__name__", None)
    if isinstance(preferred_name, str) and getattr(module, preferred_name, None) is reference:
        return module, preferred_name, reference
    matches = [name for name, value in vars(module).items() if value is reference]
    if len(matches) == 1:
        return module, matches[0], reference
    raise ValueError(
        f"cannot identify a unique module attribute for {reference!r}; "
        "pass (module, attribute_name) instead"
    )


def instrument_dependencies(
    modules: Iterable[ModuleType | str] = (),
    *,
    functions: Iterable[DependencyFunctionReference] = (),
    policy: LightweightPolicy | None = None,
    engine: Any | None = None,
    target_prefix: str = "dependency",
    state_directory: str | Path | None = None,
    include_private: bool = False,
    owned_only: bool = True,
    exclude: Iterable[str] = (),
    prepare_guard: bool = True,
) -> DependencyInstrumentation:
    """Install lightweight slots over dependency module functions.

    Bare modules instrument their public module-owned Python/builtin functions.
    ``functions`` can name selected dependency boundaries as callables,
    ``(module, attribute)`` pairs, or ``"module:attribute"`` strings.  Explicitly
    selected functions are instrumented even when their implementation originates
    in another module (for example ``os.stat`` implemented by ``posix``).

    This function is intended for application initialization: construct the Guard
    and Repair engines, call ``instrument_dependencies(..., engine=engine)``, then
    install Guard hooks and begin application work.  When ``prepare_guard`` is true,
    each original callable is registered with Guard immediately without enabling
    heavyweight per-call observation; the call-count sampler still controls when a
    behavior sample is taken.
    """
    selected_policy = policy or DEFAULT_DEPENDENCY_POLICY
    validate_lightweight_policy(selected_policy)
    prefix = target_prefix.strip(".") or "dependency"
    excluded = frozenset(str(name) for name in exclude)
    candidates: list[tuple[ModuleType, str, Callable[..., Any]]] = []

    for module_reference in modules:
        module = _resolve_dependency_module(module_reference)
        for name, function in _module_function_candidates(
            module,
            include_private=include_private,
            owned_only=owned_only,
            exclude=excluded,
        ):
            candidates.append((module, name, function))

    for reference in functions:
        candidates.append(_resolve_dependency_function(reference))

    installed: list[LightweightDependencySlot] = []
    skipped: list[str] = []
    seen: set[tuple[int, str]] = set()
    for module, name, original in candidates:
        key = (id(module), name)
        label = f"{module.__name__}.{name}"
        if key in seen:
            continue
        seen.add(key)

        current = getattr(module, name, None)
        if current is not original:
            skipped.append(f"{label}: module attribute changed during instrumentation")
            continue
        if hasattr(current, "__caretaker_dependency_slot__"):
            skipped.append(f"{label}: already dependency-instrumented")
            continue
        if hasattr(current, "__caretaker_adaptive__"):
            skipped.append(f"{label}: already adaptively instrumented")
            continue

        target_id = f"{prefix}.{module.__name__}.{name}"
        wrapper = lightweight_dependency(
            policy=selected_policy,
            target_id=target_id,
            engine=engine,
            state_directory=state_directory,
        )(original)
        controller = getattr(wrapper, "__caretaker_adaptive__")
        slot = LightweightDependencySlot(
            module=module,
            attribute_name=name,
            target_id=target_id,
            original=original,
            wrapper=wrapper,
            controller=controller,
        )
        setattr(wrapper, "__caretaker_dependency_slot__", slot)
        setattr(module, name, wrapper)
        installed.append(slot)

        if prepare_guard:
            # Keep Guard registration itself on a non-instrumented dependency path.
            previous_depth = int(getattr(_DEPENDENCY_RUNTIME, "depth", 0))
            _DEPENDENCY_RUNTIME.depth = previous_depth + 1
            try:
                controller.prepare_guard_registration()
            finally:
                _DEPENDENCY_RUNTIME.depth = previous_depth

    return DependencyInstrumentation(slots=tuple(installed), skipped=tuple(skipped))


class _DependencyImportLoader:
    def __init__(self, delegate: Any, owner: "DependencyImportInstrumentation") -> None:
        self.delegate = delegate
        self.owner = owner

    def create_module(self, spec: Any) -> Any:
        creator = getattr(self.delegate, "create_module", None)
        return creator(spec) if creator is not None else None

    def exec_module(self, module: ModuleType) -> None:
        self.delegate.exec_module(module)
        self.owner._module_loaded(module)


class _DependencyImportFinder:
    def __init__(self, owner: "DependencyImportInstrumentation") -> None:
        self.owner = owner

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if not self.owner.active or fullname not in self.owner.watched_modules:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None or spec.loader is None:
            return spec
        if not hasattr(spec.loader, "exec_module"):
            raise ImportError(
                f"dependency instrumentation requires an exec_module loader for {fullname!r}"
            )
        spec.loader = _DependencyImportLoader(spec.loader, self.owner)
        return spec


@dataclass(slots=True)
class DependencyImportInstrumentation:
    """Explicit pre-import dependency instrumentation scope."""

    watched_modules: frozenset[str]
    instrumented_modules: frozenset[str]
    selected_functions: Mapping[str, frozenset[str]]
    policy: LightweightPolicy
    engine: Any | None
    target_prefix: str
    state_directory: str | Path | None
    include_private: bool
    owned_only: bool
    exclude: frozenset[str]
    prepare_guard: bool
    installations: list[DependencyInstrumentation] = field(default_factory=list)
    active: bool = True
    finder: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.finder = _DependencyImportFinder(self)  # type: ignore[attr-defined]

    def _module_loaded(self, module: ModuleType) -> None:
        if not self.active or module.__name__ not in self.watched_modules:
            return
        references = tuple(
            (module, name) for name in self.selected_functions.get(module.__name__, ())
        )
        installation = instrument_dependencies(
            modules=(module,) if module.__name__ in self.instrumented_modules else (),
            functions=references,
            policy=self.policy,
            engine=self.engine,
            target_prefix=self.target_prefix,
            state_directory=self.state_directory,
            include_private=self.include_private,
            owned_only=self.owned_only,
            exclude=self.exclude,
            prepare_guard=self.prepare_guard,
        )
        self.installations.append(installation)

    def restore(self) -> int:
        if not self.active:
            return 0
        self.active = False
        try:
            sys.meta_path.remove(self.finder)
        except ValueError:
            pass
        restored = 0
        for installation in reversed(self.installations):
            restored += installation.restore()
        return restored

    def __enter__(self) -> "DependencyImportInstrumentation":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.restore()


def install_dependency_import_hook(
    modules: Iterable[str] = (),
    *,
    functions: Iterable[str] = (),
    policy: LightweightPolicy | None = None,
    engine: Any | None = None,
    target_prefix: str = "dependency",
    state_directory: str | Path | None = None,
    include_private: bool = False,
    owned_only: bool = True,
    exclude: Iterable[str] = (),
    prepare_guard: bool = True,
) -> DependencyImportInstrumentation:
    """Instrument selected dependency modules before application imports them.

    ``modules`` contains explicit import names whose module-owned functions may
    be wrapped. ``functions`` contains explicit ``"module:attribute"`` names.
    The hook is intentionally scoped to this allowlist and must be restored by
    the caller when startup configuration is complete.
    """
    selected_policy = policy or DEFAULT_DEPENDENCY_POLICY
    validate_lightweight_policy(selected_policy)
    module_references = tuple(modules)
    module_names = frozenset(
        name for name in module_references
        if isinstance(name, str) and name.strip()
    )
    if len(module_names) != len(module_references):
        raise TypeError("dependency import modules must be non-empty strings")
    selected: dict[str, set[str]] = {}
    for reference in functions:
        if not isinstance(reference, str) or ":" not in reference:
            raise ValueError("dependency import functions must use 'module:attribute' syntax")
        module_name, attribute_name = reference.rsplit(":", 1)
        if not module_name.strip() or not attribute_name.strip():
            raise ValueError("dependency import function references cannot be empty")
        selected.setdefault(module_name, set()).add(attribute_name)
    watched = frozenset((*module_names, *selected))
    if not watched:
        raise ValueError("at least one dependency module or function must be selected")
    instrumentation = DependencyImportInstrumentation(
        watched_modules=watched,
        instrumented_modules=module_names,
        selected_functions={name: frozenset(values) for name, values in selected.items()},
        policy=selected_policy,
        engine=engine,
        target_prefix=target_prefix.strip(".") or "dependency",
        state_directory=state_directory,
        include_private=include_private,
        owned_only=owned_only,
        exclude=frozenset(str(name) for name in exclude),
        prepare_guard=prepare_guard,
    )
    for module_name in watched:
        loaded = sys.modules.get(module_name)
        if loaded is not None:
            instrumentation._module_loaded(loaded)
    sys.meta_path.insert(0, instrumentation.finder)
    return instrumentation
