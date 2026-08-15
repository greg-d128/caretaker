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
import json
import os
import re
import tempfile
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar, overload
from uuid import uuid4

from .runtime import set_runtime_context

F = TypeVar("F", bound=Callable[..., Any])
_DEPENDENCY_BINDING = object()
_DEPENDENCY_RUNTIME = threading.local()


def _authority_context():
    from .authority import get_authority_runtime_context
    return get_authority_runtime_context()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InstrumentationLevel(Enum):
    LIGHTWEIGHT = 0
    BEHAVIOR = 1
    REPAIR = 2


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
class InstrumentationDemotionPolicy:
    """Acceptance criteria required before promoted instrumentation may step down.

    The two phases intentionally mirror Repair ``ObservationPolicy`` semantics:
    first establish a short-term successful probation, then require a larger and
    optionally time-bounded long-term observation before demotion is permitted.
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
class LightweightPolicy:
    exception: ExceptionPromotionPolicy = field(default_factory=ExceptionPromotionPolicy)
    soft_timing: SoftTimingPromotionPolicy = field(default_factory=SoftTimingPromotionPolicy)
    demotion: InstrumentationDemotionPolicy = field(default_factory=InstrumentationDemotionPolicy)
    initial_level: InstrumentationLevel = InstrumentationLevel.LIGHTWEIGHT
    behavior_executions: int = 100
    persist_state: bool = True


@dataclass(slots=True)
class AdaptiveInstrumentationState:
    target_id: str
    code_hash: str
    level: InstrumentationLevel
    acceptance: AcceptanceState = AcceptanceState.NONE
    promoted_at: str | None = None
    promotion_reason: str | None = None
    short_term_accepted_at: str | None = None
    long_term_accepted_at: str | None = None
    successful_executions: int = 0
    probation_failures: int = 0
    long_term_successes: int = 0
    long_term_failures: int = 0
    last_transition_at: str | None = None
    recent_diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def public_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "code_hash": self.code_hash,
            "level": self.level.name,
            "acceptance": self.acceptance.value,
            "promoted_at": self.promoted_at,
            "promotion_reason": self.promotion_reason,
            "short_term_accepted_at": self.short_term_accepted_at,
            "long_term_accepted_at": self.long_term_accepted_at,
            "successful_executions": self.successful_executions,
            "probation_failures": self.probation_failures,
            "long_term_successes": self.long_term_successes,
            "long_term_failures": self.long_term_failures,
            "last_transition_at": self.last_transition_at,
            "recent_diagnostics": list(self.recent_diagnostics),
        }


_STATE_REGISTRY: dict[str, AdaptiveInstrumentationState] = {}
_STATE_REGISTRY_LOCK = threading.RLock()


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
        self._authority_fingerprint: str | None = None
        self.policy = self._effective_policy()
        validate_lightweight_policy(self.policy)
        self._state_path = _state_path(target_id, self.code_hash, self._state_directory) if self.policy.persist_state else None
        self.state = self._load_state() or AdaptiveInstrumentationState(
            target_id=target_id,
            code_hash=self.code_hash,
            level=self.policy.initial_level,
        )
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
                level = self.state.level

            started = time.perf_counter()
            failed = False
            promoted_during_call = False
            try:
                if level is InstrumentationLevel.REPAIR and self.allow_repair_promotion:
                    result = self._repair_call(*args, **kwargs)
                elif level.value >= InstrumentationLevel.BEHAVIOR.value:
                    result = self._behavior_call(*args, **kwargs)
                else:
                    result = self.function(*args, **kwargs)
                return result
            except BaseException as exc:
                failed = True
                promoted_during_call = self._observe_exception(exc)
                raise
            finally:
                elapsed = time.perf_counter() - started
                timing_breach, timing_promoted = self._observe_timing(elapsed)
                promoted_during_call = promoted_during_call or timing_promoted
                if not promoted_during_call:
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

    def _behavior_call(self, *args: Any, **kwargs: Any) -> Any:
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
        if guard is None or not binding.enabled:
            return self.function(*args, **kwargs)
        if not self._behavior_registered:
            guard.register_target(self.target_id, self.function, binding)
            from .guard.models import GuardMode
            guard.request_instrumentation(
                self.target_id,
                GuardMode.RESEARCH,
                execution_count=self.policy.behavior_executions,
                reason=self.state.promotion_reason or "adaptive lightweight promotion",
            )
            self._behavior_registered = True
        call_id = uuid4()
        tokens = set_runtime_context(
            target_id=self.target_id,
            call_id=call_id,
            operation="adaptive-behavior-call",
        )
        started = time.perf_counter()
        succeeded = False
        guard.before_call(self.target_id, self.function, call_id, candidate_id=None)
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

    def _observe_exception(self, exception: BaseException) -> bool:
        now = time.time()
        promoted = False
        with self._lock:
            if self.state.level.value >= InstrumentationLevel.BEHAVIOR.value:
                self._diagnostic({
                    "timestamp": utcnow_iso(),
                    "kind": "exception",
                    "exception_type": type(exception).__name__,
                })
            policy = self.policy.exception
            if policy.enabled:
                self._append_window(self._exception_events, now, policy.window_seconds)
                self._persist_event_state()
                if len(self._exception_events) >= policy.occurrences:
                    promoted = self._promote(
                        policy.promote_to,
                        f"{policy.occurrences} exceptions within {policy.window_seconds:g}s",
                    )
        return promoted

    def _observe_timing(self, elapsed: float) -> tuple[bool, bool]:
        policy = self.policy.soft_timing
        if not policy.enabled or elapsed <= policy.seconds:
            return False, False
        now = time.time()
        promoted = False
        with self._lock:
            if self.state.level.value >= InstrumentationLevel.BEHAVIOR.value:
                self._diagnostic({
                    "timestamp": utcnow_iso(),
                    "kind": "soft-timing-breach",
                    "elapsed_seconds": elapsed,
                    "threshold_seconds": policy.seconds,
                })
            self._append_window(self._timing_events, now, policy.window_seconds)
            self._persist_event_state()
            if len(self._timing_events) >= policy.occurrences:
                promoted = self._promote(
                    policy.promote_to,
                    f"{policy.occurrences} soft timing breaches > {policy.seconds:g}s within {policy.window_seconds:g}s",
                )
        return True, promoted

    def _promote(self, requested: InstrumentationLevel, reason: str) -> bool:
        if requested is InstrumentationLevel.REPAIR and not self.allow_repair_promotion:
            requested = InstrumentationLevel.BEHAVIOR
        if requested.value <= self.state.level.value:
            return False
        now = utcnow_iso()
        self.state.level = requested
        self.state.acceptance = AcceptanceState.PROBATION
        self.state.promoted_at = now
        self.state.promotion_reason = reason
        self.state.short_term_accepted_at = None
        self.state.long_term_accepted_at = None
        self.state.successful_executions = 0
        self.state.probation_failures = 0
        self.state.long_term_successes = 0
        self.state.long_term_failures = 0
        self.state.last_transition_at = now
        self._exception_events.clear()
        self._timing_events.clear()
        self._persist()
        self._publish_state()
        return True

    def _observe_acceptance(self, *, success: bool) -> None:
        with self._lock:
            if self.state.level is InstrumentationLevel.LIGHTWEIGHT:
                return
            if success:
                self._record_acceptance_success()
            else:
                self._record_acceptance_failure()
            self._persist()
            self._publish_state()

    def _record_acceptance_success(self) -> None:
        policy = self.policy.demotion
        if self.state.acceptance in {AcceptanceState.NONE, AcceptanceState.PROBATION}:
            self.state.acceptance = AcceptanceState.PROBATION
            self.state.successful_executions += 1
            if (
                self.state.successful_executions >= policy.initial_successful_executions
                and self.state.probation_failures <= policy.probation_failure_budget
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
        if self.state.long_term_successes < policy.long_term_successful_executions:
            return False
        if self.state.long_term_failures > policy.long_term_maximum_failures:
            return False
        total = self.state.long_term_successes + self.state.long_term_failures
        if total and (self.state.long_term_failures / total) > policy.long_term_failure_rate:
            return False
        start = self.state.short_term_accepted_at
        if start is None:
            return False
        try:
            accepted_at = datetime.fromisoformat(start).timestamp()
        except ValueError:
            return False
        return (time.time() - accepted_at) >= policy.long_term_minimum_duration_seconds

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
        self._code_object = current_code
        self.code_hash = _function_hash(self.function)
        self._exception_events.clear()
        self._timing_events.clear()
        self._managed_wrapper = None
        self._behavior_registered = False
        self._state_path = (
            _state_path(self.target_id, self.code_hash, self._state_directory)
            if self.policy.persist_state
            else None
        )
        self.state = self._load_state() or AdaptiveInstrumentationState(
            target_id=self.target_id,
            code_hash=self.code_hash,
            level=self.policy.initial_level,
        )
        self._publish_state()

    def _refresh_policy_if_needed(self) -> None:
        fingerprint = _authority_context().effective.fingerprint
        if fingerprint == self._authority_fingerprint:
            return
        self.policy = self._effective_policy()
        validate_lightweight_policy(self.policy)

    def _effective_policy(self) -> LightweightPolicy:
        context = _authority_context()
        policy = context.apply(self.declared_policy, prefix="lightweight", target_id=self.target_id)
        self._authority_fingerprint = context.effective.fingerprint
        return policy

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
                acceptance=AcceptanceState(str(data.get("acceptance", "none"))),
                promoted_at=data.get("promoted_at"),
                promotion_reason=data.get("promotion_reason"),
                short_term_accepted_at=data.get("short_term_accepted_at"),
                long_term_accepted_at=data.get("long_term_accepted_at"),
                successful_executions=int(data.get("successful_executions", 0)),
                probation_failures=int(data.get("probation_failures", 0)),
                long_term_successes=int(data.get("long_term_successes", 0)),
                long_term_failures=int(data.get("long_term_failures", 0)),
                last_transition_at=data.get("last_transition_at"),
                recent_diagnostics=[dict(item) for item in data.get("recent_diagnostics", ())][-20:],
            )
        except Exception:
            return None

    def _persist_event_state(self) -> None:
        # Persist only noteworthy threshold events. Healthy LIGHTWEIGHT calls still
        # perform no Caretaker filesystem I/O, while rolling windows survive restart.
        self._persist()

    def _persist(self) -> None:
        if self._state_path is None:
            return
        self._state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = self.state.public_dict()
        payload["policy_fingerprint"] = _policy_hash(self.policy)
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
    promote_to: InstrumentationLevel = InstrumentationLevel.BEHAVIOR,
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
        behavior_binding=_DEPENDENCY_BINDING,
        allow_repair_promotion=False,
    )
