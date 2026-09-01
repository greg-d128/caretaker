from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from collections import OrderedDict, deque
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event, RLock
from time import monotonic
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID, uuid4

from .evidence.models import CodeIdentity


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SignalDomain(Enum):
    FAILURE = auto()
    BEHAVIOR = auto()
    INTEGRITY = auto()
    IMPORT = auto()
    INTERNAL = auto()


class SignalSeverity(Enum):
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class RuntimeActionKind(Enum):
    RECORD = auto()
    ALERT = auto()
    ESCALATE_INSTRUMENTATION = auto()
    INTERROGATE_LOGS = auto()
    OPEN_REPAIR_EPISODE = auto()
    REJECT_REPAIR_CANDIDATE = auto()
    ROLLBACK_REPAIR = auto()
    ALLOW_IMPORT = auto()
    DENY_IMPORT = auto()
    SUBSTITUTE_MODULE = auto()
    QUARANTINE_MODULE = auto()
    RESTART_WITH_MODULE_ROUTE = auto()
    TERMINATE_PROCESS = auto()


@dataclass(frozen=True, slots=True)
class ActionLineage:
    root_signal_id: UUID
    parent_action_id: UUID | None = None
    depth: int = 0
    participating_components: tuple[str, ...] = ()
    repair_episode_ids: tuple[UUID, ...] = ()
    deviation_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True)
class RuntimeSignal:
    signal_id: UUID
    occurred_at: datetime
    domain: SignalDomain
    kind: str
    severity: SignalSeverity
    run_id: UUID
    call_id: UUID | None
    target_id: str | None
    module_identity: CodeIdentity | None
    evidence_refs: tuple[UUID, ...]
    source_component: str
    requires_immediate_decision: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)
    lineage: ActionLineage | None = None

    @classmethod
    def create(
        cls,
        *,
        domain: SignalDomain,
        kind: str,
        severity: SignalSeverity,
        run_id: UUID,
        source_component: str,
        call_id: UUID | None = None,
        target_id: str | None = None,
        module_identity: CodeIdentity | None = None,
        evidence_refs: tuple[UUID, ...] = (),
        requires_immediate_decision: bool = False,
        attributes: Mapping[str, Any] | None = None,
        lineage: ActionLineage | None = None,
    ) -> "RuntimeSignal":
        signal_id = uuid4()
        return cls(
            signal_id=signal_id,
            occurred_at=utcnow(),
            domain=domain,
            kind=kind,
            severity=severity,
            run_id=run_id,
            call_id=call_id,
            target_id=target_id,
            module_identity=module_identity,
            evidence_refs=evidence_refs,
            source_component=source_component,
            requires_immediate_decision=requires_immediate_decision,
            attributes=attributes or {},
            lineage=lineage or ActionLineage(root_signal_id=signal_id),
        )


@dataclass(frozen=True, slots=True)
class RuntimeDecision:
    decision_id: UUID
    signal_id: UUID
    actions: tuple[RuntimeActionKind, ...]
    reason: str
    policy_id: str
    created_at: datetime
    selected_module_variant_id: str | None = None
    requires_human_review: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeAction:
    action_id: UUID
    decision_id: UUID
    signal_id: UUID
    kind: RuntimeActionKind
    created_at: datetime
    reason: str
    lineage: ActionLineage
    attributes: Mapping[str, Any] = field(default_factory=dict)


class RuntimePolicyEngine(Protocol):
    def evaluate(self, signal: RuntimeSignal, context: Mapping[str, Any]) -> RuntimeDecision: ...


class DefaultRuntimePolicyEngine:
    """Conservative default policy.

    Deterministic integrity/import denials take precedence. Behavioral signals
    alert and escalate by default; they do not terminate execution solely from
    an LLM or statistical assessment.
    """

    policy_id = "caretaker-default-control-v1"

    def evaluate(self, signal: RuntimeSignal, context: Mapping[str, Any]) -> RuntimeDecision:
        actions: tuple[RuntimeActionKind, ...]
        human_review = False
        if signal.domain is SignalDomain.INTEGRITY and signal.severity in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }:
            actions = (RuntimeActionKind.ALERT, RuntimeActionKind.DENY_IMPORT)
        elif signal.domain is SignalDomain.IMPORT and signal.attributes.get("quarantined"):
            fallback = signal.attributes.get("fallback_variant_id")
            actions = (
                (RuntimeActionKind.SUBSTITUTE_MODULE,)
                if fallback
                else (RuntimeActionKind.DENY_IMPORT,)
            )
        elif signal.domain is SignalDomain.BEHAVIOR:
            requested = str(signal.attributes.get("requested_action", ""))
            if requested == "ROLLBACK_ACTIVE_CANDIDATE":
                actions = (RuntimeActionKind.ALERT, RuntimeActionKind.ROLLBACK_REPAIR)
            elif requested == "OPEN_REPAIR_EPISODE":
                actions = (RuntimeActionKind.ALERT, RuntimeActionKind.OPEN_REPAIR_EPISODE)
            elif requested == "QUARANTINE_TARGET":
                actions = (RuntimeActionKind.ALERT, RuntimeActionKind.QUARANTINE_MODULE)
            elif requested == "ALERT":
                actions = (RuntimeActionKind.ALERT,)
            elif signal.severity in {SignalSeverity.HIGH, SignalSeverity.CRITICAL}:
                actions = (
                    RuntimeActionKind.ALERT,
                    RuntimeActionKind.ESCALATE_INSTRUMENTATION,
                )
                human_review = True
            else:
                actions = (RuntimeActionKind.RECORD,)
        elif signal.domain is SignalDomain.FAILURE:
            actions = (RuntimeActionKind.RECORD, RuntimeActionKind.OPEN_REPAIR_EPISODE)
        elif signal.domain is SignalDomain.INTERNAL:
            actions = (RuntimeActionKind.ALERT,)
            human_review = signal.severity in {SignalSeverity.HIGH, SignalSeverity.CRITICAL}
        else:
            actions = (RuntimeActionKind.RECORD,)
        return RuntimeDecision(
            decision_id=uuid4(),
            signal_id=signal.signal_id,
            actions=actions,
            reason=f"Default policy for {signal.domain.name}:{signal.kind}",
            policy_id=self.policy_id,
            created_at=utcnow(),
            selected_module_variant_id=signal.attributes.get("fallback_variant_id"),
            requires_human_review=human_review,
        )


ActionHandler = Callable[[RuntimeAction, RuntimeSignal], None]


@dataclass(frozen=True, slots=True)
class RuntimeInteractionPolicy:
    maximum_action_depth: int = 4
    duplicate_window_seconds: float = 30.0
    minimum_internal_change_interval_seconds: float = 30.0
    maximum_scope_actions_per_window: int = 3
    scope_action_window_seconds: float = 300.0
    maximum_history_entries: int = 4096
    maximum_long_jobs: int = 2
    maximum_active_jobs_per_client: int = 1
    maximum_pending_jobs: int = 8
    maximum_pending_jobs_per_client: int = 4
    maximum_job_history_entries: int = 256
    maximum_job_result_bytes: int = 512 * 1024
    maximum_job_duration_seconds: float = 300.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.maximum_history_entries, bool)
            or not isinstance(self.maximum_history_entries, int)
            or not 1 <= self.maximum_history_entries <= 1_000_000
        ):
            raise ValueError(
                "maximum_history_entries must be an integer from 1 through 1000000"
            )
        for name in (
            "maximum_long_jobs",
            "maximum_active_jobs_per_client",
            "maximum_pending_jobs",
            "maximum_pending_jobs_per_client",
            "maximum_job_history_entries",
            "maximum_job_result_bytes",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive integer")
        if (
            isinstance(self.maximum_job_duration_seconds, bool)
            or not isinstance(self.maximum_job_duration_seconds, (int, float))
            or self.maximum_job_duration_seconds <= 0
        ):
            raise ValueError("maximum_job_duration_seconds must be greater than zero")


class RuntimeJobState(Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    INTERRUPTED = "INTERRUPTED"


class RuntimeJobCancelled(RuntimeError):
    """Raised by a cooperative long-running operation after cancellation."""


class RuntimeJobExpired(RuntimeError):
    """Raised by a cooperative long-running operation after its deadline."""


@dataclass(frozen=True, slots=True)
class RuntimeJob:
    job_id: UUID
    command: str
    client_id: str
    submitted_at: datetime
    state: RuntimeJobState
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: Mapping[str, Any] | None = None
    error: str | None = None

    def public_dict(self, *, include_result: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": str(self.job_id),
            "command": self.command,
            "client_id": self.client_id,
            "submitted_at": self.submitted_at.isoformat(),
            "state": self.state.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }
        if include_result and self.result is not None:
            payload["result"] = dict(self.result)
        return payload


class RuntimeJobContext:
    """Cancellation and deadline context passed to one long-running job."""

    def __init__(self, cancel_event: Event, deadline: float) -> None:
        self._cancel_event = cancel_event
        self._deadline = deadline

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    @property
    def expired(self) -> bool:
        return monotonic() >= self._deadline

    def checkpoint(self) -> None:
        if self.cancelled:
            raise RuntimeJobCancelled("job cancellation was requested")
        if self.expired:
            raise RuntimeJobExpired("job execution deadline was reached")


JobOperation = Callable[[RuntimeJobContext], Mapping[str, Any]]


class RuntimeJobRegistry:
    """Bounded process-local registry for long control-plane operations.

    The registry deliberately exposes polling and cooperative cancellation
    through the existing control protocol. It does not grant authority to a
    job and does not make a partially completed result actionable.
    """

    def __init__(
        self,
        *,
        interaction_policy: RuntimeInteractionPolicy | None = None,
        on_transition: Callable[[RuntimeJob], None] | None = None,
    ) -> None:
        self.policy = interaction_policy or RuntimeInteractionPolicy()
        self._jobs: OrderedDict[UUID, RuntimeJob] = OrderedDict()
        self._cancel_events: dict[UUID, Event] = {}
        self._futures: dict[UUID, Future[Any]] = {}
        self._lock = RLock()
        self._on_transition = on_transition
        self._executor = ThreadPoolExecutor(
            max_workers=self.policy.maximum_long_jobs,
            thread_name_prefix="caretaker-long-job",
        )
        self._closed = False

    def _notify(self, job: RuntimeJob) -> None:
        callback = self._on_transition
        if callback is not None:
            try:
                callback(job)
            except Exception:
                # Observability must not change job outcome.
                pass

    def _replace(self, job: RuntimeJob) -> RuntimeJob:
        with self._lock:
            self._jobs[job.job_id] = job
            self._jobs.move_to_end(job.job_id)
            self._prune_locked()
        self._notify(job)
        return job

    def _prune_locked(self) -> None:
        terminal = {
            RuntimeJobState.SUCCEEDED,
            RuntimeJobState.FAILED,
            RuntimeJobState.CANCELLED,
            RuntimeJobState.EXPIRED,
            RuntimeJobState.INTERRUPTED,
        }
        while len(self._jobs) > self.policy.maximum_job_history_entries:
            job_id, job = next(iter(self._jobs.items()))
            if job.state not in terminal:
                break
            self._jobs.pop(job_id)
            self._cancel_events.pop(job_id, None)
            self._futures.pop(job_id, None)

    def submit(
        self,
        command: str,
        *,
        client_id: str,
        operation: JobOperation,
    ) -> RuntimeJob:
        if not str(command).strip():
            raise ValueError("long job command cannot be empty")
        if not callable(operation):
            raise TypeError("long job operation must be callable")
        with self._lock:
            if self._closed:
                raise RuntimeError("long job registry is closed")
            pending = sum(job.state is RuntimeJobState.QUEUED for job in self._jobs.values())
            client_active = sum(
                job.client_id == str(client_id)
                and job.state in {RuntimeJobState.RUNNING, RuntimeJobState.CANCEL_REQUESTED}
                for job in self._jobs.values()
            )
            client_pending = sum(
                job.client_id == str(client_id)
                and job.state is RuntimeJobState.QUEUED
                for job in self._jobs.values()
            )
            if client_active >= self.policy.maximum_active_jobs_per_client:
                raise RuntimeError("long job per-client active capacity is exhausted")
            if pending >= self.policy.maximum_pending_jobs:
                raise RuntimeError("long job pending capacity is exhausted")
            if client_pending >= self.policy.maximum_pending_jobs_per_client:
                raise RuntimeError("long job per-client pending capacity is exhausted")
            job = RuntimeJob(
                job_id=uuid4(),
                command=str(command).strip(),
                client_id=str(client_id),
                submitted_at=utcnow(),
                state=RuntimeJobState.QUEUED,
            )
            cancel_event = Event()
            self._jobs[job.job_id] = job
            self._cancel_events[job.job_id] = cancel_event
            future = self._executor.submit(self._execute, job.job_id, operation)
            self._futures[job.job_id] = future
            self._prune_locked()
        self._notify(job)
        return job

    def _execute(self, job_id: UUID, operation: JobOperation) -> None:
        with self._lock:
            current = self._jobs.get(job_id)
            cancel_event = self._cancel_events.get(job_id)
            if current is None or cancel_event is None or current.state is not RuntimeJobState.QUEUED:
                return

        started = RuntimeJob(
            job_id=current.job_id,
            command=current.command,
            client_id=current.client_id,
            submitted_at=current.submitted_at,
            state=RuntimeJobState.RUNNING,
            started_at=utcnow(),
        )
        self._replace(started)
        context = RuntimeJobContext(
            cancel_event,
            monotonic() + float(self.policy.maximum_job_duration_seconds),
        )
        try:
            context.checkpoint()
            result = operation(context)
            context.checkpoint()
            if not isinstance(result, Mapping):
                raise TypeError("long job operation must return a mapping")
            encoded = json.dumps(dict(result), default=str, separators=(",", ":")).encode()
            if len(encoded) > self.policy.maximum_job_result_bytes:
                raise ValueError(
                    "long job result exceeds the configured byte limit "
                    f"({self.policy.maximum_job_result_bytes})"
                )
            with self._lock:
                current = self._jobs.get(job_id)
                if current is None or current.state is RuntimeJobState.INTERRUPTED:
                    return
                final = RuntimeJob(
                    job_id=current.job_id,
                    command=current.command,
                    client_id=current.client_id,
                    submitted_at=current.submitted_at,
                    state=(
                        RuntimeJobState.CANCELLED
                        if current.state is RuntimeJobState.CANCEL_REQUESTED
                        else RuntimeJobState.SUCCEEDED
                    ),
                    started_at=current.started_at,
                    completed_at=utcnow(),
                    result=dict(result) if current.state is not RuntimeJobState.CANCEL_REQUESTED else None,
                    error=("job cancellation was requested" if current.state is RuntimeJobState.CANCEL_REQUESTED else None),
                )
            self._replace(final)
        except RuntimeJobCancelled as exc:
            self._finish(job_id, RuntimeJobState.CANCELLED, error=str(exc))
        except RuntimeJobExpired as exc:
            self._finish(job_id, RuntimeJobState.EXPIRED, error=str(exc))
        except Exception as exc:
            self._finish(job_id, RuntimeJobState.FAILED, error=f"{type(exc).__name__}: {exc}")

    def _finish(self, job_id: UUID, state: RuntimeJobState, *, error: str) -> None:
        with self._lock:
            current = self._jobs.get(job_id)
            if current is None or current.state is RuntimeJobState.INTERRUPTED:
                return
            final = RuntimeJob(
                job_id=current.job_id,
                command=current.command,
                client_id=current.client_id,
                submitted_at=current.submitted_at,
                state=state,
                started_at=current.started_at,
                completed_at=utcnow(),
                error=str(error)[:2048],
            )
        self._replace(final)

    def status(self, job_id: UUID | str) -> RuntimeJob:
        parsed = UUID(str(job_id))
        with self._lock:
            job = self._jobs.get(parsed)
            if job is None:
                raise KeyError(f"unknown long job {parsed}")
            return job

    def cancel(self, job_id: UUID | str) -> RuntimeJob:
        parsed = UUID(str(job_id))
        with self._lock:
            current = self._jobs.get(parsed)
            event = self._cancel_events.get(parsed)
            if current is None or event is None:
                raise KeyError(f"unknown long job {parsed}")
            if current.state in {
                RuntimeJobState.SUCCEEDED,
                RuntimeJobState.FAILED,
                RuntimeJobState.CANCELLED,
                RuntimeJobState.EXPIRED,
                RuntimeJobState.INTERRUPTED,
            }:
                return current
            event.set()
            future = self._futures.get(parsed)
            if current.state is RuntimeJobState.QUEUED and future is not None and future.cancel():
                final = RuntimeJob(
                    job_id=current.job_id,
                    command=current.command,
                    client_id=current.client_id,
                    submitted_at=current.submitted_at,
                    state=RuntimeJobState.CANCELLED,
                    completed_at=utcnow(),
                    error="job cancelled before execution",
                )
            else:
                final = RuntimeJob(
                    job_id=current.job_id,
                    command=current.command,
                    client_id=current.client_id,
                    submitted_at=current.submitted_at,
                    state=RuntimeJobState.CANCEL_REQUESTED,
                    started_at=current.started_at,
                )
        return self._replace(final)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(self._jobs.values())
            for event in self._cancel_events.values():
                event.set()
            for job in active:
                if job.state in {
                    RuntimeJobState.QUEUED,
                    RuntimeJobState.RUNNING,
                    RuntimeJobState.CANCEL_REQUESTED,
                }:
                    self._jobs[job.job_id] = RuntimeJob(
                        job_id=job.job_id,
                        command=job.command,
                        client_id=job.client_id,
                        submitted_at=job.submitted_at,
                        state=RuntimeJobState.INTERRUPTED,
                        started_at=job.started_at,
                        completed_at=utcnow(),
                        error="runtime control plane shut down",
                    )
        self._executor.shutdown(wait=False, cancel_futures=True)



class RuntimeControlPlane:
    def __init__(
        self,
        *,
        policy_engine: RuntimePolicyEngine | None = None,
        maximum_action_depth: int = 4,
        interaction_policy: RuntimeInteractionPolicy | None = None,
    ) -> None:
        self.policy_engine = policy_engine or DefaultRuntimePolicyEngine()
        self.interaction_policy = interaction_policy or RuntimeInteractionPolicy(maximum_action_depth=maximum_action_depth)
        self.maximum_action_depth = self.interaction_policy.maximum_action_depth
        history_limit = self.interaction_policy.maximum_history_entries
        self.signals: deque[RuntimeSignal] = deque(maxlen=history_limit)
        self.decisions: deque[RuntimeDecision] = deque(maxlen=history_limit)
        self.actions: deque[RuntimeAction] = deque(maxlen=history_limit)
        self._handlers: dict[RuntimeActionKind, list[ActionHandler]] = {}
        self._seen: dict[tuple[str, str | None, str | None], datetime] = {}
        self._scope_action_history: dict[tuple[str | None, RuntimeActionKind], list[datetime]] = {}
        self._lock = RLock()

    def register_handler(self, kind: RuntimeActionKind, handler: ActionHandler) -> None:
        with self._lock:
            self._handlers.setdefault(kind, []).append(handler)

    def submit(
        self,
        signal: RuntimeSignal,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> RuntimeDecision:
        lineage = signal.lineage or ActionLineage(root_signal_id=signal.signal_id)
        if lineage.depth > self.maximum_action_depth:
            return RuntimeDecision(
                decision_id=uuid4(),
                signal_id=signal.signal_id,
                actions=(RuntimeActionKind.RECORD,),
                reason="Maximum cross-subsystem action depth exceeded",
                policy_id="loop-suppression",
                created_at=utcnow(),
            )
        dedupe_key = (signal.kind, signal.target_id, signal.module_identity.logical_name if signal.module_identity else None)
        now = utcnow()
        with self._lock:
            self.signals.append(signal)
            previous = self._seen.get(dedupe_key)
            duplicate = bool(
                previous is not None
                and (now - previous).total_seconds() < self.interaction_policy.duplicate_window_seconds
                and not signal.requires_immediate_decision
            )
            self._seen[dedupe_key] = now
            cutoff = now - timedelta(seconds=self.interaction_policy.duplicate_window_seconds)
            self._seen = {key: seen_at for key, seen_at in self._seen.items() if seen_at >= cutoff}
        work_decision = self._work_in_progress_decision(signal, context or {})
        if work_decision is not None:
            decision = work_decision
        elif duplicate:
            decision = RuntimeDecision(
                decision_id=uuid4(),
                signal_id=signal.signal_id,
                actions=(RuntimeActionKind.RECORD,),
                reason="Duplicate non-immediate signal suppressed",
                policy_id="deduplication",
                created_at=utcnow(),
            )
        else:
            decision = self.policy_engine.evaluate(signal, context or {})
        with self._lock:
            self.decisions.append(decision)
        for kind in decision.actions:
            if self._rate_limited(signal.target_id, kind, signal.domain):
                kind = RuntimeActionKind.RECORD
            action = RuntimeAction(
                action_id=uuid4(),
                decision_id=decision.decision_id,
                signal_id=signal.signal_id,
                kind=kind,
                created_at=utcnow(),
                reason=decision.reason,
                lineage=ActionLineage(
                    root_signal_id=lineage.root_signal_id,
                    parent_action_id=lineage.parent_action_id,
                    depth=lineage.depth + 1,
                    participating_components=lineage.participating_components + (signal.source_component,),
                    repair_episode_ids=lineage.repair_episode_ids,
                    deviation_ids=lineage.deviation_ids,
                ),
                attributes=decision.attributes,
            )
            with self._lock:
                self.actions.append(action)
                handlers = tuple(self._handlers.get(kind, ()))
            for handler in handlers:
                handler(action, signal)
        return decision

    def _work_in_progress_decision(
        self,
        signal: RuntimeSignal,
        context: Mapping[str, Any],
    ) -> RuntimeDecision | None:
        registry = context.get("work_registry")
        if registry is None or signal.target_id is None:
            return None
        try:
            overlapping = registry.overlapping(signal.target_id)
        except Exception:
            return None
        if not overlapping:
            return None
        observed = signal.attributes.get("observed_code_fingerprint")
        expected = {
            fingerprint
            for work in overlapping
            for scope, fingerprint in work.expected_code_fingerprints.items()
            if scope == signal.target_id or signal.target_id.startswith(scope + ".")
        }
        if observed is not None and observed in expected:
            return RuntimeDecision(
                decision_id=uuid4(), signal_id=signal.signal_id,
                actions=(RuntimeActionKind.RECORD,),
                reason="Observed change matches active Caretaker work in progress",
                policy_id="active-work-correlation", created_at=utcnow(),
                attributes={"work_ids": [str(work.work_id) for work in overlapping]},
            )
        return RuntimeDecision(
            decision_id=uuid4(), signal_id=signal.signal_id,
            actions=(RuntimeActionKind.ALERT, RuntimeActionKind.INTERROGATE_LOGS),
            reason="Observed change overlaps active work but does not match its expected fingerprint",
            policy_id="active-work-conflict", created_at=utcnow(),
            requires_human_review=True,
            attributes={"work_ids": [str(work.work_id) for work in overlapping]},
        )

    def _rate_limited(
        self,
        target_id: str | None,
        kind: RuntimeActionKind,
        domain: SignalDomain,
    ) -> bool:
        if kind not in {
            RuntimeActionKind.OPEN_REPAIR_EPISODE,
            RuntimeActionKind.ROLLBACK_REPAIR,
            RuntimeActionKind.QUARANTINE_MODULE,
            RuntimeActionKind.RESTART_WITH_MODULE_ROUTE,
        }:
            return False
        now = utcnow()
        key = (target_id, kind)
        cutoff = now - timedelta(seconds=self.interaction_policy.scope_action_window_seconds)
        with self._lock:
            history = [item for item in self._scope_action_history.get(key, ()) if item >= cutoff]
            if domain is SignalDomain.INTERNAL and history:
                if (now - history[-1]).total_seconds() < self.interaction_policy.minimum_internal_change_interval_seconds:
                    self._scope_action_history[key] = history
                    return True
            if len(history) >= self.interaction_policy.maximum_scope_actions_per_window:
                self._scope_action_history[key] = history
                return True
            history.append(now)
            self._scope_action_history[key] = history
        return False
