from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from collections import OrderedDict, deque
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from threading import Event, RLock
from time import monotonic
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID, uuid4

from .evidence.models import CodeIdentity
from .validation_primitives import finite_number


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
        try:
            finite_number(
                self.maximum_job_duration_seconds,
                name="maximum_job_duration_seconds",
                minimum=0.0,
            )
        except ValueError as exc:
            raise ValueError("maximum_job_duration_seconds must be a finite positive number") from exc
        if self.maximum_job_duration_seconds <= 0:
            raise ValueError("maximum_job_duration_seconds must be a finite positive number")
        for name in (
            "duplicate_window_seconds",
            "minimum_internal_change_interval_seconds",
            "scope_action_window_seconds",
        ):
            try:
                finite_number(getattr(self, name), name=name, minimum=0.0)
            except ValueError as exc:
                raise ValueError(f"{name} must be a finite non-negative number") from exc


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
    progress: Mapping[str, Any] | None = None

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
        if self.progress is not None:
            payload["progress"] = dict(self.progress)
        if include_result and self.result is not None:
            payload["result"] = dict(self.result)
        return payload


RUNTIME_JOB_STORE_SCHEMA_VERSION = 1


class RuntimeJobStore(Protocol):
    """Durable owner for bounded control-plane job records."""

    def load(self, *, limit: int) -> tuple[RuntimeJob, ...]: ...
    def save(self, job: RuntimeJob) -> None: ...
    def delete(self, job_id: UUID) -> None: ...
    def prune(self, *, limit: int) -> None: ...


class RuntimeJobStoreError(RuntimeError):
    """Raised when a durable control-plane job record is invalid."""


class SQLiteRuntimeJobStore:
    """Small SQLite store for restart-visible control-plane job summaries.

    Callable operations are never persisted.  On a new process, any queued or
    running record is therefore reclassified as interrupted by the registry.
    """

    def __init__(self, path: str | Any) -> None:
        self.path = str(path)
        parent = Path(self.path).parent
        parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS caretaker_runtime_job_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = connection.execute(
                "SELECT value FROM caretaker_runtime_job_metadata WHERE key='schema_version'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO caretaker_runtime_job_metadata(key, value) VALUES (?, ?)",
                    ("schema_version", str(RUNTIME_JOB_STORE_SCHEMA_VERSION)),
                )
            elif int(row["value"]) != RUNTIME_JOB_STORE_SCHEMA_VERSION:
                raise RuntimeJobStoreError(
                    f"unsupported runtime job store schema: {row['value']}"
                )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS caretaker_runtime_jobs (
                    job_id TEXT PRIMARY KEY,
                    command TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    state TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    progress_json TEXT,
                    result_json TEXT,
                    error TEXT
                )"""
            )

    @staticmethod
    def _timestamp(value: str | None) -> datetime | None:
        if value is None:
            return None
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeJobStoreError("runtime job timestamp is invalid") from exc

    @staticmethod
    def _json_mapping(value: str | None, field_name: str) -> Mapping[str, Any] | None:
        if value is None:
            return None
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeJobStoreError(f"runtime job {field_name} is invalid JSON") from exc
        if not isinstance(parsed, Mapping):
            raise RuntimeJobStoreError(f"runtime job {field_name} is not a mapping")
        return dict(parsed)

    @classmethod
    def _row_to_job(cls, row: sqlite3.Row) -> RuntimeJob:
        try:
            job_id = UUID(str(row["job_id"]))
            state = RuntimeJobState(str(row["state"]))
            submitted_at = cls._timestamp(row["submitted_at"])
        except (TypeError, ValueError, KeyError) as exc:
            raise RuntimeJobStoreError("runtime job identity or state is invalid") from exc
        if submitted_at is None:
            raise RuntimeJobStoreError("runtime job submitted_at is missing")
        return RuntimeJob(
            job_id=job_id,
            command=str(row["command"]),
            client_id=str(row["client_id"]),
            submitted_at=submitted_at,
            state=state,
            started_at=cls._timestamp(row["started_at"]),
            completed_at=cls._timestamp(row["completed_at"]),
            progress=cls._json_mapping(row["progress_json"], "progress"),
            result=cls._json_mapping(row["result_json"], "result"),
            error=row["error"],
        )

    def load(self, *, limit: int) -> tuple[RuntimeJob, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("runtime job store load limit must be a positive integer")
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM caretaker_runtime_jobs "
                "ORDER BY submitted_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(self._row_to_job(row) for row in reversed(rows))

    def save(self, job: RuntimeJob) -> None:
        result = (
            json.dumps(dict(job.result), default=str, sort_keys=True, separators=(",", ":"))
            if job.result is not None
            else None
        )
        progress = (
            json.dumps(dict(job.progress), default=str, sort_keys=True, separators=(",", ":"))
            if job.progress is not None
            else None
        )
        with self._lock, self._connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO caretaker_runtime_jobs
                (job_id, command, client_id, submitted_at, state, started_at,
                 completed_at, progress_json, result_json, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(job.job_id),
                    job.command,
                    job.client_id,
                    job.submitted_at.isoformat(),
                    job.state.value,
                    job.started_at.isoformat() if job.started_at else None,
                    job.completed_at.isoformat() if job.completed_at else None,
                    progress,
                    result,
                    job.error,
                ),
            )

    def delete(self, job_id: UUID) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "DELETE FROM caretaker_runtime_jobs WHERE job_id=?", (str(job_id),)
            )

    def prune(self, *, limit: int) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("runtime job store prune limit must be a positive integer")
        with self._lock, self._connect() as connection:
            connection.execute(
                """DELETE FROM caretaker_runtime_jobs
                WHERE job_id NOT IN (
                    SELECT job_id FROM caretaker_runtime_jobs
                    ORDER BY submitted_at DESC LIMIT ?
                )""",
                (limit,),
            )


class RuntimeJobContext:
    """Cancellation and deadline context passed to one long-running job."""

    def __init__(
        self,
        cancel_event: Event,
        deadline: float,
        report_progress: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        self._cancel_event = cancel_event
        self._deadline = deadline
        self._report_progress = report_progress

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

    def report_progress(self, progress: Mapping[str, Any]) -> None:
        """Publish a bounded status mapping for operator polling."""

        if not isinstance(progress, Mapping):
            raise TypeError("job progress must be a mapping")
        if self._report_progress is None:
            return
        self.checkpoint()
        self._report_progress(progress)


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
        job_store: RuntimeJobStore | None = None,
    ) -> None:
        self.policy = interaction_policy or RuntimeInteractionPolicy()
        self._jobs: OrderedDict[UUID, RuntimeJob] = OrderedDict()
        self._cancel_events: dict[UUID, Event] = {}
        self._futures: dict[UUID, Future[Any]] = {}
        self._lock = RLock()
        self._on_transition = on_transition
        self._job_store = job_store
        self._executor = ThreadPoolExecutor(
            max_workers=self.policy.maximum_long_jobs,
            thread_name_prefix="caretaker-long-job",
        )
        self._closed = False
        self._restore_jobs()

    def _restore_jobs(self) -> None:
        store = self._job_store
        if store is None:
            return
        store.prune(limit=self.policy.maximum_job_history_entries)
        restored: list[RuntimeJob] = []
        for job in store.load(limit=self.policy.maximum_job_history_entries):
            if job.state in {
                RuntimeJobState.QUEUED,
                RuntimeJobState.RUNNING,
                RuntimeJobState.CANCEL_REQUESTED,
            }:
                job = RuntimeJob(
                    job_id=job.job_id,
                    command=job.command,
                    client_id=job.client_id,
                    submitted_at=job.submitted_at,
                    state=RuntimeJobState.INTERRUPTED,
                    started_at=job.started_at,
                    completed_at=utcnow(),
                    progress=job.progress,
                    error="runtime control plane restarted before job completion",
                )
                restored.append(job)
            self._jobs[job.job_id] = job
        for job in restored:
            self._notify(job)

    def _notify(self, job: RuntimeJob) -> None:
        store = self._job_store
        if store is not None:
            try:
                store.save(job)
            except Exception:
                # A persistence failure must not change the outcome of a
                # running operation or prevent the in-memory audit callback.
                pass
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
            store = self._job_store
            if store is not None:
                try:
                    store.delete(job_id)
                except Exception:
                    pass

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
            # Publish the admission state before the executor can observe the
            # job. This keeps durable transition order monotonic for fast jobs.
            self._notify(job)
            future = self._executor.submit(self._execute, job.job_id, operation)
            self._futures[job.job_id] = future
            self._prune_locked()
        return job

    def _update_progress(self, job_id: UUID, progress: Mapping[str, Any]) -> None:
        encoded = json.dumps(dict(progress), separators=(",", ":")).encode()
        if len(encoded) > self.policy.maximum_job_result_bytes:
            raise ValueError(
                "job progress exceeds the configured byte limit "
                f"({self.policy.maximum_job_result_bytes})"
            )
        with self._lock:
            current = self._jobs.get(job_id)
            if current is None or current.state not in {
                RuntimeJobState.RUNNING,
                RuntimeJobState.CANCEL_REQUESTED,
            }:
                return
            updated = RuntimeJob(
                job_id=current.job_id,
                command=current.command,
                client_id=current.client_id,
                submitted_at=current.submitted_at,
                state=current.state,
                started_at=current.started_at,
                completed_at=current.completed_at,
                progress=dict(progress),
                result=current.result,
                error=current.error,
            )
        self._replace(updated)

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
            progress=current.progress,
        )
        self._replace(started)
        context = RuntimeJobContext(
            cancel_event,
            monotonic() + float(self.policy.maximum_job_duration_seconds),
            lambda progress: self._update_progress(job_id, progress),
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
                    progress=current.progress,
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
                progress=current.progress,
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
                    progress=current.progress,
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
                    progress=current.progress,
                )
        return self._replace(final)

    def close(self) -> None:
        interrupted: list[RuntimeJob] = []
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
                    interrupted_job = RuntimeJob(
                        job_id=job.job_id,
                        command=job.command,
                        client_id=job.client_id,
                        submitted_at=job.submitted_at,
                        state=RuntimeJobState.INTERRUPTED,
                        started_at=job.started_at,
                        completed_at=utcnow(),
                        progress=job.progress,
                        error="runtime control plane shut down",
                    )
                    self._jobs[job.job_id] = interrupted_job
                    interrupted.append(interrupted_job)
        self._executor.shutdown(wait=False, cancel_futures=True)
        for job in interrupted:
            self._notify(job)



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
