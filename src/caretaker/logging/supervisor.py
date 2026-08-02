from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping
from uuid import UUID, uuid4

from .handler import LoggingRuntime
from .models import (
    ActiveWork,
    CaretakerComponent,
    LoggingMode,
    WorkState,
    WorkerFailureAction,
    WorkerHealth,
    WorkerKind,
    WorkerState,
)


class WorkRegistry:
    def __init__(self, *, recent_seconds: float = 60.0) -> None:
        self.recent_seconds = recent_seconds
        self._active: dict[UUID, ActiveWork] = {}
        self._recent: dict[UUID, ActiveWork] = {}
        self._lock = threading.RLock()

    def start(
        self,
        *,
        component: CaretakerComponent,
        work_kind: str,
        scope: str,
        root_signal_id: UUID,
        expected_code_fingerprints: Mapping[str, str] | None = None,
        parent_work_id: UUID | None = None,
    ) -> ActiveWork:
        work = ActiveWork(
            work_id=uuid4(), component=component, work_kind=work_kind, scope=scope,
            started_at=datetime.now(timezone.utc), expected_completion_at=None,
            current_state=WorkState.ACTIVE,
            expected_code_fingerprints=dict(expected_code_fingerprints or {}),
            parent_work_id=parent_work_id, root_signal_id=root_signal_id,
        )
        with self._lock:
            self._active[work.work_id] = work
        return work

    def finish(self, work_id: UUID, *, state: WorkState = WorkState.COMPLETED) -> ActiveWork:
        with self._lock:
            work = self._active.pop(work_id)
            completed = replace(
                work, current_state=state,
                recently_changed_until=datetime.now(timezone.utc) + timedelta(seconds=self.recent_seconds),
            )
            self._recent[work_id] = completed
            return completed

    def overlapping(self, scope: str) -> tuple[ActiveWork, ...]:
        self.expire_recent()
        with self._lock:
            return tuple(
                item for item in (*self._active.values(), *self._recent.values())
                if scope == item.scope or scope.startswith(item.scope + ".") or item.scope.startswith(scope + ".")
            )

    def all(self) -> tuple[ActiveWork, ...]:
        self.expire_recent()
        with self._lock:
            return tuple((*self._active.values(), *self._recent.values()))

    def expire_recent(self) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            for work_id, work in tuple(self._recent.items()):
                if work.recently_changed_until and work.recently_changed_until <= now:
                    self._recent.pop(work_id, None)


class WorkerRegistry:
    def __init__(self, *, heartbeat_timeout_seconds: float = 15.0) -> None:
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._workers: dict[UUID, WorkerHealth] = {}
        self._lock = threading.RLock()

    def register(self, kind: WorkerKind, pid: int) -> WorkerHealth:
        now = datetime.now(timezone.utc)
        health = WorkerHealth(
            worker_id=uuid4(), worker_kind=kind, process_id=pid,
            process_start_id=uuid4(), started_at=now, last_heartbeat_at=now,
            state=WorkerState.STARTING, current_work_ids=(), queue_depth=0,
            last_completed_sequence=None, restart_count=0, last_error_fingerprint=None,
        )
        with self._lock:
            self._workers[health.worker_id] = health
        return health

    def heartbeat(
        self,
        worker_id: UUID,
        *,
        state: WorkerState = WorkerState.HEALTHY,
        current_work_ids: tuple[UUID, ...] = (),
        queue_depth: int = 0,
        last_completed_sequence: int | None = None,
    ) -> WorkerHealth:
        with self._lock:
            current = self._workers[worker_id]
            updated = replace(
                current, last_heartbeat_at=datetime.now(timezone.utc), state=state,
                current_work_ids=current_work_ids, queue_depth=queue_depth,
                last_completed_sequence=last_completed_sequence,
            )
            self._workers[worker_id] = updated
            return updated

    def mark_failed(self, worker_id: UUID, *, error_fingerprint: str | None = None) -> WorkerHealth:
        with self._lock:
            current = self._workers[worker_id]
            updated = replace(
                current,
                state=WorkerState.FAILED,
                last_heartbeat_at=datetime.now(timezone.utc),
                last_error_fingerprint=error_fingerprint,
            )
            self._workers[worker_id] = updated
            return updated

    def record_restart(self, worker_id: UUID, *, pid: int | None = None) -> WorkerHealth:
        with self._lock:
            current = self._workers[worker_id]
            updated = replace(
                current,
                process_id=current.process_id if pid is None else pid,
                process_start_id=uuid4(),
                started_at=datetime.now(timezone.utc),
                last_heartbeat_at=datetime.now(timezone.utc),
                state=WorkerState.STARTING,
                current_work_ids=(),
                queue_depth=0,
                restart_count=current.restart_count + 1,
                last_error_fingerprint=None,
            )
            self._workers[worker_id] = updated
            return updated

    def unhealthy(self) -> tuple[WorkerHealth, ...]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.heartbeat_timeout_seconds)
        with self._lock:
            return tuple(item for item in self._workers.values() if item.last_heartbeat_at < cutoff or item.state is WorkerState.FAILED)

    def all(self) -> tuple[WorkerHealth, ...]:
        with self._lock:
            return tuple(self._workers.values())


class Watchdog:
    def __init__(
        self,
        registry: WorkerRegistry,
        *,
        on_unhealthy: Callable[[WorkerHealth], None],
        interval_seconds: float = 2.0,
    ) -> None:
        self.registry = registry
        self.on_unhealthy = on_unhealthy
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="caretaker-watchdog", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        seen: set[UUID] = set()
        while not self._stop.wait(self.interval_seconds):
            for worker in self.registry.unhealthy():
                if worker.worker_id not in seen:
                    self.on_unhealthy(worker)
                    seen.add(worker.worker_id)
            healthy = {item.worker_id for item in self.registry.all() if item not in self.registry.unhealthy()}
            seen.intersection_update(set(item.worker_id for item in self.registry.all()) - healthy)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


class CaretakerApplicationSupervisor:
    """Application-scoped supervisor.

    Caretaker follows the application lifecycle and exits when the application
    terminates. It does not attempt to become a machine-wide service manager.
    """

    def __init__(self, runtime: LoggingRuntime, *, application_pid: int | None = None) -> None:
        self.runtime = runtime
        self.application_pid = application_pid
        self.work = WorkRegistry()
        self.workers = WorkerRegistry()
        self.supervisor_health = self.workers.register(WorkerKind.SUPERVISOR, os.getpid())
        self.watchdog = Watchdog(self.workers, on_unhealthy=self._worker_unhealthy)
        self._stop = threading.Event()

    def start(self) -> None:
        self.workers.heartbeat(self.supervisor_health.worker_id)
        self.watchdog.start()

    def _worker_unhealthy(self, worker: WorkerHealth) -> None:
        self.runtime.event(
            logger_name="caretaker.watchdog", severity=40,
            channel=__import__("caretaker.logging.models", fromlist=["LogChannel"]).LogChannel.CARETAKER_INTERNAL,
            message=f"Caretaker worker unhealthy: {worker.worker_kind.name}",
            fields={"worker_id": str(worker.worker_id), "pid": worker.process_id},
        )

    def monitor_application(self, *, interval_seconds: float = 1.0) -> None:
        while not self._stop.wait(interval_seconds):
            self.workers.heartbeat(self.supervisor_health.worker_id)
            if self.application_pid is not None and not _pid_alive(self.application_pid):
                self.stop()
                return

    def stop_application(self, *, graceful_signal: int = signal.SIGTERM, timeout_seconds: float = 10.0) -> None:
        if self.application_pid is None:
            return
        try:
            os.kill(self.application_pid, graceful_signal)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline and _pid_alive(self.application_pid):
            time.sleep(0.1)
        if _pid_alive(self.application_pid):
            os.kill(self.application_pid, signal.SIGKILL)

    def stop(self) -> None:
        self._stop.set()
        self.watchdog.stop()
        self.runtime.close()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
