from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4

from .handler import LoggingRuntime
from ..repair_recovery import (
    RecoveryAuthorityPacket,
    RepairRecoveryPolicy,
    verify_recovery_authority_packet,
)
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

    def register_authorized(
        self,
        kind: WorkerKind,
        pid: int,
        packet: RecoveryAuthorityPacket,
        *,
        supervisor_time: datetime,
        target_id: str,
        generation_id: str,
        code_hash: str,
        policy_fingerprint: str,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        allowed_capabilities: set[str] | frozenset[str] = frozenset(),
        policy: RepairRecoveryPolicy | None = None,
    ) -> WorkerHealth:
        """Admit a worker only after exact packet/context verification."""
        verification = verify_recovery_authority_packet(
            packet,
            supervisor_time=supervisor_time,
            target_id=target_id,
            generation_id=generation_id,
            code_hash=code_hash,
            policy_fingerprint=policy_fingerprint,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
            allowed_capabilities=allowed_capabilities,
            policy=policy,
        )
        if not verification["valid"]:
            raise PermissionError(
                "worker authority packet rejected: "
                + ", ".join(str(item) for item in verification["failures"])
            )
        health = self.register(kind, pid)
        with self._lock:
            admitted = replace(
                health,
                authority_packet_id=packet.packet_id,
                authority_packet_expires_at=packet.expires_at,
            )
            self._workers[health.worker_id] = admitted
            return admitted

    def heartbeat(
        self,
        worker_id: UUID,
        *,
        state: WorkerState = WorkerState.HEALTHY,
        current_work_ids: tuple[UUID, ...] = (),
        queue_depth: int = 0,
        last_completed_sequence: int | None = None,
        supervisor_time: datetime | None = None,
    ) -> WorkerHealth:
        with self._lock:
            current = self._workers[worker_id]
            expired = (
                supervisor_time is not None
                and current.authority_packet_expires_at is not None
                and supervisor_time >= current.authority_packet_expires_at
            )
            updated = replace(
                current, last_heartbeat_at=datetime.now(timezone.utc), state=state,
                current_work_ids=current_work_ids, queue_depth=queue_depth,
                last_completed_sequence=last_completed_sequence,
            )
            if expired:
                updated = replace(
                    updated,
                    state=WorkerState.UNAUTHORIZED,
                    last_error_fingerprint="authority-expired",
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
                authority_packet_id=None,
                authority_packet_expires_at=None,
            )
            self._workers[worker_id] = updated
            return updated

    def unhealthy(self) -> tuple[WorkerHealth, ...]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.heartbeat_timeout_seconds)
        with self._lock:
            return tuple(
                item
                for item in self._workers.values()
                if item.last_heartbeat_at < cutoff
                or item.state in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}
            )

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

    def __init__(
        self,
        runtime: LoggingRuntime,
        *,
        application_pid: int | None = None,
        application_process_group_id: int | None = None,
        application_process=None,
    ) -> None:
        self.runtime = runtime
        self.application_pid = application_pid
        self.application_process_group_id = application_process_group_id
        self.application_process = application_process
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
            fields=self.worker_failure_envelope(worker),
        )

    @staticmethod
    def worker_failure_envelope(worker: WorkerHealth) -> dict[str, Any]:
        """Return bounded evidence needed to reconcile one failed worker."""
        return {
            "worker_id": str(worker.worker_id),
            "worker_kind": worker.worker_kind.name,
            "process_id": worker.process_id,
            "process_start_id": str(worker.process_start_id),
            "state": worker.state.name,
            "current_work_ids": [str(item) for item in worker.current_work_ids],
            "queue_depth": worker.queue_depth,
            "last_completed_sequence": worker.last_completed_sequence,
            "restart_count": worker.restart_count,
            "last_error_fingerprint": worker.last_error_fingerprint,
            "authority_packet_id": (
                str(worker.authority_packet_id)
                if worker.authority_packet_id is not None
                else None
            ),
            "authority_packet_expires_at": (
                worker.authority_packet_expires_at.isoformat()
                if worker.authority_packet_expires_at is not None
                else None
            ),
            "transaction_state": "ROLLED_BACK",
        }

    def handle_worker_failure(
        self,
        worker: WorkerHealth,
        *,
        policy: Any,
        create_incident: Callable[[Mapping[str, Any]], Any] | None = None,
        restart_worker: Callable[[WorkerHealth], Any] | None = None,
        disable_component: Callable[[WorkerHealth], Any] | None = None,
    ) -> dict[str, Any]:
        """Apply the policy boundary for one failed worker.

        The supervisor records failure evidence and chooses an action, but
        worker creation and component-specific shutdown remain callbacks owned
        by the application boundary. A callback must report success before the
        registry treats a worker as restarted.
        """
        envelope = self.worker_failure_envelope(worker)
        incident_error = None
        if create_incident is not None:
            try:
                create_incident(envelope)
                incident_status = "RECORDED"
            except Exception as exc:
                incident_status = "FAILED"
                incident_error = f"{type(exc).__name__}: {exc}"[:256]
        else:
            incident_status = "NOT_CONFIGURED"
        restart_policy = policy
        restart_requested = (
            bool(getattr(restart_policy, "enabled", False))
            and worker.restart_count < int(getattr(restart_policy, "maximum_restarts", 0))
        )
        restart_result: dict[str, Any] | None = None
        if restart_requested and restart_worker is not None:
            try:
                raw_result = restart_worker(worker)
                if isinstance(raw_result, Mapping):
                    restart_result = dict(raw_result)
                elif raw_result:
                    restart_result = {"started": True}
            except Exception as exc:
                restart_result = {
                    "started": False,
                    "error": f"{type(exc).__name__}: {exc}"[:256],
                }
            if restart_result and bool(restart_result.get("started")):
                restarted = self.workers.record_restart(
                    worker.worker_id,
                    pid=(
                        int(restart_result["pid"])
                        if restart_result.get("pid") is not None
                        else None
                    ),
                )
                return {
                    "ok": True,
                    "action": "RESTARTED",
                    "incident_status": incident_status,
                    "incident_error": incident_error,
                    "restart": {
                        "started": True,
                        "worker_id": str(restarted.worker_id),
                        "restart_count": restarted.restart_count,
                    },
                    "failure_envelope": envelope,
                }
        exhaustion = getattr(
            restart_policy,
            "exhaustion_action",
            WorkerFailureAction.DISABLE_COMPONENT,
        )
        if not isinstance(exhaustion, WorkerFailureAction):
            exhaustion = WorkerFailureAction[str(exhaustion).upper()]
        callback_result = None
        if exhaustion is WorkerFailureAction.DISABLE_COMPONENT and disable_component is not None:
            callback_result = disable_component(worker)
        elif exhaustion is WorkerFailureAction.STOP_APPLICATION:
            callback_result = self.stop_application()
        result = {
            "ok": True,
            "action": exhaustion.name,
            "incident_status": incident_status,
            "incident_error": incident_error,
            "restart": restart_result,
            "failure_envelope": envelope,
        }
        if callback_result is not None:
            result["action_result"] = callback_result
        self.runtime.event(
            logger_name="caretaker.watchdog",
            severity=50 if exhaustion is WorkerFailureAction.STOP_APPLICATION else 40,
            channel=__import__("caretaker.logging.models", fromlist=["LogChannel"]).LogChannel.CARETAKER_INTERNAL,
            message=f"Caretaker worker failure policy applied: {exhaustion.name}",
            fields={
                "worker_id": str(worker.worker_id),
                "action": exhaustion.name,
                "incident_status": incident_status,
                "transaction_state": "ROLLED_BACK",
            },
        )
        return result

    def monitor_application(self, *, interval_seconds: float = 1.0) -> None:
        while not self._stop.wait(interval_seconds):
            self.workers.heartbeat(self.supervisor_health.worker_id)
            if self.application_pid is not None and not _pid_alive(self.application_pid):
                self.stop()
                return

    def stop_application(
        self,
        *,
        graceful_signal: int = signal.SIGTERM,
        timeout_seconds: float = 10.0,
    ) -> dict[str, object]:
        """Stop the supervised application boundary and report the outcome.

        The launcher creates a dedicated session/process group for the
        application. Signalling that group keeps application descendants in
        Caretaker's application-scoped authority boundary without signalling
        the supervisor or unrelated same-UID processes.
        """
        if self.application_pid is None:
            return {"boundary": "none", "application_alive": False, "forced": False}

        process_group_id = self.application_process_group_id
        boundary = "process_group" if process_group_id is not None else "process"
        send = (
            (lambda sig: os.killpg(process_group_id, sig))
            if process_group_id is not None
            else (lambda sig: os.kill(self.application_pid, sig))
        )
        try:
            send(graceful_signal)
        except ProcessLookupError:
            return {
                "boundary": boundary,
                "process_group_id": process_group_id,
                "application_alive": False,
                "forced": False,
            }
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline and _boundary_alive(self.application_pid, process_group_id):
            if self.application_process is not None:
                self.application_process.poll()
            time.sleep(0.1)
        forced = _boundary_alive(self.application_pid, process_group_id)
        if forced:
            try:
                send(signal.SIGKILL)
            except ProcessLookupError:
                forced = False
            forced_deadline = time.monotonic() + min(max(timeout_seconds, 0.0), 1.0)
            while time.monotonic() < forced_deadline and _boundary_alive(self.application_pid, process_group_id):
                if self.application_process is not None:
                    self.application_process.poll()
                time.sleep(0.05)
        return {
            "boundary": boundary,
            "process_group_id": process_group_id,
            "application_alive": (
                self.application_process.poll() is None
                if self.application_process is not None
                else _pid_alive(self.application_pid)
            ),
            "boundary_alive": _boundary_alive(self.application_pid, process_group_id),
            "forced": forced,
        }

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


def _boundary_alive(pid: int, process_group_id: int | None) -> bool:
    if process_group_id is None:
        return _pid_alive(pid)
    try:
        os.killpg(process_group_id, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
