"""Application-runtime scheduling and health-monitoring primitives.

These primitives are owned by the application runtime. The logging package
re-exports them temporarily for compatibility with existing integrations, but
their implementation must not depend on the logging supervisor or runtime.
"""

from __future__ import annotations

import json
import math
import os
import signal
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID, uuid4

from .adaptive_aggregation import (
    QueueAdaptiveAggregationStore,
    SupervisorAdaptiveAggregationStore,
)
from .logging.acceptance import WorkerAcceptanceStore
from .logging.models import (
    ActiveWork,
    CaretakerComponent,
    EvidencePriority,
    WorkState,
    WorkerHealth,
    WorkerAcceptanceState,
    WorkerFailureAction,
    WorkerKind,
    WorkerState,
)
from .repair_recovery import (
    ComparisonWorkerAssignment,
    ComparisonWorkerComparisonReport,
    ComparisonWorkerReconciliationReport,
    ComparisonWorkerResult,
    RecoveryAuthorityPacket,
    RepairRecoveryPolicy,
    WorkerEvidenceJoinReport,
    WorkerAcceptancePolicy,
    WorkerReplacementRequest,
    compare_comparison_worker_result as compare_comparison_worker_result_evidence,
    create_comparison_worker_assignment,
    deserialize_recovery_authority_packet,
    deserialize_worker_replacement_request,
    create_worker_failure_record,
    create_worker_failure_recovery_record,
    dispatch_recovery_action,
    evaluate_worker_acceptance,
    join_worker_evidence_reconciliations as join_worker_evidence_reconciliations_evidence,
    reconcile_comparison_worker_reports as reconcile_comparison_worker_reports_evidence,
    reconcile_worker_failure_records,
    resolve_worker_failure_scope,
    select_recovery_action,
    serialize_recovery_authority_packet,
    serialize_worker_replacement_request,
    validate_worker_acceptance_policy,
    verify_comparison_worker_assignment,
    verify_comparison_worker_result,
    verify_recovery_authority_packet,
)
from .transport import APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES


MAX_ADAPTIVE_QUEUE_WORKERS = 128
MAX_WORKER_AUTHORITY_HANDOFFS = 4096
MAX_WORKER_FAILURE_COHORT = 128

# A supervisor owns application shutdown and cannot safely replace itself from
# inside its own failure callback. Other roles are replaceable only through the
# existing packet/identity admission path.
RESTARTABLE_WORKER_KINDS = frozenset({
    WorkerKind.WRITER,
    WorkerKind.EVENT_SERVER,
    WorkerKind.CONTROL_SERVER,
    WorkerKind.SYSTEM_COLLECTOR,
    WorkerKind.GUARD_ANALYZER,
    WorkerKind.REPAIR_ANALYZER,
    WorkerKind.INTERROGATION,
    WorkerKind.SIGNER,
})


class WorkRegistry:
    """Bounded in-memory registry for application-runtime work."""

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


class Watchdog:
    """Application-runtime health monitor with bounded callback delivery."""

    def __init__(
        self,
        registry: Any,
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
            unhealthy = self.registry.unhealthy()
            for worker in unhealthy:
                if worker.worker_id not in seen:
                    self.on_unhealthy(worker)
                    seen.add(worker.worker_id)
            healthy = {
                item.worker_id
                for item in self.registry.all()
                if item not in self.registry.unhealthy()
            }
            seen.intersection_update(set(item.worker_id for item in self.registry.all()) - healthy)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)


class AdaptiveAggregationQueueRegistry:
    """Own application-worker queue bindings used by supervisor cycles."""

    def __init__(
        self,
        *,
        worker_lookup: Callable[[UUID], WorkerHealth],
        maximum_workers: int = MAX_ADAPTIVE_QUEUE_WORKERS,
    ) -> None:
        self.worker_lookup = worker_lookup
        self.maximum_workers = maximum_workers
        self._queues: dict[UUID, QueueAdaptiveAggregationStore] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _parse_worker_id(worker_id: UUID | str) -> UUID:
        try:
            return worker_id if isinstance(worker_id, UUID) else UUID(str(worker_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("adaptive queue binding requires a valid worker ID") from exc

    def bind(
        self,
        worker_id: UUID | str,
        queue_store: QueueAdaptiveAggregationStore,
    ) -> dict[str, Any]:
        """Bind one application-owned queue to a live worker."""
        parsed_worker_id = self._parse_worker_id(worker_id)
        if not isinstance(queue_store, QueueAdaptiveAggregationStore):
            raise TypeError("adaptive queue binding requires a QueueAdaptiveAggregationStore")
        try:
            worker = self.worker_lookup(parsed_worker_id)
        except KeyError as exc:
            raise PermissionError("adaptive queue binding requires a registered worker") from exc
        if worker.state not in {WorkerState.STARTING, WorkerState.HEALTHY, WorkerState.DEGRADED}:
            raise PermissionError(
                "adaptive queue binding cannot target a failed or unauthorized worker"
            )
        with self._lock:
            existing = self._queues.get(parsed_worker_id)
            if existing is not None and existing is not queue_store:
                raise ValueError("adaptive queue is already bound; unbind it before replacement")
            self._queues[parsed_worker_id] = queue_store
        return {
            "bound": True,
            "authority_granted": False,
            "worker_id": str(worker.worker_id),
            "worker_pid": worker.process_id,
            "transport": "QUEUE",
        }

    def unbind(
        self,
        worker_id: UUID | str,
        *,
        queue_store: QueueAdaptiveAggregationStore | None = None,
    ) -> dict[str, Any]:
        """Remove a binding without draining or deleting its evidence."""
        parsed_worker_id = self._parse_worker_id(worker_id)
        if queue_store is not None and not isinstance(queue_store, QueueAdaptiveAggregationStore):
            raise TypeError("adaptive queue unbinding requires a QueueAdaptiveAggregationStore")
        with self._lock:
            existing = self._queues.get(parsed_worker_id)
            if existing is None:
                return {
                    "unbound": False,
                    "authority_granted": False,
                    "worker_id": str(parsed_worker_id),
                }
            if queue_store is not None and existing is not queue_store:
                raise ValueError("adaptive queue unbinding does not match its bound queue")
            self._queues.pop(parsed_worker_id)
        return {
            "unbound": True,
            "authority_granted": False,
            "worker_id": str(parsed_worker_id),
        }

    def snapshot(self) -> dict[UUID, QueueAdaptiveAggregationStore]:
        """Return a shallow snapshot for one bounded control cycle."""
        with self._lock:
            return dict(self._queues)

    def status(self) -> tuple[dict[str, Any], ...]:
        """Return a bounded read-only projection of queue bindings."""
        bindings = tuple(self.snapshot().items())[: self.maximum_workers]
        result: list[dict[str, Any]] = []
        for worker_id, queue_store in bindings:
            try:
                worker = self.worker_lookup(worker_id)
            except KeyError:
                continue
            result.append(
                {
                    "worker_id": str(worker_id),
                    "worker_pid": worker.process_id,
                    "worker_state": worker.state.name,
                    "queue": queue_store.status(),
                    "authority_granted": False,
                }
            )
        return tuple(result)


class WorkerRegistry:
    _TERMINAL_STATES = frozenset({WorkerState.FAILED, WorkerState.UNAUTHORIZED})

    def __init__(
        self,
        *,
        heartbeat_timeout_seconds: float = 15.0,
        acceptance_store: WorkerAcceptanceStore | None = None,
        audit_event: Callable[..., Any] | None = None,
        authority_verifier: Callable[..., Any] | None = None,
    ) -> None:
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self.acceptance_store = acceptance_store
        self.audit_event = audit_event
        self._authority_verifier = authority_verifier or verify_recovery_authority_packet
        self._workers: dict[UUID, WorkerHealth] = {}
        self._acceptance_policies: dict[UUID, WorkerAcceptancePolicy] = {}
        self._replacement_requests: set[UUID] = set()
        # Handoff IDs are transport transaction IDs.  They are intentionally
        # never evicted during a registry lifetime: evicting them would make a
        # previously accepted packet replayable.  The bound fails closed when
        # an application has not established a fresh supervisor lifecycle.
        self._authority_handoffs: set[UUID] = set()
        self._lock = threading.RLock()

    @classmethod
    def _next_state(cls, current: WorkerHealth, requested: WorkerState) -> WorkerState:
        """Apply the worker lifecycle rule without reviving terminal state."""
        if current.state in cls._TERMINAL_STATES:
            return current.state
        return requested

    def _emit_audit(self, event_type: str, **fields: Any) -> None:
        if self.audit_event is not None:
            self.audit_event(event_type, **fields)

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
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> WorkerHealth:
        """Admit a worker only after exact packet/context verification."""
        verification = self._authority_verifier(
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
        resolved_acceptance_policy = acceptance_policy
        if resolved_acceptance_policy is None and policy is not None:
            resolved_acceptance_policy = policy.worker_acceptance
        persisted = None
        if resolved_acceptance_policy is not None and self.acceptance_store is not None:
            persisted = self.acceptance_store.load(
                target_id=target_id,
                generation_id=generation_id,
                code_hash=code_hash,
                policy_fingerprint=policy_fingerprint,
            )
        successful = int(persisted["successful_executions"]) if persisted else 0
        failed = int(persisted["failed_executions"]) if persisted else 0
        with self._lock:
            acceptance_state = WorkerAcceptanceState.UNTRACKED
            lifecycle_state = WorkerState.STARTING
            lifecycle_error = None
            if resolved_acceptance_policy is not None:
                evaluation = evaluate_worker_acceptance(
                    target_id=target_id,
                    successful_executions=successful,
                    failed_executions=failed,
                    policy=resolved_acceptance_policy,
                )
                acceptance_state = (
                    WorkerAcceptanceState.FAILED
                    if evaluation["failed"]
                    else (
                        WorkerAcceptanceState.ACCEPTED
                        if evaluation["accepted"]
                        else WorkerAcceptanceState.PROBATION
                    )
                )
                if evaluation["failed"]:
                    lifecycle_state = WorkerState.FAILED
                    lifecycle_error = "worker-acceptance-failed"
            health = self.register(kind, pid)
            admitted = replace(
                health,
                authority_packet_id=packet.packet_id,
                authority_packet_expires_at=packet.expires_at,
                target_id=str(target_id),
                generation_id=str(generation_id),
                code_hash=str(code_hash),
                policy_fingerprint=str(policy_fingerprint),
                state=lifecycle_state,
                last_error_fingerprint=lifecycle_error,
                acceptance_state=acceptance_state,
                acceptance_successful_executions=successful,
                acceptance_failed_executions=failed,
            )
            self._workers[health.worker_id] = admitted
            if resolved_acceptance_policy is not None:
                self._acceptance_policies[health.worker_id] = resolved_acceptance_policy
        self._emit_audit(
            "WORKER_AUTHORITY_ISSUED",
            actor={"type": "supervisor"},
            scope={
                "worker_id": str(admitted.worker_id),
                "target_id": admitted.target_id,
            },
            policy={
                "fingerprint": admitted.policy_fingerprint,
                "authority_policy_generation": authority_policy_generation,
                "authority_policy_fingerprint": authority_policy_fingerprint,
            },
            outcome={"state": "ISSUED"},
            details={
                "authority_packet_id": str(packet.packet_id),
                "authority_packet_expires_at": packet.expires_at.isoformat(),
                "acceptance_state": admitted.acceptance_state.name,
            },
        )
        return admitted

    def refresh_authorized(
        self,
        worker_id: UUID,
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
        """Refresh a live worker's packet without re-admitting its process.

        Refresh only replaces the immutable authorization snapshot. It does
        not change the worker's identity, acceptance counters, or execution
        context. A worker that has failed, stopped, become unauthorized, or
        already reached packet expiry must re-enter through replacement
        admission instead.
        """
        with self._lock:
            current = self._workers[worker_id]
            if current.state in {
                WorkerState.FAILED,
                WorkerState.UNAUTHORIZED,
                WorkerState.STOPPING,
            }:
                raise PermissionError(
                    "worker packet refresh requires a live authorized worker"
                )
            if (
                current.authority_packet_id is None
                or current.authority_packet_expires_at is None
            ):
                raise PermissionError("worker has no authorized packet to refresh")
            observed_packet_id = current.authority_packet_id
            if supervisor_time >= current.authority_packet_expires_at:
                raise PermissionError(
                    "worker authority packet has expired; re-admission is required"
                )
            expected_context = {
                "target_id": str(target_id),
                "generation_id": str(generation_id),
                "code_hash": str(code_hash),
                "policy_fingerprint": str(policy_fingerprint),
            }
            for name, expected in expected_context.items():
                if getattr(current, name) != expected:
                    raise PermissionError(f"worker refresh context mismatch: {name}")

        verification = self._authority_verifier(
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
                "worker authority packet refresh rejected: "
                + ", ".join(str(item) for item in verification["failures"])
            )

        with self._lock:
            current = self._workers[worker_id]
            if current.state in {
                WorkerState.FAILED,
                WorkerState.UNAUTHORIZED,
                WorkerState.STOPPING,
            }:
                raise PermissionError(
                    "worker packet refresh requires a live authorized worker"
                )
            if (
                current.authority_packet_expires_at is None
                or supervisor_time >= current.authority_packet_expires_at
            ):
                raise PermissionError(
                    "worker authority packet has expired; re-admission is required"
                )
            if current.authority_packet_id != observed_packet_id:
                raise PermissionError(
                    "worker authority packet changed during refresh; retry"
                )
            updated = replace(
                current,
                authority_packet_id=packet.packet_id,
                authority_packet_expires_at=packet.expires_at,
            )
            self._workers[worker_id] = updated
        self._emit_audit(
            "WORKER_AUTHORITY_REFRESHED",
            actor={"type": "supervisor"},
            scope={
                "worker_id": str(updated.worker_id),
                "target_id": updated.target_id,
            },
            policy={
                "fingerprint": updated.policy_fingerprint,
                "authority_policy_generation": authority_policy_generation,
                "authority_policy_fingerprint": authority_policy_fingerprint,
            },
            outcome={"state": "REFRESHED"},
            details={
                "prior_authority_packet_id": str(observed_packet_id),
                "authority_packet_id": str(packet.packet_id),
                "authority_packet_expires_at": packet.expires_at.isoformat(),
            },
        )
        return updated

    @staticmethod
    def _parse_authority_handoff_id(handoff_id: str | UUID) -> UUID:
        try:
            parsed = handoff_id if isinstance(handoff_id, UUID) else UUID(str(handoff_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("worker authority handoff requires a valid handoff_id") from exc
        return parsed

    def register_transported_authorized(
        self,
        kind: WorkerKind,
        peer_pid: int,
        transport_value: Any,
        *,
        handoff_id: str | UUID,
        supervisor_time: datetime,
        target_id: str,
        generation_id: str,
        code_hash: str,
        policy_fingerprint: str,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        allowed_capabilities: set[str] | frozenset[str] = frozenset(),
        policy: RepairRecoveryPolicy | None = None,
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> WorkerHealth:
        """Admit a worker from a local transport with peer-PID binding.

        The transport envelope is decoded before admission, while the caller's
        authenticated Unix peer PID is the only process identity accepted. A
        handoff ID is consumed only after successful packet/context admission,
        so a valid handoff cannot be replayed to create a second worker.
        """
        if isinstance(peer_pid, bool) or not isinstance(peer_pid, int) or peer_pid <= 0:
            raise ValueError("worker authority handoff requires a positive peer PID")
        parsed_handoff = self._parse_authority_handoff_id(handoff_id)
        packet = deserialize_recovery_authority_packet(transport_value)
        with self._lock:
            if parsed_handoff in self._authority_handoffs:
                raise PermissionError("worker authority handoff has already been consumed")
            if len(self._authority_handoffs) >= MAX_WORKER_AUTHORITY_HANDOFFS:
                raise PermissionError("worker authority handoff capacity is exhausted")
            admitted = self.register_authorized(
                kind,
                peer_pid,
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
                acceptance_policy=acceptance_policy,
            )
            self._authority_handoffs.add(parsed_handoff)
        return admitted

    def refresh_transported_authorized(
        self,
        worker_id: UUID,
        peer_pid: int,
        transport_value: Any,
        *,
        handoff_id: str | UUID,
        process_start_id: str | UUID,
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
        """Refresh a packet over local transport for its registered process."""
        if isinstance(peer_pid, bool) or not isinstance(peer_pid, int) or peer_pid <= 0:
            raise ValueError("worker authority handoff requires a positive peer PID")
        parsed_handoff = self._parse_authority_handoff_id(handoff_id)
        packet = deserialize_recovery_authority_packet(transport_value)
        with self._lock:
            current = self._workers[worker_id]
            if current.process_id != peer_pid:
                raise PermissionError("worker process identity does not match its registration")
            if str(current.process_start_id) != str(process_start_id):
                raise PermissionError("worker process start identity does not match its registration")
            if parsed_handoff in self._authority_handoffs:
                raise PermissionError("worker authority handoff has already been consumed")
            if len(self._authority_handoffs) >= MAX_WORKER_AUTHORITY_HANDOFFS:
                raise PermissionError("worker authority handoff capacity is exhausted")
            updated = self.refresh_authorized(
                worker_id,
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
            self._authority_handoffs.add(parsed_handoff)
        return updated

    def prepare_replacement(
        self,
        worker_id: UUID,
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
        reason: str = "failed worker replacement",
    ) -> WorkerReplacementRequest:
        """Prepare a packet-verified replacement handoff for a failed worker."""
        with self._lock:
            failed = self._workers[worker_id]
            if failed.state not in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}:
                raise ValueError("worker replacement requires a failed or unauthorized worker")
        verification = self._authority_verifier(
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
                "worker replacement packet rejected: "
                + ", ".join(str(item) for item in verification["failures"])
            )
        return WorkerReplacementRequest(
            request_id=uuid4(),
            failed_worker_id=worker_id,
            worker_kind=failed.worker_kind.name,
            issued_at=supervisor_time,
            authority_packet=packet,
            reason=str(reason)[:256],
        )

    def register_replacement(
        self,
        request: WorkerReplacementRequest,
        kind: WorkerKind,
        pid: int,
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
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> WorkerHealth:
        """Admit a replacement only after packet and failed-worker checks."""
        if kind not in RESTARTABLE_WORKER_KINDS:
            raise PermissionError(f"worker role {kind.name} is not restartable")
        if request.worker_kind != kind.name:
            raise PermissionError("worker replacement kind does not match request")
        with self._lock:
            if request.request_id in self._replacement_requests:
                raise PermissionError("worker replacement request has already been consumed")
            failed = self._workers.get(request.failed_worker_id)
            if failed is None:
                raise PermissionError("worker replacement references an unknown worker")
            if failed.state not in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}:
                raise PermissionError("worker replacement source is no longer failed")
            replacement_restart_count = failed.restart_count + 1
            self._replacement_requests.add(request.request_id)
        try:
            admitted = self.register_authorized(
                kind,
                pid,
                request.authority_packet,
                supervisor_time=supervisor_time,
                target_id=target_id,
                generation_id=generation_id,
                code_hash=code_hash,
                policy_fingerprint=policy_fingerprint,
                authority_policy_generation=authority_policy_generation,
                authority_policy_fingerprint=authority_policy_fingerprint,
                allowed_capabilities=allowed_capabilities,
                policy=policy,
                acceptance_policy=acceptance_policy,
            )
        except Exception:
            with self._lock:
                self._replacement_requests.discard(request.request_id)
            raise
        with self._lock:
            replacement = replace(
                admitted,
                replaced_worker_id=request.failed_worker_id,
                restart_count=replacement_restart_count,
            )
            self._workers[replacement.worker_id] = replacement
            return replacement

    def register_transported_replacement(
        self,
        request: WorkerReplacementRequest | bytes | bytearray | str | Mapping[str, Any],
        peer_pid: int,
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
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> WorkerHealth:
        """Admit an application-started replacement from local transport.

        The replacement request's existing request ID is the replay key. The
        only process identity accepted is the authenticated transport peer;
        no PID supplied inside transport data is consulted.
        """
        if isinstance(peer_pid, bool) or not isinstance(peer_pid, int) or peer_pid <= 0:
            raise ValueError("worker replacement handoff requires a positive peer PID")
        if not isinstance(request, WorkerReplacementRequest):
            request = deserialize_worker_replacement_request(request)
        return self.register_replacement(
            request,
            WorkerKind[request.worker_kind],
            peer_pid,
            supervisor_time=supervisor_time,
            target_id=target_id,
            generation_id=generation_id,
            code_hash=code_hash,
            policy_fingerprint=policy_fingerprint,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
            allowed_capabilities=allowed_capabilities,
            policy=policy,
            acceptance_policy=acceptance_policy,
        )

    def record_acceptance_observation(
        self,
        worker_id: UUID,
        *,
        success: bool,
        policy: WorkerAcceptancePolicy | None = None,
        observation_id: str | UUID | None = None,
        observed_at: str | None = None,
    ) -> WorkerHealth:
        """Record exactly one authorized worker observation for acceptance."""
        if not isinstance(success, bool):
            raise TypeError("worker acceptance success must be a boolean")
        with self._lock:
            current = self._workers[worker_id]
            if current.target_id is None or current.acceptance_state is WorkerAcceptanceState.UNTRACKED:
                raise ValueError("worker acceptance is not configured for this worker")
            if current.state in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}:
                raise PermissionError("failed or unauthorized workers cannot advance acceptance")
            configured_policy = self._acceptance_policies.get(worker_id)
            if policy is None:
                policy = configured_policy
            elif configured_policy is not None and policy != configured_policy:
                raise PermissionError("worker acceptance policy does not match admission policy")
            if policy is None:
                raise ValueError("worker acceptance policy is not configured for this worker")
            validate_worker_acceptance_policy(policy)
            if self.acceptance_store is not None:
                if observation_id is None:
                    raise ValueError("observation_id is required for durable worker acceptance")
                if not all((current.generation_id, current.code_hash, current.policy_fingerprint)):
                    raise ValueError("worker acceptance context is unavailable for durable recording")
                persisted = self.acceptance_store.record(
                    observation_id=str(observation_id),
                    worker_id=str(worker_id),
                    target_id=current.target_id,
                    generation_id=current.generation_id,
                    code_hash=current.code_hash,
                    policy_fingerprint=current.policy_fingerprint,
                    success=success,
                    observed_at=observed_at,
                )
                successful = int(persisted["successful_executions"])
                failed = int(persisted["failed_executions"])
            else:
                successful = current.acceptance_successful_executions + (1 if success else 0)
                failed = current.acceptance_failed_executions + (0 if success else 1)
            evaluation = evaluate_worker_acceptance(
                target_id=current.target_id,
                successful_executions=successful,
                failed_executions=failed,
                policy=policy,
            )
            acceptance_failed = bool(evaluation["failed"])
            acceptance_state = (
                WorkerAcceptanceState.FAILED
                if acceptance_failed
                else (
                    WorkerAcceptanceState.ACCEPTED
                    if evaluation["accepted"]
                    else WorkerAcceptanceState.PROBATION
                )
            )
            updated = replace(
                current,
                state=self._next_state(
                    current,
                    WorkerState.FAILED if acceptance_failed else current.state,
                ),
                last_error_fingerprint=(
                    "worker-acceptance-failed"
                    if acceptance_failed
                    else current.last_error_fingerprint
                ),
                acceptance_state=acceptance_state,
                acceptance_successful_executions=successful,
                acceptance_failed_executions=failed,
            )
            self._workers[worker_id] = updated
            return updated

    def heartbeat(
        self,
        worker_id: UUID,
        *,
        state: WorkerState = WorkerState.HEALTHY,
        current_work_ids: tuple[UUID, ...] = (),
        queue_depth: int = 0,
        last_completed_sequence: int | None = None,
        diagnostic_context: Mapping[str, Any] | None = None,
        supervisor_time: datetime | None = None,
    ) -> WorkerHealth:
        authority_expired = False
        with self._lock:
            current = self._workers[worker_id]
            expired = (
                supervisor_time is not None
                and current.authority_packet_expires_at is not None
                and supervisor_time >= current.authority_packet_expires_at
            )
            updated = replace(
                current,
                last_heartbeat_at=datetime.now(timezone.utc),
                state=self._next_state(current, state),
                current_work_ids=current_work_ids, queue_depth=queue_depth,
                last_completed_sequence=last_completed_sequence,
                diagnostic_context=(
                    current.diagnostic_context
                    if diagnostic_context is None
                    else dict(diagnostic_context)
                ),
            )
            if expired and current.state not in self._TERMINAL_STATES:
                authority_expired = True
            if expired and current.state not in self._TERMINAL_STATES:
                updated = replace(
                    updated,
                    state=WorkerState.UNAUTHORIZED,
                    last_error_fingerprint="authority-expired",
                )
            self._workers[worker_id] = updated
        if authority_expired:
            self._emit_audit(
                "WORKER_AUTHORITY_EXPIRED",
                actor={"type": "supervisor"},
                scope={
                    "worker_id": str(updated.worker_id),
                    "target_id": updated.target_id,
                },
                policy={"fingerprint": updated.policy_fingerprint},
                outcome={"state": "EXPIRED"},
                details={
                    "authority_packet_id": (
                        str(current.authority_packet_id)
                        if current.authority_packet_id is not None
                        else None
                    ),
                    "authority_packet_expires_at": (
                        current.authority_packet_expires_at.isoformat()
                        if current.authority_packet_expires_at is not None
                        else None
                    ),
                },
            )
        return updated

    def reconcile_authority_expiry(
        self,
        supervisor_time: datetime,
    ) -> tuple[WorkerHealth, ...]:
        """Mark packet-bearing workers unauthorized after supervisor time expiry.

        A worker may be silent, so expiry cannot depend on receiving another
        heartbeat. This method is an explicit supervisor-cycle operation and
        is idempotent: an already unauthorized or failed worker is not
        rewritten and does not emit a duplicate expiry event.
        """
        if supervisor_time.tzinfo is None or supervisor_time.utcoffset() is None:
            raise ValueError("supervisor time must be timezone-aware")
        expired: list[tuple[WorkerHealth, WorkerHealth]] = []
        with self._lock:
            for worker_id, current in self._workers.items():
                if (
                    current.authority_packet_expires_at is None
                    or supervisor_time < current.authority_packet_expires_at
                    or current.state
                    in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}
                ):
                    continue
                updated = replace(
                    current,
                    state=WorkerState.UNAUTHORIZED,
                    last_error_fingerprint="authority-expired",
                )
                self._workers[worker_id] = updated
                expired.append((current, updated))
        for previous, updated in expired:
            self._emit_audit(
                "WORKER_AUTHORITY_EXPIRED",
                actor={"type": "supervisor"},
                scope={
                    "worker_id": str(updated.worker_id),
                    "target_id": updated.target_id,
                },
                policy={"fingerprint": updated.policy_fingerprint},
                outcome={"state": "EXPIRED"},
                details={
                    "authority_packet_id": (
                        str(previous.authority_packet_id)
                        if previous.authority_packet_id is not None
                        else None
                    ),
                    "authority_packet_expires_at": (
                        previous.authority_packet_expires_at.isoformat()
                        if previous.authority_packet_expires_at is not None
                        else None
                    ),
                },
            )
        return tuple(item[1] for item in expired)

    def mark_failed(
        self,
        worker_id: UUID,
        *,
        error_fingerprint: str | None = None,
        diagnostic_context: Mapping[str, Any] | None = None,
    ) -> WorkerHealth:
        with self._lock:
            current = self._workers[worker_id]
            updated = replace(
                current,
                state=self._next_state(current, WorkerState.FAILED),
                last_heartbeat_at=datetime.now(timezone.utc),
                last_error_fingerprint=(
                    error_fingerprint
                    if error_fingerprint is not None
                    else current.last_error_fingerprint
                ),
                diagnostic_context=(
                    current.diagnostic_context
                    if diagnostic_context is None
                    else dict(diagnostic_context)
                ),
            )
            self._workers[worker_id] = updated
            return updated

    def record_restart(self, worker_id: UUID, *, pid: int | None = None) -> WorkerHealth:
        with self._lock:
            current = self._workers[worker_id]
            if current.worker_kind not in RESTARTABLE_WORKER_KINDS:
                raise PermissionError(
                    f"worker role {current.worker_kind.name} is not restartable"
                )
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
                target_id=None,
                generation_id=None,
                code_hash=None,
                policy_fingerprint=None,
                acceptance_state=WorkerAcceptanceState.UNTRACKED,
                acceptance_successful_executions=0,
                acceptance_failed_executions=0,
            )
            self._workers[worker_id] = updated
            self._acceptance_policies.pop(worker_id, None)
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

    def get(self, worker_id: UUID) -> WorkerHealth:
        with self._lock:
            return self._workers[worker_id]

class ApplicationWorkerLifecycle:
    """Connect application-owned process callbacks to worker admission.

    Caretaker remains the controller and verifier: ``spawn_worker`` creates a
    process in the embedding application, while this adapter admits it only
    after packet verification. The callback receives a
    ``RecoveryAuthorityPacket`` for an initial worker and a
    ``WorkerReplacementRequest`` for a replacement. Caretaker never creates
    or terminates an operating-system process.
    """

    def __init__(
        self,
        supervisor: CaretakerApplicationSupervisor,
        *,
        spawn_worker: Callable[[RecoveryAuthorityPacket | WorkerReplacementRequest], Any],
        stop_worker: Callable[[int], Any] | None = None,
    ) -> None:
        if not callable(spawn_worker):
            raise TypeError("worker lifecycle requires a spawn_worker callback")
        if stop_worker is not None and not callable(stop_worker):
            raise TypeError("worker lifecycle stop_worker must be callable")
        self.supervisor = supervisor
        self.spawn_worker = spawn_worker
        self.stop_worker = stop_worker

    def _cleanup_started_process(self, pid: int) -> dict[str, Any]:
        if self.stop_worker is None:
            return {
                "status": "REQUIRED",
                "accepted": False,
                "reason": "application-owned process cleanup callback is not configured",
            }
        try:
            result = self.stop_worker(pid)
        except Exception as exc:
            return {
                "status": "FAILED",
                "accepted": False,
                "reason": f"{type(exc).__name__}: {exc}"[:256],
            }
        accepted = bool(
            result
            if not isinstance(result, Mapping)
            else result.get("accepted") or result.get("stopped")
        )
        return {
            "status": "STOPPED" if accepted else "REJECTED",
            "accepted": accepted,
            "result": dict(result) if isinstance(result, Mapping) else result,
        }

    def start_authorized_worker(
        self,
        kind: WorkerKind,
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
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> dict[str, Any]:
        """Start and admit one worker, cleaning up an unadmitted process."""
        try:
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
        except Exception as exc:
            return {
                "accepted": False,
                "authority_granted": False,
                "status": "AUTHORITY_PACKET_REJECTED",
                "reason": f"{type(exc).__name__}: {exc}"[:256],
            }
        if not verification.get("valid"):
            return {
                "accepted": False,
                "authority_granted": False,
                "status": "AUTHORITY_PACKET_REJECTED",
                "reason": "; ".join(str(item) for item in verification.get("failures", ()))[:256],
            }

        pid: int | None = None
        try:
            started = self.spawn_worker(packet)
            if not isinstance(started, Mapping) or not bool(started.get("started")):
                return {
                    "accepted": False,
                    "authority_granted": False,
                    "status": "PROCESS_NOT_STARTED",
                    "reason": "application did not start worker",
                }
            candidate_pid = started.get("pid")
            if isinstance(candidate_pid, bool) or not isinstance(candidate_pid, int) or candidate_pid <= 0:
                return {
                    "accepted": False,
                    "authority_granted": False,
                    "status": "PROCESS_ID_INVALID",
                    "reason": "application did not return a valid worker pid",
                }
            pid = candidate_pid
            worker = self.supervisor.workers.register_authorized(
                kind,
                pid,
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
                acceptance_policy=acceptance_policy,
            )
        except Exception as exc:
            result = {
                "accepted": False,
                "authority_granted": False,
                "status": "ADMISSION_FAILED",
                "reason": f"{type(exc).__name__}: {exc}"[:256],
            }
            if pid is not None:
                result["process_cleanup"] = self._cleanup_started_process(pid)
            return result

        allowed_acceptance_states = {
            WorkerAcceptanceState.PROBATION,
            WorkerAcceptanceState.ACCEPTED,
        }
        if policy is None and acceptance_policy is None:
            allowed_acceptance_states.add(WorkerAcceptanceState.UNTRACKED)
        if worker.acceptance_state not in allowed_acceptance_states:
            return {
                "accepted": False,
                "authority_granted": False,
                "status": "ACCEPTANCE_FAILED",
                "worker_id": str(worker.worker_id),
                "acceptance_state": worker.acceptance_state.name,
                "process_cleanup": self._cleanup_started_process(pid),
            }
        return {
            "accepted": True,
            "authority_granted": False,
            "status": "ADMITTED",
            "worker_id": str(worker.worker_id),
            "pid": pid,
            "process_start_id": str(worker.process_start_id),
            "authority_packet_id": str(packet.packet_id),
            "authority_packet_verified": True,
            "authority_packet_expires_at": packet.expires_at.isoformat(),
            "acceptance_state": worker.acceptance_state.name,
        }

    def build_replacement_handler(
        self,
        *,
        failed_worker_id: UUID,
        packet: RecoveryAuthorityPacket,
        supervisor_time: datetime,
        target_id: str,
        generation_id: str,
        code_hash: str,
        policy_fingerprint: str,
        authority_policy_generation: str,
        authority_policy_fingerprint: str,
        allowed_capabilities: set[str] | frozenset[str] = frozenset(),
        policy: RepairRecoveryPolicy | None = None,
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        """Build a replacement handler using the same lifecycle callbacks."""
        return self.supervisor.build_replacement_action_handler(
            failed_worker_id=failed_worker_id,
            packet=packet,
            supervisor_time=supervisor_time,
            target_id=target_id,
            generation_id=generation_id,
            code_hash=code_hash,
            policy_fingerprint=policy_fingerprint,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
            spawn_worker=self.spawn_worker,
            stop_worker=self.stop_worker,
            allowed_capabilities=allowed_capabilities,
            policy=policy,
            acceptance_policy=acceptance_policy,
        )

    def build_recovery_handlers(
        self,
        *,
        create_incident: Callable[[Mapping[str, Any]], Any] | None = None,
        replace_worker: Callable[[Mapping[str, Any]], Any] | None = None,
        rollback_to_deployed_code: Callable[[Mapping[str, Any]], Any] | None = None,
        continue_degraded: Callable[[Mapping[str, Any]], Any] | None = None,
        stop_application: Callable[[Mapping[str, Any]], Any] | None = None,
        use_supervisor_shutdown: bool = False,
    ) -> dict[str, Callable[[Mapping[str, Any]], Any]]:
        """Assemble explicitly configured application recovery handlers.

        This is a wiring convenience for ``reconcile_worker_failures`` and
        ``handle_worker_failure_cohort``.  Every supplied callback remains
        application-owned and must return the acknowledgement required by the
        recovery dispatcher.  In particular, ``replace_worker`` should be the
        result of ``build_replacement_handler()`` so packet and acceptance
        gates are preserved; this method never creates a packet or process.

        A shutdown handler is omitted unless the application supplies one or
        explicitly opts into the supervisor's application-boundary shutdown
        adapter.  Unconfigured policy actions therefore remain visible as
        unconfigured instead of acquiring an implicit side effect.
        """
        callbacks = {
            "GENERATE_INCIDENT": create_incident,
            "REPLACE_WORKER": replace_worker,
            "ROLLBACK_TO_DEPLOYED_CODE": rollback_to_deployed_code,
            "CONTINUE_DEGRADED": continue_degraded,
        }
        handlers: dict[str, Callable[[Mapping[str, Any]], Any]] = {}
        if create_incident is not None:
            handlers["GENERATE_INCIDENT"] = self.supervisor.build_incident_action_handler(
                create_incident
            )
        for action, callback in callbacks.items():
            if action == "GENERATE_INCIDENT" or callback is None:
                continue
            if not callable(callback):
                raise TypeError(f"{action} recovery handler must be callable")
            handlers[action] = callback
        if stop_application is not None:
            handlers["STOP_APPLICATION"] = self.supervisor.build_shutdown_action_handler(
                stop_application
            )
        elif use_supervisor_shutdown:
            handlers["STOP_APPLICATION"] = self.supervisor.build_shutdown_action_handler()
        return handlers

    def build_failure_recovery_callback(
        self,
        *,
        scope: str | Callable[[tuple[WorkerHealth, ...]], str],
        recovery_policy: RepairRecoveryPolicy,
        recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
        require_complete_postmortem: bool = False,
        minimum_sample_count: int = 30,
        z_threshold: float = 3.0,
    ) -> Callable[[tuple[WorkerHealth, ...]], dict[str, Any]]:
        """Build a cohort callback for ordinary worker-failure recovery.

        The embedding application supplies the workers that belong to one
        continuous transaction.  The callback only delegates to the
        supervisor's evidence, reconciliation, and policy-action gates; it
        does not infer a scope from target identity or create replacement
        authority.
        """
        if not isinstance(recovery_policy, RepairRecoveryPolicy):
            raise TypeError("failure recovery callback requires a RepairRecoveryPolicy")
        if not isinstance(scope, str) and not callable(scope):
            raise TypeError("failure recovery scope must be a string or callable")

        def callback(workers: tuple[WorkerHealth, ...]) -> dict[str, Any]:
            supplied = tuple(workers)
            resolved_scope = scope(supplied) if callable(scope) else scope
            return self.supervisor.handle_worker_failure_cohort(
                supplied,
                scope=resolved_scope,
                recovery_policy=recovery_policy,
                recovery_handlers=recovery_handlers,
                diagnostic_debug=diagnostic_debug,
                critical_evidence=critical_evidence,
                collect_postmortem=collect_postmortem,
                require_complete_postmortem=require_complete_postmortem,
                minimum_sample_count=minimum_sample_count,
                z_threshold=z_threshold,
            )

        return callback

    def build_expiry_recovery_callback(
        self,
        *,
        scope: str | Callable[[tuple[WorkerHealth, ...], datetime], str],
        recovery_policy: RepairRecoveryPolicy,
        recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
        require_complete_postmortem: bool = False,
        minimum_sample_count: int = 30,
        z_threshold: float = 3.0,
    ) -> Callable[[tuple[WorkerHealth, ...], datetime], dict[str, Any]]:
        """Build a control-cycle callback for policy-selected expiry recovery.

        The application chooses the reconciliation scope and supplies any
        handlers that can create an incident, replace a worker, continue in a
        degraded mode, roll back, or stop the application.  The returned
        callback only invokes the supervisor's validation and evidence gates;
        it never creates a process or supplies missing authority.
        """
        if not isinstance(recovery_policy, RepairRecoveryPolicy):
            raise TypeError("expiry recovery callback requires a RepairRecoveryPolicy")
        if not isinstance(scope, str) and not callable(scope):
            raise TypeError("expiry recovery scope must be a string or callable")

        def callback(
            workers: tuple[WorkerHealth, ...],
            supervisor_time: datetime,
        ) -> dict[str, Any]:
            resolved_scope = (
                scope(workers, supervisor_time)
                if callable(scope)
                else scope
            )
            return self.supervisor.handle_expired_worker_cohort(
                workers,
                supervisor_time=supervisor_time,
                scope=resolved_scope,
                recovery_policy=recovery_policy,
                recovery_handlers=recovery_handlers,
                diagnostic_debug=diagnostic_debug,
                critical_evidence=critical_evidence,
                collect_postmortem=collect_postmortem,
                require_complete_postmortem=require_complete_postmortem,
                minimum_sample_count=minimum_sample_count,
                z_threshold=z_threshold,
            )

        return callback


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def reconcile_adaptive_aggregation_queues(
    supervisor: Any,
    queues: Mapping[UUID | str, QueueAdaptiveAggregationStore] | None = None,
    *,
    aggregation_store: SupervisorAdaptiveAggregationStore,
    current_generations: Mapping[str, str],
    policy_fingerprint: str | None = None,
    policy_fingerprints: Mapping[str, str] | None = None,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    maximum_batches_per_worker: int = 32,
    maximum_total_batches: int = APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES,
    promotion_policies: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Drain application-owned adaptive queues during one control cycle.

    Each queue is bound to one registered worker.  The queue map may be
    supplied for a single call, or omitted to use bindings registered with
    ``bind_adaptive_aggregation_queue``.  The supervisor derives
    the worker PID from that registration and passes it to
    ``QueueAdaptiveAggregationStore.drain_to``; worker IDs and PIDs inside
    queue batches are never trusted.  The application supplies current
    generation, policy, and authority context, which is required before
    the single-writer ledger can reconcile the drained evidence.

    Queue drain failures are returned as bounded per-worker evidence while
    other queues and already-pending ledger batches still receive their
    reconciliation attempt.  No queue failure falls back to a local
    worker-owned ledger and this operation never grants authority.
    """
    if not isinstance(aggregation_store, SupervisorAdaptiveAggregationStore):
        raise TypeError(
            "adaptive queue reconciliation requires a supervisor aggregation store"
        )
    if queues is None:
        queues = supervisor._adaptive_aggregation_queue_registry.snapshot()
    if not isinstance(queues, Mapping) or not queues:
        raise ValueError("adaptive queue reconciliation requires at least one worker queue")
    if len(queues) > MAX_ADAPTIVE_QUEUE_WORKERS:
        raise ValueError(
            "adaptive queue reconciliation cannot exceed "
            f"{MAX_ADAPTIVE_QUEUE_WORKERS} worker queues"
        )
    if (
        isinstance(maximum_batches_per_worker, bool)
        or not isinstance(maximum_batches_per_worker, int)
        or not 1 <= maximum_batches_per_worker <= APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES
    ):
        raise ValueError(
            "maximum_batches_per_worker must be between 1 and "
            f"{APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES}"
        )
    if (
        isinstance(maximum_total_batches, bool)
        or not isinstance(maximum_total_batches, int)
        or not 1 <= maximum_total_batches <= APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES
    ):
        raise ValueError(
            "maximum_total_batches must be between 1 and "
            f"{APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES}"
        )
    if not isinstance(current_generations, Mapping) or not current_generations:
        raise ValueError("adaptive queue reconciliation requires current generations")
    if policy_fingerprint is not None and policy_fingerprints is not None:
        raise ValueError(
            "adaptive queue reconciliation accepts policy_fingerprint or policy_fingerprints, not both"
        )

    worker_results: list[dict[str, Any]] = []
    seen_worker_ids: set[UUID] = set()
    remaining = maximum_total_batches
    for raw_worker_id, queue_store in queues.items():
        try:
            worker_id = raw_worker_id if isinstance(raw_worker_id, UUID) else UUID(str(raw_worker_id))
        except (TypeError, ValueError) as exc:
            raise ValueError("adaptive queue map contains an invalid worker ID") from exc
        if worker_id in seen_worker_ids:
            raise ValueError("adaptive queue map contains a duplicate worker ID")
        seen_worker_ids.add(worker_id)
        if not isinstance(queue_store, QueueAdaptiveAggregationStore):
            raise TypeError(
                "adaptive queue map values must be QueueAdaptiveAggregationStore instances"
            )
        try:
            worker = supervisor.workers.get(worker_id)
        except KeyError as exc:
            raise PermissionError(
                "adaptive queue is not bound to a registered worker"
            ) from exc
        if worker.state not in {
            WorkerState.STARTING,
            WorkerState.HEALTHY,
            WorkerState.DEGRADED,
        }:
            raise PermissionError(
                "adaptive queue cannot be drained for a failed or unauthorized worker"
            )
        if (
            isinstance(worker.process_id, bool)
            or not isinstance(worker.process_id, int)
            or worker.process_id <= 0
        ):
            raise PermissionError("adaptive queue worker has no valid registered process identity")
        if remaining <= 0:
            worker_results.append(
                {
                    "worker_id": str(worker.worker_id),
                    "status": "DEFERRED",
                    "drained": 0,
                    "reason": "control-cycle batch bound reached",
                }
            )
            continue
        try:
            drained = queue_store.drain_to(
                aggregation_store,
                limit=min(maximum_batches_per_worker, remaining),
                worker_id=str(worker.worker_id),
                worker_pid=worker.process_id,
            )
            drained_count = len(drained)
            remaining -= drained_count
            worker_results.append(
                {
                    "worker_id": str(worker.worker_id),
                    "worker_pid": worker.process_id,
                    "status": "DRAINED",
                    "drained": drained_count,
                    "submissions": list(drained),
                }
            )
        except Exception as exc:
            worker_results.append(
                {
                    "worker_id": str(worker.worker_id),
                    "worker_pid": worker.process_id,
                    "status": "FAILED",
                    "drained": 0,
                    "error": f"{type(exc).__name__}: {exc}"[:256],
                }
            )

    reconciliation = aggregation_store.reconcile(
        current_generations=current_generations,
        policy_fingerprint=policy_fingerprint,
        policy_fingerprints=policy_fingerprints,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        maximum_batches=maximum_total_batches,
    )
    promotions = None
    if promotion_policies is not None:
        promotions = aggregation_store.evaluate_promotions(
            current_generations=current_generations,
            policy_fingerprint=policy_fingerprint,
            policy_fingerprints=policy_fingerprints,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
            promotion_policies=promotion_policies,
            maximum=maximum_total_batches,
        )
    failed_workers = sum(item["status"] == "FAILED" for item in worker_results)
    result: dict[str, Any] = {
        "ok": failed_workers == 0 and not reconciliation.get("errors"),
        "authority_granted": False,
        "worker_count": len(worker_results),
        "drained": sum(int(item.get("drained", 0)) for item in worker_results),
        "workers": worker_results,
        "reconciliation": reconciliation,
    }
    if promotions is not None:
        result["promotions"] = promotions
    return result


def run_supervisor_control_cycle(
    supervisor: Any,
    *,
    supervisor_time: datetime | None = None,
    on_expired_workers: Callable[[tuple[WorkerHealth, ...], datetime], Any] | None = None,
    on_cycle: Callable[[datetime], Any] | None = None,
) -> dict[str, Any]:
    """Run one bounded supervisor cycle and application-owned hooks.

    The supervisor first reconciles authority expiry and refreshes its own
    heartbeat. If workers became unauthorized, ``on_expired_workers`` is
    then given their immutable health snapshots and the authoritative cycle
    timestamp so the embedding application can deliberately replace or
    otherwise reconcile them. ``on_cycle`` is invoked afterward with the
    same timestamp. Neither callback receives or creates authority from
    this method. Callback failures are returned as bounded evidence so the
    embedding application can apply its own policy without silently
    treating the cycle as successful.
    """
    if on_expired_workers is not None and not callable(on_expired_workers):
        raise TypeError("expired-worker control-cycle callback must be callable")
    if on_cycle is not None and not callable(on_cycle):
        raise TypeError("supervisor control-cycle callback must be callable")
    now = supervisor_time or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("supervisor control-cycle time must be timezone-aware")
    expired = supervisor.workers.reconcile_authority_expiry(now)
    supervisor.workers.heartbeat(
        supervisor.supervisor_health.worker_id,
        supervisor_time=now,
    )
    expiry_callback: dict[str, Any] = {
        "status": "NOT_NEEDED" if not expired else "NOT_CONFIGURED",
        "authority_granted": False,
    }
    result: dict[str, Any] = {
        "ok": True,
        "authority_granted": False,
        "supervisor_time": now.isoformat(),
        "expired_worker_ids": [str(worker.worker_id) for worker in expired],
        "expired_workers": [
            {
                "worker_id": str(worker.worker_id),
                "worker_kind": worker.worker_kind.name,
                "process_id": worker.process_id,
                "target_id": worker.target_id,
                "generation_id": worker.generation_id,
                "code_hash": worker.code_hash,
                "policy_fingerprint": worker.policy_fingerprint,
                "state": worker.state.name,
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
            }
            for worker in expired
        ],
        "authority_expiry_callback": expiry_callback,
        "cycle_callback": {"status": "NOT_CONFIGURED"},
        "application_alive": (
            _pid_alive(supervisor.application_pid)
            if supervisor.application_pid is not None
            else None
        ),
    }
    if on_expired_workers is not None and expired:
        try:
            callback_result = on_expired_workers(expired, now)
        except Exception as exc:
            result["ok"] = False
            result["authority_expiry_callback"] = {
                "status": "FAILED",
                "error": f"{type(exc).__name__}: {exc}"[:256],
                "worker_count": len(expired),
                "authority_granted": False,
            }
        else:
            result["authority_expiry_callback"] = {
                "status": "COMPLETED",
                "result": callback_result,
                "worker_count": len(expired),
                "authority_granted": False,
            }
    if on_cycle is not None:
        try:
            callback_result = on_cycle(now)
        except Exception as exc:
            result["ok"] = False
            result["cycle_callback"] = {
                "status": "FAILED",
                "error": f"{type(exc).__name__}: {exc}"[:256],
                "authority_granted": False,
            }
        else:
            result["cycle_callback"] = {
                "status": "COMPLETED",
                "result": callback_result,
                "authority_granted": False,
            }
    return result


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

def monitor_application(
    supervisor: Any,
    *,
    interval_seconds: float = 1.0,
    on_expired_workers: Callable[[tuple[WorkerHealth, ...], datetime], Any] | None = None,
    on_cycle: Callable[[datetime], Any] | None = None,
) -> None:
    """Monitor the application and invoke optional cycle callbacks."""
    while not supervisor._stop.wait(interval_seconds):
        cycle = supervisor.run_control_cycle(
            on_expired_workers=on_expired_workers,
            on_cycle=on_cycle,
        )
        if cycle["application_alive"] is False:
            supervisor.stop()
            return

def stop_application(
    supervisor: Any,
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
    if supervisor.application_pid is None:
        return {"boundary": "none", "application_alive": False, "forced": False}

    process_group_id = supervisor.application_process_group_id
    boundary = "process_group" if process_group_id is not None else "process"
    send = (
        (lambda sig: os.killpg(process_group_id, sig))
        if process_group_id is not None
        else (lambda sig: os.kill(supervisor.application_pid, sig))
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
    while time.monotonic() < deadline and _boundary_alive(supervisor.application_pid, process_group_id):
        if supervisor.application_process is not None:
            supervisor.application_process.poll()
        time.sleep(0.1)
    forced = _boundary_alive(supervisor.application_pid, process_group_id)
    if forced:
        try:
            send(signal.SIGKILL)
        except ProcessLookupError:
            forced = False
        forced_deadline = time.monotonic() + min(max(timeout_seconds, 0.0), 1.0)
        while time.monotonic() < forced_deadline and _boundary_alive(supervisor.application_pid, process_group_id):
            if supervisor.application_process is not None:
                supervisor.application_process.poll()
            time.sleep(0.05)
    return {
        "boundary": boundary,
        "process_group_id": process_group_id,
        "application_alive": (
            supervisor.application_process.poll() is None
            if supervisor.application_process is not None
            else _pid_alive(supervisor.application_pid)
        ),
        "boundary_alive": _boundary_alive(supervisor.application_pid, process_group_id),
        "forced": forced,
    }

def stop_runtime_supervisor(supervisor: Any) -> None:
    supervisor._stop.set()
    supervisor.watchdog.stop()
    supervisor._audit_event(
        "SUPERVISOR_STATE_CHANGED",
        actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
        scope={"worker_id": str(supervisor.supervisor_health.worker_id)},
        outcome={"state": "STOPPED"},
        details={"application_pid": supervisor.application_pid},
    )
    supervisor.runtime.close()
def diagnostic_debug_enabled() -> bool:
    """Return whether controlled diagnostic detail is explicitly enabled."""
    return os.environ.get("CARETAKER_DIAGNOSTIC_DEBUG", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def bounded_diagnostic_value(value: Any, *, depth: int = 0) -> Any:
    """Keep worker-supplied diagnostic context finite and JSON-shaped."""
    if depth >= 4:
        return "<depth-limit>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: bounded_diagnostic_value(
                item, depth=depth + 1
            )
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            bounded_diagnostic_value(
                item, depth=depth + 1
            )
            for item in list(value)[:64]
        ]
    return str(value)[:512]

@staticmethod

def worker_failure_envelope(
    worker: WorkerHealth,
    *,
    diagnostic_debug: bool | None = None,
) -> dict[str, Any]:
    """Return bounded evidence needed to reconcile one failed worker.

    Standard envelopes retain worker identity, queue counters, active work
    IDs, authority context, and the failure fingerprint. The explicit
    ``CARETAKER_DIAGNOSTIC_DEBUG`` setting (or the argument used by tests
    and embedding applications) additionally includes worker-supplied
    milestone, partial-queue, and policy-state context. Diagnostic detail
    is evidence only and cannot authorize recovery.
    """
    include_diagnostic = (
        diagnostic_debug_enabled()
        if diagnostic_debug is None
        else diagnostic_debug
    )
    envelope = {
        "detail_level": "DIAGNOSTIC" if include_diagnostic else "STANDARD",
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
        "target_id": worker.target_id,
        "acceptance_state": worker.acceptance_state.name,
        "acceptance_successful_executions": worker.acceptance_successful_executions,
        "acceptance_failed_executions": worker.acceptance_failed_executions,
        "generation_id": worker.generation_id,
        "code_hash": worker.code_hash,
        "policy_fingerprint": worker.policy_fingerprint,
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
        "replaced_worker_id": (
            str(worker.replaced_worker_id)
            if worker.replaced_worker_id is not None
            else None
        ),
        "transaction_state": "ROLLED_BACK",
    }
    if include_diagnostic:
        envelope["diagnostic_context"] = (
            bounded_diagnostic_value(
                worker.diagnostic_context
            )
        )
    return envelope


def capture_worker_failure_evidence_internal(
    supervisor: Any,
    worker: WorkerHealth,
    *,
    diagnostic_debug: bool | None = None,
    critical_evidence: bool = False,
    collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
    require_complete_postmortem: bool = False,
    reconciliation_scope: str | None = None,
) -> tuple[dict[str, Any], Any | None, dict[str, Any]]:
    """Capture and durably store one failed worker before any action."""
    if worker.state not in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}:
        raise ValueError("worker failure evidence requires a failed or unauthorized worker")
    envelope = supervisor.worker_failure_envelope(
        worker,
        diagnostic_debug=diagnostic_debug,
    )
    supervisor._audit_event(
        "WORKER_FAILED",
        actor={"type": "worker", "id": str(worker.worker_id)},
        scope={
            "worker_id": str(worker.worker_id),
            "target_id": worker.target_id,
        },
        policy={
            "fingerprint": worker.policy_fingerprint,
            "authority_packet_id": envelope.get("authority_packet_id"),
        },
        outcome={
            "state": "ROLLED_BACK",
            "reason": envelope.get("last_error_fingerprint") or "worker_failure",
        },
        details={
            "worker_kind": worker.worker_kind.name,
            "detail_level": envelope.get("detail_level"),
        },
    )
    postmortem_evidence: Mapping[str, Any] | None = None
    postmortem_error: str | None = None
    if collect_postmortem is not None:
        try:
            collected = collect_postmortem(worker, envelope)
            if isinstance(collected, Mapping):
                postmortem_evidence = collected
            else:
                postmortem_error = "post-mortem callback must return an evidence mapping"
        except Exception as exc:
            postmortem_error = (
                f"post-mortem callback failed: {type(exc).__name__}: {exc}"
            )[:256]
    postmortem_status = (
        "INCOMPLETE"
        if critical_evidence and require_complete_postmortem
        else (
            "INVALID"
            if postmortem_error
            else (
                "COLLECTED"
                if postmortem_evidence is not None
                else "NOT_REQUESTED"
            )
        )
    )
    failure_record = None
    failure_persistence_error = None
    if supervisor.failure_store is not None:
        try:
            failure_record = create_worker_failure_record(
                envelope,
                critical_evidence=critical_evidence,
                postmortem_evidence=postmortem_evidence,
                postmortem_error=postmortem_error,
                require_complete_postmortem=require_complete_postmortem,
                scope=reconciliation_scope,
            )
            supervisor.failure_store.record_worker_failure(failure_record)
            failure_persistence_status = "PERSISTED"
            postmortem_status = failure_record.postmortem_status
        except Exception as exc:
            failure_persistence_status = "FAILED"
            failure_persistence_error = f"{type(exc).__name__}: {exc}"[:256]
    else:
        failure_persistence_status = "NOT_CONFIGURED"
    return envelope, failure_record, {
        "failure_persistence_status": failure_persistence_status,
        "failure_persistence_error": failure_persistence_error,
        "postmortem_status": postmortem_status,
        "postmortem_error": postmortem_error,
        "reconciliation_scope": (
            failure_record.reconciliation_scope
            if failure_record is not None
            else reconciliation_scope
        ),
    }

def capture_worker_failure_evidence(
    supervisor: Any,
    worker: WorkerHealth,
    *,
    diagnostic_debug: bool | None = None,
    critical_evidence: bool = False,
    collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
    require_complete_postmortem: bool = False,
    reconciliation_scope: str | None = None,
) -> dict[str, Any]:
    """Persist one rollback envelope without selecting a recovery action.

    This is the evidence half of coordinated failure handling. It is safe
    to call for every worker in one transaction before invoking
    ``reconcile_worker_failures``; it never creates authority or starts a
    replacement process.
    """
    envelope, failure_record, metadata = capture_worker_failure_evidence_internal(
        supervisor,
        worker,
        diagnostic_debug=diagnostic_debug,
        critical_evidence=critical_evidence,
        collect_postmortem=collect_postmortem,
        require_complete_postmortem=require_complete_postmortem,
        reconciliation_scope=reconciliation_scope,
    )
    return {
        "ok": failure_record is not None,
        "worker_id": str(worker.worker_id),
        "failure_id": str(failure_record.failure_id) if failure_record else None,
        "failure_envelope": envelope,
        "authority_granted": False,
        **metadata,
    }


def build_incident_action_handler(
    create_incident: Callable[[Mapping[str, Any]], Any],
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    """Build an application-owned incident action adapter.

    Incident persistence is owned by the embedding application. The
    callback receives the complete recovery decision, including its
    policy action and bounded recovery evidence, and must return a
    mapping with ``accepted=True`` and a durable ``incident_id``. A
    non-mapping result is converted to an explicit rejection so the
    recovery dispatcher cannot mistake a callback that returned
    ``None`` for a successfully created incident.
    """
    if not callable(create_incident):
        raise TypeError("create_incident must be callable")

    def handler(decision: Mapping[str, Any]) -> dict[str, Any]:
        try:
            result = create_incident(decision)
        except Exception as exc:
            return {
                "accepted": False,
                "reason": f"incident callback failed: {type(exc).__name__}: {exc}"[:256],
            }
        if not isinstance(result, Mapping):
            return {
                "accepted": False,
                "reason": "incident callback must return an acknowledgement mapping",
            }
        return dict(result)

    return handler

def build_shutdown_action_handler(
    supervisor: Any,
    stop_application_callback: Callable[[Mapping[str, Any]], Any] | None = None,
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    """Build an application-boundary shutdown action adapter.

    By default this wraps the supervisor's application process-group
    shutdown implementation. An embedding application may provide a
    callback instead; it must accept the complete recovery decision and
    return a mapping with ``accepted=True`` and
    ``shutdown_requested=True``. The latter is an explicit application
    acknowledgement, not a Caretaker authority grant.
    """
    if stop_application_callback is not None and not callable(stop_application_callback):
        raise TypeError("stop_application must be callable")

    def handler(decision: Mapping[str, Any]) -> dict[str, Any]:
        try:
            if stop_application_callback is None:
                raw_result = stop_application(supervisor)
                if not isinstance(raw_result, Mapping):
                    return {
                        "accepted": False,
                        "reason": "supervisor shutdown did not return an acknowledgement mapping",
                    }
                result = dict(raw_result)
                if result.get("boundary") == "none":
                    result["accepted"] = False
                    result["reason"] = "no application boundary is configured"
                    return result
                boundary_alive = bool(
                    result.get("boundary_alive", result.get("application_alive", True))
                )
                result["shutdown_requested"] = not boundary_alive
                result["accepted"] = bool(result["shutdown_requested"])
                if not result["accepted"]:
                    result["reason"] = "application boundary remains alive after shutdown request"
                return result
            result = stop_application_callback(decision)
        except Exception as exc:
            return {
                "accepted": False,
                "reason": f"shutdown callback failed: {type(exc).__name__}: {exc}"[:256],
            }
        if not isinstance(result, Mapping):
            return {
                "accepted": False,
                "reason": "shutdown callback must return an acknowledgement mapping",
            }
        return dict(result)

    return handler


def handle_worker_acceptance_observation(
    supervisor: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
) -> dict[str, Any]:
    """Accept one observation from the registered worker process only."""
    try:
        worker_id = UUID(str(request["worker_id"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("worker acceptance observation requires a valid worker_id") from exc
    worker = supervisor.workers.get(worker_id)
    if worker.process_id != credentials[0]:
        raise PermissionError("worker process identity does not match its registration")
    if str(request.get("process_start_id") or "") != str(worker.process_start_id):
        raise PermissionError("worker process start identity does not match its registration")
    if str(request.get("authority_packet_id") or "") != str(worker.authority_packet_id or ""):
        raise PermissionError("worker authority packet identity does not match its registration")
    success = request.get("success")
    if not isinstance(success, bool):
        raise ValueError("worker acceptance observation success must be a boolean")
    observation_id = str(request.get("observation_id") or "")
    if not observation_id or len(observation_id) > 256:
        raise ValueError("worker acceptance observation requires a 1..256 observation_id")
    updated = supervisor.workers.record_acceptance_observation(
        worker_id,
        success=success,
        policy=None,
        observation_id=observation_id,
        observed_at=(str(request["observed_at"]) if request.get("observed_at") else None),
    )
    return {
        "ok": True,
        "worker_id": str(updated.worker_id),
        "target_id": updated.target_id,
        "state": updated.state.name,
        "acceptance_state": updated.acceptance_state.name,
        "acceptance_successful_executions": updated.acceptance_successful_executions,
        "acceptance_failed_executions": updated.acceptance_failed_executions,
        "authority_granted": False,
    }

def handle_worker_authority_packet(
    supervisor: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    *,
    allowed_worker_kinds: set[WorkerKind] | frozenset[WorkerKind],
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    acceptance_policy: WorkerAcceptancePolicy | None = None,
) -> dict[str, Any]:
    """Admit or refresh a worker packet received on the local control socket.

    The application supplies the current context through this method's
    keyword arguments.  Request fields are transport data only; in
    particular, a worker cannot choose its PID, policy context, or allowed
    worker kind.  ``ControlSocketServer`` supplies authenticated peer
    credentials to this handler.
    """
    if request.get("command") != "worker-authority-packet":
        raise ValueError("unsupported worker authority packet command")
    try:
        kind = WorkerKind[str(request["worker_kind"]).upper()]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("worker authority packet requires a valid worker_kind") from exc
    if kind not in allowed_worker_kinds:
        raise PermissionError("worker authority packet kind is not permitted")
    operation = request.get("operation")
    if operation not in {"register", "refresh"}:
        raise ValueError("worker authority packet operation must be register or refresh")
    handoff_id = request.get("handoff_id")
    if not isinstance(handoff_id, str) or not handoff_id.strip():
        raise ValueError("worker authority packet requires a handoff_id")
    transport_value = request.get("packet")
    if not isinstance(transport_value, Mapping):
        raise ValueError("worker authority packet requires a JSON transport envelope")
    if operation == "register":
        worker = supervisor.workers.register_transported_authorized(
            kind,
            credentials[0],
            transport_value,
            handoff_id=handoff_id,
            supervisor_time=supervisor_time,
            target_id=target_id,
            generation_id=generation_id,
            code_hash=code_hash,
            policy_fingerprint=policy_fingerprint,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
            allowed_capabilities=allowed_capabilities,
            policy=policy,
            acceptance_policy=acceptance_policy,
        )
    else:
        try:
            worker_id = UUID(str(request["worker_id"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("worker authority refresh requires a valid worker_id") from exc
        process_start_id = request.get("process_start_id")
        if not isinstance(process_start_id, str) or not process_start_id.strip():
            raise ValueError("worker authority refresh requires process_start_id")
        worker = supervisor.workers.refresh_transported_authorized(
            worker_id,
            credentials[0],
            transport_value,
            handoff_id=handoff_id,
            process_start_id=process_start_id,
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
    return {
        "ok": True,
        "operation": operation,
        "worker_id": str(worker.worker_id),
        "process_id": worker.process_id,
        "process_start_id": str(worker.process_start_id),
        "worker_kind": worker.worker_kind.name,
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
        "state": worker.state.name,
        "acceptance_state": worker.acceptance_state.name,
        "authority_granted": False,
    }

def handle_worker_authority_queue_handoff(
    supervisor: Any,
    handoff: Mapping[str, Any],
    *,
    authoritative_worker_pid: int,
    allowed_worker_kinds: set[WorkerKind] | frozenset[WorkerKind],
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    acceptance_policy: WorkerAcceptancePolicy | None = None,
) -> dict[str, Any]:
    """Admit a typed queue handoff using application-owned identity.

    ``QueueWorkerAuthorityPacketTransport.receive()`` returns evidence
    decoded from an application-owned queue.  Queue access and its sender
    PID are not authentication, so the embedding application must bind
    the handoff to a live worker and provide that worker's authoritative
    PID here.  The packet and handoff replay gates remain the same as the
    local control-socket path.
    """
    if not isinstance(handoff, Mapping):
        raise TypeError("worker authority queue handoff must be a mapping")
    operation = handoff.get("operation")
    if operation not in {"register", "refresh"}:
        raise ValueError("worker authority queue handoff operation is invalid")
    expected_fields = {
        "operation",
        "handoff_id",
        "worker_kind",
        "packet",
        "transport_message_id",
        "transport_sender_pid",
    }
    if operation == "refresh":
        expected_fields.update({"worker_id", "process_start_id"})
    if set(handoff) != expected_fields:
        raise ValueError("worker authority queue handoff fields are invalid")
    if (
        isinstance(authoritative_worker_pid, bool)
        or not isinstance(authoritative_worker_pid, int)
        or authoritative_worker_pid <= 0
    ):
        raise ValueError("worker authority queue handoff requires a positive authoritative worker PID")
    worker_kind = handoff.get("worker_kind")
    if not isinstance(worker_kind, str) or not worker_kind.strip():
        raise ValueError("worker authority queue handoff worker_kind is invalid")
    packet = handoff.get("packet")
    if not isinstance(packet, RecoveryAuthorityPacket):
        raise ValueError("worker authority queue handoff packet is invalid")
    try:
        transport_value = json.loads(
            serialize_recovery_authority_packet(packet).decode("utf-8")
        )
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("worker authority queue handoff packet is invalid") from exc
    request: dict[str, Any] = {
        "command": "worker-authority-packet",
        "operation": operation,
        "handoff_id": handoff.get("handoff_id"),
        "worker_kind": worker_kind.strip(),
        "packet": transport_value,
    }
    if operation == "refresh":
        request["worker_id"] = handoff.get("worker_id")
        request["process_start_id"] = handoff.get("process_start_id")
    result = handle_worker_authority_packet(
        supervisor,
        request,
        (authoritative_worker_pid, 0, 0),
        allowed_worker_kinds=allowed_worker_kinds,
        supervisor_time=supervisor_time,
        target_id=target_id,
        generation_id=generation_id,
        code_hash=code_hash,
        policy_fingerprint=policy_fingerprint,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        allowed_capabilities=allowed_capabilities,
        policy=policy,
        acceptance_policy=acceptance_policy,
    )
    result["transport_message_id"] = handoff["transport_message_id"]
    result["transport_sender_pid"] = handoff["transport_sender_pid"]
    result["authoritative_worker_pid"] = authoritative_worker_pid
    return result

def handle_worker_replacement_packet(
    supervisor: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    *,
    allowed_worker_kinds: set[WorkerKind] | frozenset[WorkerKind],
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    acceptance_policy: WorkerAcceptancePolicy | None = None,
) -> dict[str, Any]:
    """Admit an application-started replacement over local transport.

    The replacement request is a supervisor-issued, single-use handoff.
    The application still starts the process; this handler only binds the
    authenticated peer PID and performs the existing replacement gates.
    """
    if request.get("command") != "worker-replacement-packet":
        raise ValueError("unsupported worker replacement command")
    transport_value = request.get("replacement")
    if not isinstance(transport_value, Mapping):
        raise ValueError("worker replacement requires a JSON transport envelope")
    replacement_request = deserialize_worker_replacement_request(transport_value)
    try:
        kind = WorkerKind[replacement_request.worker_kind]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("worker replacement request has an invalid worker kind") from exc
    if kind not in allowed_worker_kinds:
        raise PermissionError("worker replacement kind is not permitted")
    replacement = supervisor.workers.register_transported_replacement(
        replacement_request,
        credentials[0],
        supervisor_time=supervisor_time,
        target_id=target_id,
        generation_id=generation_id,
        code_hash=code_hash,
        policy_fingerprint=policy_fingerprint,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        allowed_capabilities=allowed_capabilities,
        policy=policy,
        acceptance_policy=acceptance_policy,
    )
    return {
        "ok": True,
        "operation": "replacement",
        "worker_id": str(replacement.worker_id),
        "process_id": replacement.process_id,
        "process_start_id": str(replacement.process_start_id),
        "worker_kind": replacement.worker_kind.name,
        "replaced_worker_id": (
            str(replacement.replaced_worker_id)
            if replacement.replaced_worker_id is not None
            else None
        ),
        "authority_packet_id": (
            str(replacement.authority_packet_id)
            if replacement.authority_packet_id is not None
            else None
        ),
        "authority_packet_expires_at": (
            replacement.authority_packet_expires_at.isoformat()
            if replacement.authority_packet_expires_at is not None
            else None
        ),
        "state": replacement.state.name,
        "acceptance_state": replacement.acceptance_state.name,
        "authority_granted": False,
    }

def handle_worker_replacement_queue_handoff(
    supervisor: Any,
    handoff: Mapping[str, Any],
    *,
    authoritative_worker_pid: int,
    allowed_worker_kinds: set[WorkerKind] | frozenset[WorkerKind],
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    acceptance_policy: WorkerAcceptancePolicy | None = None,
) -> dict[str, Any]:
    """Admit a typed replacement queue handoff with bound process identity.

    The application supplies the live replacement PID after associating it
    with its queue binding.  The queue-reported sender PID is retained as
    provenance only and is never used as the worker identity.
    """
    if not isinstance(handoff, Mapping):
        raise TypeError("worker replacement queue handoff must be a mapping")
    if set(handoff) != {
        "request",
        "transport_message_id",
        "transport_sender_pid",
    }:
        raise ValueError("worker replacement queue handoff fields are invalid")
    if (
        isinstance(authoritative_worker_pid, bool)
        or not isinstance(authoritative_worker_pid, int)
        or authoritative_worker_pid <= 0
    ):
        raise ValueError("worker replacement queue handoff requires a positive authoritative worker PID")
    request_value = handoff.get("request")
    if not isinstance(request_value, WorkerReplacementRequest):
        raise ValueError("worker replacement queue handoff request is invalid")
    try:
        transport_value = json.loads(
            serialize_worker_replacement_request(request_value).decode("utf-8")
        )
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("worker replacement queue handoff request is invalid") from exc
    result = handle_worker_replacement_packet(
        supervisor,
        {
            "command": "worker-replacement-packet",
            "replacement": transport_value,
        },
        (authoritative_worker_pid, 0, 0),
        allowed_worker_kinds=allowed_worker_kinds,
        supervisor_time=supervisor_time,
        target_id=target_id,
        generation_id=generation_id,
        code_hash=code_hash,
        policy_fingerprint=policy_fingerprint,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        allowed_capabilities=allowed_capabilities,
        policy=policy,
        acceptance_policy=acceptance_policy,
    )
    result["transport_message_id"] = handoff["transport_message_id"]
    result["transport_sender_pid"] = handoff["transport_sender_pid"]
    result["authoritative_worker_pid"] = authoritative_worker_pid
    return result


def issue_comparison_worker_assignment(
    supervisor: Any,
    packet: RecoveryAuthorityPacket,
    *,
    scope: str,
    evidence_refs: tuple[str, ...] = (),
    supervisor_time: datetime,
    worker_kind: str = "REPAIR_ANALYZER",
    policy: RepairRecoveryPolicy | None = None,
    store: Any | None = None,
) -> ComparisonWorkerAssignment:
    """Issue and optionally persist a bounded independent evidence task.

    The embedding application still owns worker creation and transport.
    This method only binds the task to an existing supervisor-issued
    packet and records its provenance; the assignment cannot grant
    capabilities or advance policy state.
    """

    assignment = create_comparison_worker_assignment(
        packet,
        scope=scope,
        evidence_refs=evidence_refs,
        supervisor_time=supervisor_time,
        worker_kind=worker_kind,
        policy=policy,
    )
    target_store = store if store is not None else supervisor.failure_store
    persisted = False
    if target_store is not None:
        recorder = getattr(target_store, "record_comparison_worker_assignment", None)
        if not callable(recorder):
            raise TypeError(
                "comparison assignment store does not support assignments"
            )
        recorder(assignment)
        persisted = True
    supervisor._audit_event(
        "WORKER_COMPARISON_ASSIGNMENT",
        actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
        scope={
            "assignment_id": str(assignment.assignment_id),
            "target_id": assignment.target_id,
            "reconciliation_scope": assignment.scope,
        },
        policy={
            "fingerprint": assignment.policy_fingerprint,
            "authority_policy_generation": assignment.authority_policy_generation,
            "authority_policy_fingerprint": assignment.authority_policy_fingerprint,
        },
        outcome={"state": "ISSUED", "authority_granted": False},
        details={
            "authority_packet_id": str(assignment.authority_packet_id),
            "expires_at": assignment.expires_at.isoformat(),
            "worker_kind": assignment.worker_kind,
            "evidence_ref_count": len(assignment.evidence_refs),
            "persisted": persisted,
        },
    )
    return assignment

def accept_comparison_worker_result(
    supervisor: Any,
    assignment: ComparisonWorkerAssignment | Mapping[str, Any],
    packet: RecoveryAuthorityPacket,
    result: ComparisonWorkerResult | Mapping[str, Any],
    *,
    supervisor_time: datetime,
    worker_process_id: int,
    worker_process_start_id: UUID | str,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    store: Any | None = None,
) -> dict[str, Any]:
    """Accept a result only from the registered, packet-bound worker.

    Result acceptance is evidence persistence only. It does not mark the
    worker accepted, modify policy, authorize a repair, or select a
    recovery action.
    """

    result_worker_id = (
        result.get("worker_id")
        if isinstance(result, Mapping)
        else result.worker_id
    )
    try:
        worker_id = UUID(str(result_worker_id))
    except (TypeError, ValueError) as exc:
        raise PermissionError("comparison result worker identity is invalid") from exc
    worker = supervisor.workers.get(worker_id)
    if worker_process_id != worker.process_id:
        raise PermissionError("comparison result process identity does not match worker")
    if str(worker_process_start_id) != str(worker.process_start_id):
        raise PermissionError("comparison result process start identity does not match worker")
    if worker.state in {
        WorkerState.FAILED,
        WorkerState.UNAUTHORIZED,
        WorkerState.STOPPING,
    }:
        raise PermissionError("failed or unauthorized worker cannot submit comparison evidence")
    assignment_worker_kind = (
        assignment.get("worker_kind")
        if isinstance(assignment, Mapping)
        else assignment.worker_kind
    )
    if worker.worker_kind.name != str(assignment_worker_kind):
        raise PermissionError("comparison result worker kind does not match assignment")
    assignment_target = (
        assignment.get("target_id")
        if isinstance(assignment, Mapping)
        else assignment.target_id
    )
    for name, expected in (
        ("target_id", assignment_target),
        ("generation_id", assignment.get("generation_id") if isinstance(assignment, Mapping) else assignment.generation_id),
        ("code_hash", assignment.get("code_hash") if isinstance(assignment, Mapping) else assignment.code_hash),
        ("policy_fingerprint", assignment.get("policy_fingerprint") if isinstance(assignment, Mapping) else assignment.policy_fingerprint),
    ):
        if getattr(worker, name, None) != str(expected):
            raise PermissionError(f"comparison result worker context does not match assignment: {name}")
    packet_id = packet.packet_id
    if worker.authority_packet_id != packet_id:
        raise PermissionError("comparison result worker packet does not match assignment packet")
    assignment_check = verify_comparison_worker_assignment(
        assignment,
        packet,
        supervisor_time=supervisor_time,
        target_id=str(assignment_target),
        generation_id=str(assignment.get("generation_id") if isinstance(assignment, Mapping) else assignment.generation_id),
        code_hash=str(assignment.get("code_hash") if isinstance(assignment, Mapping) else assignment.code_hash),
        policy_fingerprint=str(assignment.get("policy_fingerprint") if isinstance(assignment, Mapping) else assignment.policy_fingerprint),
        authority_policy_generation=str(assignment.get("authority_policy_generation") if isinstance(assignment, Mapping) else assignment.authority_policy_generation),
        authority_policy_fingerprint=str(assignment.get("authority_policy_fingerprint") if isinstance(assignment, Mapping) else assignment.authority_policy_fingerprint),
        allowed_capabilities=allowed_capabilities,
        policy=policy,
    )
    result_check = verify_comparison_worker_result(
        result,
        assignment=assignment,
        worker_id=str(worker_id),
        supervisor_time=supervisor_time,
        policy=policy,
    )
    if not assignment_check["valid"]:
        raise PermissionError(
            "comparison assignment verification failed: "
            + ", ".join(str(item) for item in assignment_check["failures"])
        )
    if not result_check["valid"]:
        raise ValueError(
            "comparison result verification failed: "
            + ", ".join(str(item) for item in result_check["failures"])
        )
    target_store = store if store is not None else supervisor.failure_store
    persisted = False
    if target_store is not None:
        recorder = getattr(target_store, "record_comparison_worker_result", None)
        if not callable(recorder):
            raise TypeError("comparison result store does not support results")
        if not isinstance(result, ComparisonWorkerResult):
            raise TypeError("persisting a mapping result requires a ComparisonWorkerResult")
        recorder(result)
        persisted = True
    supervisor._audit_event(
        "WORKER_COMPARISON_RESULT",
        actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
        scope={
            "assignment_id": str(
                assignment.get("assignment_id")
                if isinstance(assignment, Mapping)
                else assignment.assignment_id
            ),
            "worker_id": str(worker_id),
            "target_id": str(assignment_target),
        },
        policy={"fingerprint": str(
            assignment.get("policy_fingerprint")
            if isinstance(assignment, Mapping)
            else assignment.policy_fingerprint
        )},
        outcome={"state": "ACCEPTED", "authority_granted": False},
        details={
            "result_id": result_check["result_id"],
            "status": result_check["status"],
            "content_sha256": (
                result.get("content_sha256")
                if isinstance(result, Mapping)
                else result.content_sha256
            ),
            "persisted": persisted,
        },
    )
    return {
        "accepted": True,
        "authority_granted": False,
        "assignment_id": assignment_check["assignment_id"],
        "result_id": result_check["result_id"],
        "worker_id": str(worker_id),
        "status": result_check["status"],
        "persisted": persisted,
    }

def compare_comparison_worker_result(
    supervisor: Any,
    assignment: ComparisonWorkerAssignment | Mapping[str, Any],
    result: ComparisonWorkerResult | Mapping[str, Any],
    *,
    baseline_signatures: tuple[Mapping[str, Any], ...] = (),
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
    compared_at: datetime | None = None,
    store: Any | None = None,
) -> ComparisonWorkerComparisonReport:
    """Compare independent evidence and persist the read-only report."""

    report = compare_comparison_worker_result_evidence(
        result,
        assignment=assignment,
        baseline_signatures=baseline_signatures,
        minimum_sample_count=minimum_sample_count,
        z_threshold=z_threshold,
        compared_at=compared_at,
    )
    target_store = store if store is not None else supervisor.failure_store
    persisted = False
    if target_store is not None:
        recorder = getattr(target_store, "record_comparison_worker_comparison", None)
        if not callable(recorder):
            raise TypeError("comparison report store does not support reports")
        recorder(report)
        persisted = True
    supervisor._audit_event(
        "WORKER_COMPARISON_RECONCILED",
        actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
        scope={
            "assignment_id": str(report.assignment_id),
            "result_id": str(report.result_id),
            "reconciliation_scope": report.scope,
        },
        outcome={"state": report.status, "authority_granted": False},
        details={
            "comparison_id": str(report.comparison_id),
            "baseline_count": report.baseline_count,
            "source_count": len(report.source_ids),
            "outlier_count": len(report.outliers),
            "persisted": persisted,
        },
    )
    return report

def reconcile_comparison_worker_reports(
    supervisor: Any,
    reports: tuple[ComparisonWorkerComparisonReport | Mapping[str, Any], ...],
    *,
    assignment_contexts: tuple[
        ComparisonWorkerAssignment | Mapping[str, Any], ...
    ] = (),
    reconciled_at: datetime | None = None,
    store: Any | None = None,
) -> ComparisonWorkerReconciliationReport:
    """Consolidate independent comparison reports as evidence only."""

    report = reconcile_comparison_worker_reports_evidence(
        reports,
        assignment_contexts=assignment_contexts,
        reconciled_at=reconciled_at,
    )
    target_store = store if store is not None else supervisor.failure_store
    persisted = False
    if target_store is not None:
        recorder = getattr(
            target_store, "record_comparison_worker_reconciliation", None
        )
        if not callable(recorder):
            raise TypeError(
                "comparison reconciliation store does not support reports"
            )
        recorder(report)
        persisted = True
    supervisor._audit_event(
        "WORKER_COMPARISON_RECONCILED",
        actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
        scope={"reconciliation_scope": report.scope},
        outcome={"state": report.status, "authority_granted": False},
        details={
            "reconciliation_id": str(report.reconciliation_id),
            "report_count": report.report_count,
            "unique_report_count": report.unique_report_count,
            "conflict_report_count": report.conflict_report_count,
            "incomplete_report_count": report.incomplete_report_count,
            "persisted": persisted,
        },
    )
    return report

def join_worker_evidence_reconciliations(
    supervisor: Any,
    postmortem_reconciliation: Mapping[str, Any],
    comparison_reconciliation: ComparisonWorkerReconciliationReport | Mapping[str, Any],
    *,
    assignment_contexts: tuple[
        ComparisonWorkerAssignment | Mapping[str, Any], ...
    ] = (),
    joined_at: datetime | None = None,
    store: Any | None = None,
) -> WorkerEvidenceJoinReport:
    """Link post-mortem and comparison evidence without granting authority."""

    report = join_worker_evidence_reconciliations_evidence(
        postmortem_reconciliation,
        comparison_reconciliation,
        assignment_contexts=assignment_contexts,
        joined_at=joined_at,
    )
    target_store = store if store is not None else supervisor.failure_store
    persisted = False
    if target_store is not None:
        recorder = getattr(target_store, "record_worker_evidence_join", None)
        if not callable(recorder):
            raise TypeError("evidence join store does not support joins")
        recorder(report)
        persisted = True
    supervisor._audit_event(
        "WORKER_COMPARISON_RECONCILED",
        actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
        scope={"reconciliation_scope": report.scope},
        outcome={"state": report.status, "authority_granted": False},
        details={
            "join_id": str(report.join_id),
            "postmortem_status": report.postmortem_status,
            "comparison_status": report.comparison_status,
            "postmortem_conflict": report.postmortem_conflict,
            "comparison_conflict": report.comparison_conflict,
            "persisted": persisted,
        },
    )
    return report


def build_replacement_action_handler(
    supervisor: Any,
    *,
    failed_worker_id: UUID,
    packet: RecoveryAuthorityPacket,
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    spawn_worker: Callable[[WorkerReplacementRequest], Any],
    stop_worker: Callable[[int], Any] | None = None,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    acceptance_policy: WorkerAcceptancePolicy | None = None,
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    """Build a recovery handler backed by packet-verified admission.

    The application owns ``spawn_worker``. Caretaker never starts an OS
    process here; it only admits the returned process through the existing
    packet, expiry, context, and acceptance checks.
    """
    def cleanup_started_process(pid: int) -> dict[str, Any]:
        if stop_worker is None:
            return {
                "status": "REQUIRED",
                "accepted": False,
                "reason": "application-owned process cleanup callback is not configured",
            }
        try:
            result = stop_worker(pid)
        except Exception as exc:
            return {
                "status": "FAILED",
                "accepted": False,
                "reason": f"{type(exc).__name__}: {exc}"[:256],
            }
        accepted = bool(
            result
            if not isinstance(result, Mapping)
            else result.get("accepted") or result.get("stopped")
        )
        return {
            "status": "STOPPED" if accepted else "REJECTED",
            "accepted": accepted,
            "result": dict(result) if isinstance(result, Mapping) else result,
        }

    def handler(decision: Mapping[str, Any]) -> dict[str, Any]:
        if decision.get("target_id") not in {None, target_id}:
            return {
                "accepted": False,
                "reason": "recovery target does not match replacement context",
            }
        started_pid: int | None = None
        try:
            request = supervisor.workers.prepare_replacement(
                failed_worker_id,
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
            started = spawn_worker(request)
            if not isinstance(started, Mapping) or not bool(started.get("started")):
                return {
                    "accepted": False,
                    "reason": "application did not start replacement worker",
                }
            pid = started.get("pid")
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                return {
                    "accepted": False,
                    "reason": "replacement worker callback did not return a valid pid",
                }
            started_pid = pid
            replacement = supervisor.workers.register_replacement(
                request,
                WorkerKind[request.worker_kind],
                pid,
                supervisor_time=supervisor_time,
                target_id=target_id,
                generation_id=generation_id,
                code_hash=code_hash,
                policy_fingerprint=policy_fingerprint,
                authority_policy_generation=authority_policy_generation,
                authority_policy_fingerprint=authority_policy_fingerprint,
                allowed_capabilities=allowed_capabilities,
                policy=policy,
                acceptance_policy=acceptance_policy,
            )
        except Exception as exc:
            result = {
                "accepted": False,
                "reason": f"replacement admission failed: {type(exc).__name__}: {exc}"[:256],
            }
            if started_pid is not None:
                result["process_cleanup"] = cleanup_started_process(started_pid)
            return result
        if replacement.acceptance_state.name not in {"PROBATION", "ACCEPTED"}:
            result = {
                "accepted": False,
                "reason": "replacement did not enter probation or accepted state",
                "replacement_worker_id": str(replacement.worker_id),
                "acceptance_state": replacement.acceptance_state.name,
            }
            result["process_cleanup"] = cleanup_started_process(pid)
            return result
        return {
            "accepted": True,
            "started": True,
            "pid": pid,
            "failed_worker_id": str(failed_worker_id),
            "replacement_worker_id": str(replacement.worker_id),
            "authority_packet_id": str(packet.packet_id),
            "authority_packet_verified": True,
            "authority_packet_expires_at": packet.expires_at.isoformat(),
            "acceptance_state": replacement.acceptance_state.name,
            "request_id": str(request.request_id),
        }

    return handler

def build_authorized_restart_callback(
    supervisor: Any,
    *,
    failed_worker_id: UUID,
    packet: RecoveryAuthorityPacket,
    supervisor_time: datetime,
    target_id: str,
    generation_id: str,
    code_hash: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    spawn_worker: Callable[[WorkerReplacementRequest], Any],
    stop_worker: Callable[[int], Any] | None = None,
    allowed_capabilities: set[str] | frozenset[str] = frozenset(),
    policy: RepairRecoveryPolicy | None = None,
    acceptance_policy: WorkerAcceptancePolicy | None = None,
) -> Callable[[WorkerHealth], dict[str, Any]]:
    """Build a restart callback that performs packet-verified admission.

    The embedding application owns process creation. The callback is safe
    to pass to ``handle_worker_failure``: it supplies the immutable packet
    to the application callback, verifies the returned PID, admits the new
    worker, and reports the replacement identity back to the supervisor.
    """
    replacement_handler = build_replacement_action_handler(
        supervisor,
        failed_worker_id=failed_worker_id,
        packet=packet,
        supervisor_time=supervisor_time,
        target_id=target_id,
        generation_id=generation_id,
        code_hash=code_hash,
        policy_fingerprint=policy_fingerprint,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        spawn_worker=spawn_worker,
        stop_worker=stop_worker,
        allowed_capabilities=allowed_capabilities,
        policy=policy,
        acceptance_policy=acceptance_policy,
    )

    def callback(worker: WorkerHealth) -> dict[str, Any]:
        if worker.worker_id != failed_worker_id:
            return {
                "started": False,
                "error": "restart callback received an unexpected worker identity",
            }
        result = replacement_handler({"target_id": target_id})
        if not bool(result.get("accepted")):
            return {
                "started": False,
                "error": str(result.get("reason") or "replacement admission was rejected")[:256],
                "handler_result": result,
            }
        return dict(result)

    return callback


def handle_worker_failure(
    supervisor: Any,
    worker: WorkerHealth,
    *,
    policy: Any,
    create_incident: Callable[[Mapping[str, Any]], Any] | None = None,
    restart_worker: Callable[[WorkerHealth], Any] | None = None,
    disable_component: Callable[[WorkerHealth], Any] | None = None,
    diagnostic_debug: bool | None = None,
    critical_evidence: bool = False,
    collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
    require_complete_postmortem: bool = False,
    reconciliation_scope: str | None = None,
) -> dict[str, Any]:
    """Apply the policy boundary for one failed worker.

    The supervisor records failure evidence and chooses an action, but
    worker creation and component-specific shutdown remain callbacks owned
    by the application boundary. A callback must report success before the
    registry treats a worker as restarted.
    """
    envelope, failure_record, failure_metadata = capture_worker_failure_evidence_internal(
        supervisor,
        worker,
        diagnostic_debug=diagnostic_debug,
        critical_evidence=critical_evidence,
        collect_postmortem=collect_postmortem,
        require_complete_postmortem=require_complete_postmortem,
        reconciliation_scope=reconciliation_scope,
    )
    failure_persistence_status = failure_metadata["failure_persistence_status"]
    failure_persistence_error = failure_metadata["failure_persistence_error"]
    postmortem_status = failure_metadata["postmortem_status"]
    postmortem_error = failure_metadata["postmortem_error"]
    incident_error = None
    incident_result: Mapping[str, Any] | None = None
    if create_incident is not None:
        try:
            captured = create_incident(envelope)
            if isinstance(captured, Mapping):
                incident_result = captured
            incident_status = "RECORDED"
            supervisor._audit_event(
                "INCIDENT_CAPTURED",
                actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
                scope={
                    "worker_id": str(worker.worker_id),
                    "target_id": worker.target_id,
                    "incident_id": incident_result.get("incident_id") if incident_result else None,
                },
                outcome={"state": "RECORDED"},
                details={
                    "capsule_id": incident_result.get("capsule_id") if incident_result else None,
                    "incident_recorded": bool(
                        incident_result.get("incident_recorded")
                        if incident_result
                        else True
                    ),
                },
                priority=EvidencePriority.IMPORTANT,
            )
        except Exception as exc:
            incident_status = "FAILED"
            incident_error = f"{type(exc).__name__}: {exc}"[:256]
    else:
        incident_status = "NOT_CONFIGURED"
    restart_policy = policy
    configured_enabled = getattr(restart_policy, "enabled", False)
    configured_limit = getattr(restart_policy, "maximum_restarts", 0)
    configured_window = getattr(restart_policy, "restart_window_seconds", 300.0)
    configured_initial_backoff = getattr(restart_policy, "initial_backoff_seconds", 0.5)
    configured_maximum_backoff = getattr(restart_policy, "maximum_backoff_seconds", 30.0)
    if not isinstance(configured_enabled, bool):
        raise ValueError("worker restart enabled flag must be a boolean")
    if isinstance(configured_limit, bool) or not isinstance(configured_limit, int) or not 0 <= configured_limit <= 1000:
        raise ValueError("worker restart maximum_restarts must be an integer from 0 through 1000")
    for name, value in (
        ("restart_window_seconds", configured_window),
        ("initial_backoff_seconds", configured_initial_backoff),
        ("maximum_backoff_seconds", configured_maximum_backoff),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError(f"worker restart {name} must be a finite non-negative number")
    if configured_maximum_backoff < configured_initial_backoff:
        raise ValueError("worker restart maximum_backoff_seconds must cover initial backoff")
    role_restartable = worker.worker_kind in RESTARTABLE_WORKER_KINDS
    if not role_restartable:
        restart_result = {
            "started": False,
            "error": f"worker role {worker.worker_kind.name} is not restartable",
        }
    else:
        restart_result = None
    restart_requested = (
        role_restartable
        and configured_enabled
        and worker.restart_count < configured_limit
    )
    if restart_requested and restart_worker is not None:
        supervisor._audit_event(
            "WORKER_REPLACEMENT_REQUESTED",
            actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
            scope={
                "worker_id": str(worker.worker_id),
                "target_id": worker.target_id,
            },
            outcome={
                "state": "REQUESTED",
                "reason": "worker_failure_policy",
            },
            details={"restart_count": worker.restart_count},
        )
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
        replacement = None
        if restart_result and bool(restart_result.get("started")):
            replacement_id = restart_result.get("replacement_worker_id")
            if replacement_id is not None:
                try:
                    replacement = supervisor.workers.get(UUID(str(replacement_id)))
                except (KeyError, TypeError, ValueError):
                    replacement = None
                if (
                    replacement is None
                    or replacement.replaced_worker_id != worker.worker_id
                    or replacement.authority_packet_id is None
                    or replacement.state
                    not in {WorkerState.STARTING, WorkerState.HEALTHY, WorkerState.DEGRADED}
                ):
                    replacement = None
                    restart_result = {
                        "started": False,
                        "error": (
                            "replacement callback did not return a packet-authorized "
                            "replacement admitted by the supervisor"
                        ),
                    }
            elif worker.authority_packet_id is not None:
                restart_result = {
                    "started": False,
                    "error": (
                        "an already-authorized worker must be replaced through "
                        "packet-verified supervisor admission"
                    ),
                }
        if restart_result and bool(restart_result.get("started")):
            restarted = replacement or supervisor.workers.record_restart(
                worker.worker_id,
                pid=(
                    int(restart_result["pid"])
                    if restart_result.get("pid") is not None
                    else None
                ),
            )
            restart_result["worker_id"] = str(restarted.worker_id)
            restart_result["restart_count"] = restarted.restart_count
            supervisor._audit_event(
                "WORKER_REPLACED",
                actor={"type": "supervisor", "id": str(supervisor.supervisor_health.worker_id)},
                scope={
                    "worker_id": str(worker.worker_id),
                    "target_id": worker.target_id,
                },
                outcome={"state": "RESTARTED"},
                details={
                    "replacement_worker_id": str(restarted.worker_id),
                    "restart_count": restarted.restart_count,
                },
            )
            supervisor._audit_recovery_decision(
                {
                    "scope": reconciliation_scope or f"worker:{worker.worker_id}",
                    "target_id": worker.target_id,
                    "policy_action": {
                        "selected_action": "RESTART_WORKER",
                        "status": "SELECTED",
                    },
                    "action_execution": {
                        "status": "RESTARTED",
                        "authority_granted": False,
                    },
                    "reconciliation": {},
                }
            )
            return {
                "ok": True,
                "action": "RESTARTED",
                "incident_status": incident_status,
                "incident_error": incident_error,
                "failure_persistence_status": failure_persistence_status,
                "failure_persistence_error": failure_persistence_error,
                "postmortem_status": postmortem_status,
                "postmortem_error": postmortem_error,
                "reconciliation_scope": (
                    failure_record.reconciliation_scope
                    if failure_record is not None
                    else reconciliation_scope
                ),
                "restart": {
                    **restart_result,
                },
                "failure_envelope": envelope,
            }
    exhaustion = getattr(
        restart_policy,
        "exhaustion_action",
        WorkerFailureAction.DISABLE_COMPONENT,
    )
    if not isinstance(exhaustion, WorkerFailureAction):
        try:
            exhaustion = WorkerFailureAction[str(exhaustion).upper()]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid worker exhaustion action: {exhaustion!r}") from exc
    callback_result = None
    if exhaustion is WorkerFailureAction.DISABLE_COMPONENT and disable_component is not None:
        callback_result = disable_component(worker)
    elif exhaustion is WorkerFailureAction.STOP_APPLICATION:
        callback_result = stop_application(supervisor)
    result = {
        "ok": True,
        "action": exhaustion.name,
        "incident_status": incident_status,
        "incident_error": incident_error,
        "failure_persistence_status": failure_persistence_status,
        "failure_persistence_error": failure_persistence_error,
        "postmortem_status": postmortem_status,
        "postmortem_error": postmortem_error,
        "reconciliation_scope": (
            failure_record.reconciliation_scope
            if supervisor.failure_store is not None and failure_persistence_status == "PERSISTED"
            else reconciliation_scope
        ),
        "restart": restart_result,
        "failure_envelope": envelope,
    }
    callback_accepted = isinstance(callback_result, Mapping) and bool(
        callback_result.get("accepted")
    )
    supervisor._audit_recovery_decision(
        {
            "scope": reconciliation_scope or f"worker:{worker.worker_id}",
            "target_id": worker.target_id,
            "policy_action": {
                "selected_action": exhaustion.name,
                "status": "SELECTED",
            },
            "action_execution": {
                "status": "EXECUTED" if callback_accepted else "PLANNED_ONLY",
                "authority_granted": False,
            },
            "reconciliation": {},
            "critical_evidence_conflict": bool(critical_evidence),
        }
    )
    if callback_result is not None:
        result["action_result"] = callback_result
    supervisor.runtime.event(
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


def reconcile_worker_failures(
    supervisor: Any,
    *,
    scope: str | None = None,
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
    observed_at: datetime | None = None,
    recovery_policy: RepairRecoveryPolicy | None = None,
    recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
) -> dict[str, Any]:
    """Reconcile failures and optionally dispatch policy-owned actions.

    Reconciliation is always performed first. When ``recovery_policy`` is
    supplied, each scope receives an explicit action decision: a conflict
    involving critical evidence uses ``critical_evidence_action`` and
    other failures use ``worker_failure_action``. Any effect still requires
    an application-owned handler acknowledgement through the existing
    action gates; evidence reconciliation never grants authority.
    """
    if supervisor.failure_store is None:
        raise RuntimeError("worker failure reconciliation requires a failure store")
    result = reconcile_worker_failure_records(
        supervisor.failure_store,
        scope=scope,
        minimum_sample_count=minimum_sample_count,
        z_threshold=z_threshold,
        observed_at=observed_at,
    )
    for reconciliation in result["reconciliations"]:
        supervisor._audit_worker_postmortem_reconciliation(reconciliation)
    if recovery_policy is None:
        return result
    decisions: list[dict[str, Any]] = []
    records = tuple(supervisor.failure_store.all_worker_failures())

    def record_envelope(record: Any) -> Mapping[str, Any]:
        envelope = (
            getattr(record, "envelope", None)
            or (record.get("envelope", {}) if isinstance(record, Mapping) else {})
        )
        return envelope if isinstance(envelope, Mapping) else {}

    def record_scope(record: Any) -> str:
        stored = getattr(record, "reconciliation_scope", None) or (
            record.get("reconciliation_scope") if isinstance(record, Mapping) else ""
        )
        return str(stored or resolve_worker_failure_scope(
            record_envelope(record),
            failure_id=(
                getattr(record, "failure_id", None)
                or (record.get("failure_id") if isinstance(record, Mapping) else "")
            ),
        ))

    for reconciliation in result["reconciliations"]:
        reconciliation_scope = str(reconciliation["scope"])
        reconciliation_target = str(reconciliation.get("target_id") or "")
        scoped_records = tuple(
            record
            for record in records
            if record_scope(record) == reconciliation_scope
            and str(record_envelope(record).get("target_id") or "")
            == reconciliation_target
        )
        critical_conflict = bool(reconciliation.get("conflict")) and any(
            bool(
                getattr(record, "critical_evidence", None)
                or (
                    record.get("critical_evidence")
                    if isinstance(record, Mapping)
                    else False
                )
            )
            for record in scoped_records
        )
        action = (
            recovery_policy.critical_evidence_action
            if critical_conflict
            else recovery_policy.worker_failure_action
        )
        decision = {
            "scope": reconciliation_scope,
            "target_id": reconciliation_target or None,
            "reconciliation": reconciliation,
            "critical_evidence_conflict": critical_conflict,
            "policy_action": select_recovery_action(
                action,
                enabled=recovery_policy.enabled,
            ),
            "authority_granted": False,
        }
        recorder = getattr(supervisor.failure_store, "record_worker_failure_recovery", None)
        reader = getattr(supervisor.failure_store, "all_worker_failure_recoveries", None)
        if not callable(recorder) or not callable(reader):
            decision["action_execution"] = {
                "status": "CHECKPOINT_NOT_CONFIGURED",
                "authority_granted": False,
                "reason": "worker failure recovery checkpoint is unavailable",
            }
            supervisor._audit_recovery_decision(decision)
            decisions.append(decision)
            continue
        pending_record = create_worker_failure_recovery_record(
            decision,
            action_execution={
                "status": "PENDING",
                "authority_granted": False,
            },
        )
        existing = next(
            (
                item
                for item in reader()
                if str(
                    getattr(item, "recovery_id", None)
                    or (
                        item.get("recovery_id")
                        if isinstance(item, Mapping)
                        else ""
                    )
                ) == str(pending_record.recovery_id)
            ),
            None,
        )
        decision["recovery_record_id"] = str(pending_record.recovery_id)
        if existing is not None:
            existing_execution = (
                getattr(existing, "action_execution", None)
                or (
                    existing.get("action_execution")
                    if isinstance(existing, Mapping)
                    else None
                )
            )
            decision["action_execution"] = dict(existing_execution or {
                "status": "PENDING",
                "authority_granted": False,
            })
            supervisor._audit_recovery_decision(decision)
            decisions.append(decision)
            continue
        try:
            recorder(pending_record)
        except Exception as exc:
            decision["action_execution"] = {
                "status": "CHECKPOINT_FAILED",
                "authority_granted": False,
                "error": f"{type(exc).__name__}: {exc}"[:256],
            }
            supervisor._audit_recovery_decision(decision)
            decisions.append(decision)
            continue
        execution = dispatch_recovery_action(
            decision,
            handlers=recovery_handlers,
        )
        decision["action_execution"] = execution
        try:
            recorder(
                create_worker_failure_recovery_record(
                    decision,
                    action_execution=execution,
                )
            )
        except Exception as exc:
            decision["action_execution"] = {
                **execution,
                "status": "EXECUTED_CHECKPOINT_FAILED"
                if execution.get("status") == "EXECUTED"
                else "CHECKPOINT_FAILED_AFTER_DISPATCH",
                "checkpoint_error": f"{type(exc).__name__}: {exc}"[:256],
            }
        supervisor._audit_recovery_decision(decision)
        decisions.append(decision)
    return {
        **result,
        "recovery_decisions": tuple(decisions),
        "authority_granted": False,
    }


def handle_worker_failure_cohort(
    supervisor: Any,
    workers: Iterable[WorkerHealth],
    *,
    scope: str,
    recovery_policy: RepairRecoveryPolicy,
    recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
    diagnostic_debug: bool | None = None,
    critical_evidence: bool = False,
    collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
    require_complete_postmortem: bool = False,
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
) -> dict[str, Any]:
    """Capture a failed-worker cohort before one scope-level action.

    The caller supplies the workers belonging to one continuous transaction.
    Every member is persisted under the same reconciliation scope before the
    supervisor compares evidence and dispatches the policy-selected action.
    Application-owned handlers remain responsible for incident creation,
    replacement, or shutdown. This function never grants authority.
    """
    if supervisor.failure_store is None:
        raise RuntimeError("worker failure cohort handling requires a failure store")
    normalized_scope = resolve_worker_failure_scope({}, scope=scope)
    unique_workers: dict[UUID, WorkerHealth] = {}
    for worker in workers:
        if not isinstance(worker, WorkerHealth):
            raise TypeError("worker failure cohort must contain WorkerHealth records")
        if len(unique_workers) >= MAX_WORKER_FAILURE_COHORT:
            raise ValueError(
                "worker failure cohort cannot contain more than "
                f"{MAX_WORKER_FAILURE_COHORT} workers"
            )
        if worker.worker_id in unique_workers:
            raise ValueError("worker failure cohort contains a duplicate worker")
        if worker.state not in {WorkerState.FAILED, WorkerState.UNAUTHORIZED}:
            raise ValueError(
                "worker failure cohort requires failed or unauthorized workers"
            )
        unique_workers[worker.worker_id] = worker
    if not unique_workers:
        raise ValueError("worker failure cohort must contain at least one worker")

    require_complete_postmortem = bool(require_complete_postmortem) or (
        critical_evidence
        and recovery_policy.require_full_worker_postmortem_for_critical_evidence
    )
    evidence = [
        supervisor.capture_worker_failure_evidence(
            worker,
            diagnostic_debug=diagnostic_debug,
            critical_evidence=critical_evidence,
            collect_postmortem=collect_postmortem,
            require_complete_postmortem=require_complete_postmortem,
            reconciliation_scope=normalized_scope,
        )
        for worker in unique_workers.values()
    ]
    reconciliation = supervisor.reconcile_worker_failures(
        scope=normalized_scope,
        minimum_sample_count=minimum_sample_count,
        z_threshold=z_threshold,
        recovery_policy=recovery_policy,
        recovery_handlers=recovery_handlers,
    )
    return {
        "ok": all(item["failure_persistence_status"] == "PERSISTED" for item in evidence),
        "scope": normalized_scope,
        "worker_ids": [str(item.worker_id) for item in unique_workers.values()],
        "evidence": evidence,
        "reconciliation": reconciliation,
        "authority_granted": False,
    }


def handle_expired_worker_cohort(
    supervisor: Any,
    workers: Iterable[WorkerHealth],
    *,
    supervisor_time: datetime,
    scope: str,
    recovery_policy: RepairRecoveryPolicy,
    recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
    diagnostic_debug: bool | None = None,
    critical_evidence: bool = False,
    collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
    require_complete_postmortem: bool = False,
    minimum_sample_count: int = 30,
    z_threshold: float = 3.0,
) -> dict[str, Any]:
    """Route expired workers through the runtime-owned recovery boundary.

    Only the authoritative supervisor clock may establish expiry. A supplied
    snapshot must still identify the registered process and be unauthorized;
    otherwise it cannot be used to initiate recovery. The validated workers
    are then handed to the normal cohort path, which never grants authority.
    """
    if supervisor_time.tzinfo is None or supervisor_time.utcoffset() is None:
        raise ValueError("expired-worker recovery time must be timezone-aware")
    if not isinstance(recovery_policy, RepairRecoveryPolicy):
        raise TypeError("expired-worker recovery requires a RepairRecoveryPolicy")
    supplied = tuple(workers)
    if not supplied:
        raise ValueError("expired-worker recovery requires at least one worker")
    current_workers: list[WorkerHealth] = []
    seen: set[UUID] = set()
    for worker in supplied:
        if not isinstance(worker, WorkerHealth):
            raise TypeError("expired-worker recovery requires WorkerHealth snapshots")
        if worker.worker_id in seen:
            raise ValueError("expired-worker recovery contains a duplicate worker")
        seen.add(worker.worker_id)
        try:
            current = supervisor.workers.get(worker.worker_id)
        except KeyError as exc:
            raise PermissionError(
                "expired-worker recovery snapshot is no longer registered"
            ) from exc
        if current.process_start_id != worker.process_start_id:
            raise PermissionError(
                "expired-worker recovery snapshot does not match the live process"
            )
        if current.state is not WorkerState.UNAUTHORIZED:
            raise PermissionError(
                "expired-worker recovery requires an unauthorized worker"
            )
        if (
            current.authority_packet_expires_at is None
            or supervisor_time < current.authority_packet_expires_at
        ):
            raise PermissionError(
                "expired-worker recovery requires an authority packet at or before supervisor time"
            )
        current_workers.append(current)
    return handle_worker_failure_cohort(
        supervisor,
        current_workers,
        scope=scope,
        recovery_policy=recovery_policy,
        recovery_handlers=recovery_handlers,
        diagnostic_debug=diagnostic_debug,
        critical_evidence=critical_evidence,
        collect_postmortem=collect_postmortem,
        require_complete_postmortem=require_complete_postmortem,
        minimum_sample_count=minimum_sample_count,
        z_threshold=z_threshold,
    )

__all__ = [
    "AdaptiveAggregationQueueRegistry",
    "ApplicationWorkerLifecycle",
    "accept_comparison_worker_result",
    "build_authorized_restart_callback",
    "build_incident_action_handler",
    "build_replacement_action_handler",
    "build_shutdown_action_handler",
    "bounded_diagnostic_value",
    "capture_worker_failure_evidence",
    "compare_comparison_worker_result",
    "diagnostic_debug_enabled",
    "handle_expired_worker_cohort",
    "handle_worker_acceptance_observation",
    "handle_worker_authority_packet",
    "handle_worker_authority_queue_handoff",
    "handle_worker_failure",
    "handle_worker_failure_cohort",
    "handle_worker_replacement_packet",
    "handle_worker_replacement_queue_handoff",
    "issue_comparison_worker_assignment",
    "join_worker_evidence_reconciliations",
    "MAX_WORKER_FAILURE_COHORT",
    "reconcile_adaptive_aggregation_queues",
    "reconcile_comparison_worker_reports",
    "reconcile_worker_failures",
    "Watchdog",
    "WorkRegistry",
    "WorkerRegistry",
    "monitor_application",
    "run_supervisor_control_cycle",
    "stop_application",
    "stop_runtime_supervisor",
    "worker_failure_envelope",
]
