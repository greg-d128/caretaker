"""Application-runtime scheduling and health-monitoring primitives.

These primitives are owned by the application runtime. The logging package
re-exports them temporarily for compatibility with existing integrations, but
their implementation must not depend on the logging supervisor or runtime.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID, uuid4

from .adaptive_aggregation import QueueAdaptiveAggregationStore
from .logging.acceptance import WorkerAcceptanceStore
from .logging.models import (
    ActiveWork,
    CaretakerComponent,
    WorkState,
    WorkerHealth,
    WorkerAcceptanceState,
    WorkerKind,
    WorkerState,
)
from .repair_recovery import (
    RecoveryAuthorityPacket,
    RepairRecoveryPolicy,
    WorkerAcceptancePolicy,
    WorkerReplacementRequest,
    deserialize_recovery_authority_packet,
    deserialize_worker_replacement_request,
    evaluate_worker_acceptance,
    validate_worker_acceptance_policy,
    verify_recovery_authority_packet,
)


MAX_ADAPTIVE_QUEUE_WORKERS = 128
MAX_WORKER_AUTHORITY_HANDOFFS = 4096


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

__all__ = ["AdaptiveAggregationQueueRegistry", "Watchdog", "WorkRegistry", "WorkerRegistry"]
