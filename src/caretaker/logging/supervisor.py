from __future__ import annotations

import json
import os
import signal
import threading
import time
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4

from .handler import LoggingRuntime
from .acceptance import WorkerAcceptanceStore
from ..adaptive_aggregation import (
    QueueAdaptiveAggregationStore,
    SupervisorAdaptiveAggregationStore,
)
from ..repair_recovery import (
    ComparisonWorkerAssignment,
    ComparisonWorkerComparisonReport,
    ComparisonWorkerReconciliationReport,
    ComparisonWorkerResult,
    WorkerEvidenceJoinReport,
    RecoveryAuthorityPacket,
    RepairRecoveryPolicy,
    WorkerAcceptancePolicy,
    WorkerReplacementRequest,
    create_worker_failure_record,
    create_worker_failure_recovery_record,
    create_comparison_worker_assignment,
    compare_comparison_worker_result,
    reconcile_comparison_worker_reports,
    join_worker_evidence_reconciliations,
    dispatch_recovery_action,
    evaluate_worker_acceptance,
    reconcile_worker_failure_records,
    resolve_worker_failure_scope,
    select_recovery_action,
    validate_worker_acceptance_policy,
    verify_comparison_worker_assignment,
    verify_comparison_worker_result,
    deserialize_recovery_authority_packet,
    deserialize_worker_replacement_request,
    serialize_recovery_authority_packet,
    serialize_worker_replacement_request,
    verify_recovery_authority_packet,
)
from .models import (
    ActiveWork,
    CaretakerComponent,
    EvidencePriority,
    LoggingMode,
    WorkState,
    WorkerFailureAction,
    WorkerHealth,
    WorkerAcceptanceState,
    WorkerKind,
    WorkerState,
)
from ..transport import APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES
from ..runtime_supervision import (
    MAX_ADAPTIVE_QUEUE_WORKERS,
    MAX_WORKER_AUTHORITY_HANDOFFS,
    AdaptiveAggregationQueueRegistry,
    ApplicationWorkerLifecycle,
    Watchdog,
    WorkRegistry,
    WorkerRegistry as ApplicationWorkerRegistry,
    capture_worker_failure_evidence as runtime_capture_worker_failure_evidence,
    capture_worker_failure_evidence_internal,
    handle_expired_worker_cohort as runtime_handle_expired_worker_cohort,
    handle_worker_acceptance_observation as runtime_handle_worker_acceptance_observation,
    handle_worker_authority_packet as runtime_handle_worker_authority_packet,
    handle_worker_authority_queue_handoff as runtime_handle_worker_authority_queue_handoff,
    handle_worker_failure as runtime_handle_worker_failure,
    handle_worker_failure_cohort as runtime_handle_worker_failure_cohort,
    handle_worker_replacement_packet as runtime_handle_worker_replacement_packet,
    handle_worker_replacement_queue_handoff as runtime_handle_worker_replacement_queue_handoff,
    build_authorized_restart_callback as runtime_build_authorized_restart_callback,
    build_replacement_action_handler as runtime_build_replacement_action_handler,
    accept_comparison_worker_result as runtime_accept_comparison_worker_result,
    compare_comparison_worker_result as runtime_compare_comparison_worker_result,
    issue_comparison_worker_assignment as runtime_issue_comparison_worker_assignment,
    join_worker_evidence_reconciliations as runtime_join_worker_evidence_reconciliations,
    reconcile_comparison_worker_reports as runtime_reconcile_comparison_worker_reports,
    reconcile_worker_failures as runtime_reconcile_worker_failures,
    MAX_WORKER_FAILURE_COHORT,
    monitor_application,
    run_supervisor_control_cycle,
    stop_application,
    stop_runtime_supervisor,
)


def _legacy_authority_verifier(*args: Any, **kwargs: Any) -> Any:
    """Preserve the historical module-level verifier patch seam."""
    return verify_recovery_authority_packet(*args, **kwargs)


class WorkerRegistry(ApplicationWorkerRegistry):
    """Compatibility wrapper for the application-owned worker registry."""

    def __init__(self, **kwargs: Any) -> None:
        kwargs.setdefault("authority_verifier", _legacy_authority_verifier)
        super().__init__(**kwargs)




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
        acceptance_store: WorkerAcceptanceStore | None = None,
        acceptance_store_path: str | Path | None = None,
        failure_store: Any | None = None,
    ) -> None:
        self.runtime = runtime
        self.application_pid = application_pid
        self.application_process_group_id = application_process_group_id
        self.application_process = application_process
        if acceptance_store is not None and acceptance_store_path is not None:
            raise ValueError("provide acceptance_store or acceptance_store_path, not both")
        if acceptance_store is None and acceptance_store_path is not None:
            acceptance_store = WorkerAcceptanceStore(acceptance_store_path)
        self.work = WorkRegistry()
        self.failure_store = failure_store
        self.workers = WorkerRegistry(
            acceptance_store=acceptance_store,
            audit_event=self._audit_event,
        )
        self.supervisor_health = self.workers.register(WorkerKind.SUPERVISOR, os.getpid())
        self.watchdog = Watchdog(self.workers, on_unhealthy=self._worker_unhealthy)
        self._adaptive_aggregation_queue_registry = AdaptiveAggregationQueueRegistry(
            worker_lookup=self.workers.get,
            maximum_workers=MAX_ADAPTIVE_QUEUE_WORKERS,
        )
        self._stop = threading.Event()

    def bind_adaptive_aggregation_queue(
        self,
        worker_id: UUID | str,
        queue_store: QueueAdaptiveAggregationStore,
    ) -> dict[str, Any]:
        """Bind one application-owned adaptive queue to a live worker.

        The application owns queue creation and lifetime.  This registry only
        records which queue belongs to an already registered worker so a later
        supervisor cycle can derive the worker identity and PID from the live
        registry.  Replacing a binding requires an explicit unbind first, so
        queued evidence cannot be silently abandoned.
        """
        return self._adaptive_aggregation_queue_registry.bind(worker_id, queue_store)

    def unbind_adaptive_aggregation_queue(
        self,
        worker_id: UUID | str,
        *,
        queue_store: QueueAdaptiveAggregationStore | None = None,
    ) -> dict[str, Any]:
        """Remove a queue binding without draining or deleting its evidence."""
        return self._adaptive_aggregation_queue_registry.unbind(
            worker_id,
            queue_store=queue_store,
        )

    def adaptive_aggregation_queue_bindings(self) -> tuple[dict[str, Any], ...]:
        """Return a bounded read-only projection of application queue bindings."""
        return self._adaptive_aggregation_queue_registry.status()

    def start(self) -> None:
        self.workers.heartbeat(self.supervisor_health.worker_id)
        self.watchdog.start()
        self._audit_event(
            "SUPERVISOR_STATE_CHANGED",
            actor={"type": "supervisor", "id": str(self.supervisor_health.worker_id)},
            scope={"worker_id": str(self.supervisor_health.worker_id)},
            outcome={"state": "STARTED"},
            details={
                "application_pid": self.application_pid,
                "application_process_group_id": self.application_process_group_id,
            },
        )

    def _worker_unhealthy(self, worker: WorkerHealth) -> None:
        self.runtime.event(
            logger_name="caretaker.watchdog", severity=40,
            channel=__import__("caretaker.logging.models", fromlist=["LogChannel"]).LogChannel.CARETAKER_INTERNAL,
            message=f"Caretaker worker unhealthy: {worker.worker_kind.name}",
            fields=self.worker_failure_envelope(worker),
        )

    @staticmethod
    def _diagnostic_debug_enabled() -> bool:
        """Return whether controlled diagnostic detail is explicitly enabled."""
        return os.environ.get("CARETAKER_DIAGNOSTIC_DEBUG", "").strip().lower() in {
            "1", "true", "yes", "on",
        }

    def _audit_event(
        self,
        event_type: str,
        *,
        actor: Mapping[str, Any] | None = None,
        scope: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        outcome: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
        priority: Any = None,
    ) -> None:
        """Write a high-value audit event when the runtime owns an audit stream."""
        audit = getattr(self.runtime, "audit", None)
        emit = getattr(audit, "emit", None)
        if not callable(emit):
            return
        if priority is None:
            from .models import EvidencePriority

            priority = EvidencePriority.CRITICAL
        emit(
            event_type,
            actor=actor,
            scope=scope,
            policy=policy,
            outcome=outcome,
            details=details,
            priority=priority,
        )

    def _audit_worker_postmortem_reconciliation(
        self,
        reconciliation: Mapping[str, Any],
    ) -> None:
        comparison = reconciliation.get("comparison")
        comparison = comparison if isinstance(comparison, Mapping) else {}
        packet_context = comparison.get("packet_context")
        reconciliation_scope = str(reconciliation.get("scope") or "")
        reconciliation_target = str(reconciliation.get("target_id") or "")
        self._audit_event(
            "WORKER_POSTMORTEM_RECONCILED",
            actor={"type": "supervisor", "id": str(self.supervisor_health.worker_id)},
            scope={
                "reconciliation_scope": reconciliation_scope,
                "target_id": reconciliation_target or None,
            },
            outcome={
                "state": str(comparison.get("status") or "INCOMPLETE_EVIDENCE"),
                "authority_granted": False,
            },
            details={
                "input_count": reconciliation.get("input_count", 0),
                "unique_packet_count": reconciliation.get("unique_packet_count", 0),
                "duplicate_count": reconciliation.get("duplicate_count", 0),
                "conflict": bool(reconciliation.get("conflict")),
                "packet_context_status": (
                    str(packet_context.get("status") or "")
                    if isinstance(packet_context, Mapping)
                    else None
                ),
            },
        )

    def _audit_recovery_decision(self, decision: Mapping[str, Any]) -> None:
        """Emit one critical audit record for a coordinated recovery decision."""
        policy_action = decision.get("policy_action")
        policy_action = policy_action if isinstance(policy_action, Mapping) else {}
        execution = decision.get("action_execution")
        execution = execution if isinstance(execution, Mapping) else {}
        reconciliation = decision.get("reconciliation")
        reconciliation = reconciliation if isinstance(reconciliation, Mapping) else {}
        self._audit_event(
            "RECOVERY_DECISION",
            actor={"type": "supervisor", "id": str(self.supervisor_health.worker_id)},
            scope={
                "reconciliation_scope": str(decision.get("scope") or ""),
                "target_id": decision.get("target_id"),
                "recovery_record_id": decision.get("recovery_record_id"),
            },
            outcome={
                "state": str(execution.get("status") or "UNKNOWN"),
                "action": policy_action.get("selected_action"),
                "authority_granted": False,
            },
            details={
                "policy_action_status": policy_action.get("status"),
                "critical_evidence_conflict": bool(
                    decision.get("critical_evidence_conflict")
                ),
                "reconciliation_status": reconciliation.get("status"),
                "reconciliation_conflict": bool(reconciliation.get("conflict")),
                "handler_status": execution.get("status"),
            },
        )

    @staticmethod
    def _bounded_diagnostic_value(value: Any, *, depth: int = 0) -> Any:
        """Keep worker-supplied diagnostic context finite and JSON-shaped."""
        if depth >= 4:
            return "<depth-limit>"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:512]
        if isinstance(value, Mapping):
            return {
                str(key)[:128]: CaretakerApplicationSupervisor._bounded_diagnostic_value(
                    item, depth=depth + 1
                )
                for key, item in list(value.items())[:64]
            }
        if isinstance(value, (list, tuple, set, frozenset)):
            return [
                CaretakerApplicationSupervisor._bounded_diagnostic_value(
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
            CaretakerApplicationSupervisor._diagnostic_debug_enabled()
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
                CaretakerApplicationSupervisor._bounded_diagnostic_value(
                    worker.diagnostic_context
                )
            )
        return envelope

    def _capture_worker_failure_evidence(
        self,
        worker: WorkerHealth,
        *,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
        require_complete_postmortem: bool = False,
        reconciliation_scope: str | None = None,
    ) -> tuple[dict[str, Any], Any | None, dict[str, Any]]:
        """Capture one failed-worker envelope through the runtime owner."""
        return capture_worker_failure_evidence_internal(
            self,
            worker,
            diagnostic_debug=diagnostic_debug,
            critical_evidence=critical_evidence,
            collect_postmortem=collect_postmortem,
            require_complete_postmortem=require_complete_postmortem,
            reconciliation_scope=reconciliation_scope,
        )

    def capture_worker_failure_evidence(
        self,
        worker: WorkerHealth,
        *,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[WorkerHealth, Mapping[str, Any]], Any] | None = None,
        require_complete_postmortem: bool = False,
        reconciliation_scope: str | None = None,
    ) -> dict[str, Any]:
        """Persist one rollback envelope through the runtime owner."""
        return runtime_capture_worker_failure_evidence(
            self,
            worker,
            diagnostic_debug=diagnostic_debug,
            critical_evidence=critical_evidence,
            collect_postmortem=collect_postmortem,
            require_complete_postmortem=require_complete_postmortem,
            reconciliation_scope=reconciliation_scope,
        )

    def handle_worker_failure_cohort(
        self,
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
        """Capture and reconcile a failed-worker cohort through runtime ownership."""
        return runtime_handle_worker_failure_cohort(
            self,
            workers,
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

    def handle_expired_worker_cohort(
        self,
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
        """Route expired-worker recovery through runtime ownership."""
        return runtime_handle_expired_worker_cohort(
            self,
            workers,
            supervisor_time=supervisor_time,
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

    def handle_worker_failure(
        self,
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
        """Apply the single-worker recovery boundary through runtime ownership."""
        return runtime_handle_worker_failure(
            self,
            worker,
            policy=policy,
            create_incident=create_incident,
            restart_worker=restart_worker,
            disable_component=disable_component,
            diagnostic_debug=diagnostic_debug,
            critical_evidence=critical_evidence,
            collect_postmortem=collect_postmortem,
            require_complete_postmortem=require_complete_postmortem,
            reconciliation_scope=reconciliation_scope,
        )

    def reconcile_worker_failures(
        self,
        *,
        scope: str | None = None,
        minimum_sample_count: int = 30,
        z_threshold: float = 3.0,
        observed_at: datetime | None = None,
        recovery_policy: RepairRecoveryPolicy | None = None,
        recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
    ) -> dict[str, Any]:
        """Reconcile worker failures through runtime ownership."""
        return runtime_reconcile_worker_failures(
            self,
            scope=scope,
            minimum_sample_count=minimum_sample_count,
            z_threshold=z_threshold,
            observed_at=observed_at,
            recovery_policy=recovery_policy,
            recovery_handlers=recovery_handlers,
        )

    def build_replacement_action_handler(
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
        spawn_worker: Callable[[WorkerReplacementRequest], Any],
        stop_worker: Callable[[int], Any] | None = None,
        allowed_capabilities: set[str] | frozenset[str] = frozenset(),
        policy: RepairRecoveryPolicy | None = None,
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        """Build a packet-verified replacement handler through runtime ownership."""
        return runtime_build_replacement_action_handler(
            self,
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

    def build_authorized_restart_callback(
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
        spawn_worker: Callable[[WorkerReplacementRequest], Any],
        stop_worker: Callable[[int], Any] | None = None,
        allowed_capabilities: set[str] | frozenset[str] = frozenset(),
        policy: RepairRecoveryPolicy | None = None,
        acceptance_policy: WorkerAcceptancePolicy | None = None,
    ) -> Callable[[WorkerHealth], dict[str, Any]]:
        """Build a packet-verified restart callback through runtime ownership."""
        return runtime_build_authorized_restart_callback(
            self,
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

    def issue_comparison_worker_assignment(
        self,
        packet: RecoveryAuthorityPacket,
        *,
        scope: str,
        evidence_refs: tuple[str, ...] = (),
        supervisor_time: datetime,
        worker_kind: str = "REPAIR_ANALYZER",
        policy: RepairRecoveryPolicy | None = None,
        store: Any | None = None,
    ) -> ComparisonWorkerAssignment:
        """Issue a comparison assignment through runtime ownership."""
        return runtime_issue_comparison_worker_assignment(
            self,
            packet,
            scope=scope,
            evidence_refs=evidence_refs,
            supervisor_time=supervisor_time,
            worker_kind=worker_kind,
            policy=policy,
            store=store,
        )

    def accept_comparison_worker_result(
        self,
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
        """Accept a comparison result through runtime ownership."""
        return runtime_accept_comparison_worker_result(
            self,
            assignment,
            packet,
            result,
            supervisor_time=supervisor_time,
            worker_process_id=worker_process_id,
            worker_process_start_id=worker_process_start_id,
            allowed_capabilities=allowed_capabilities,
            policy=policy,
            store=store,
        )

    def compare_comparison_worker_result(
        self,
        assignment: ComparisonWorkerAssignment | Mapping[str, Any],
        result: ComparisonWorkerResult | Mapping[str, Any],
        *,
        baseline_signatures: tuple[Mapping[str, Any], ...] = (),
        minimum_sample_count: int = 30,
        z_threshold: float = 3.0,
        compared_at: datetime | None = None,
        store: Any | None = None,
    ) -> ComparisonWorkerComparisonReport:
        """Compare a worker result through runtime ownership."""
        return runtime_compare_comparison_worker_result(
            self,
            assignment,
            result,
            baseline_signatures=baseline_signatures,
            minimum_sample_count=minimum_sample_count,
            z_threshold=z_threshold,
            compared_at=compared_at,
            store=store,
        )

    def reconcile_comparison_worker_reports(
        self,
        reports: tuple[ComparisonWorkerComparisonReport | Mapping[str, Any], ...],
        *,
        assignment_contexts: tuple[
            ComparisonWorkerAssignment | Mapping[str, Any], ...
        ] = (),
        reconciled_at: datetime | None = None,
        store: Any | None = None,
    ) -> ComparisonWorkerReconciliationReport:
        """Reconcile comparison reports through runtime ownership."""
        return runtime_reconcile_comparison_worker_reports(
            self,
            reports,
            assignment_contexts=assignment_contexts,
            reconciled_at=reconciled_at,
            store=store,
        )

    def join_worker_evidence_reconciliations(
        self,
        postmortem_reconciliation: Mapping[str, Any],
        comparison_reconciliation: ComparisonWorkerReconciliationReport | Mapping[str, Any],
        *,
        assignment_contexts: tuple[
            ComparisonWorkerAssignment | Mapping[str, Any], ...
        ] = (),
        joined_at: datetime | None = None,
        store: Any | None = None,
    ) -> WorkerEvidenceJoinReport:
        """Join worker evidence through runtime ownership."""
        return runtime_join_worker_evidence_reconciliations(
            self,
            postmortem_reconciliation,
            comparison_reconciliation,
            assignment_contexts=assignment_contexts,
            joined_at=joined_at,
            store=store,
        )

    @staticmethod
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
        self,
        stop_application: Callable[[Mapping[str, Any]], Any] | None = None,
    ) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        """Build an application-boundary shutdown action adapter.

        By default this wraps the supervisor's application process-group
        shutdown implementation. An embedding application may provide a
        callback instead; it must accept the complete recovery decision and
        return a mapping with ``accepted=True`` and
        ``shutdown_requested=True``. The latter is an explicit application
        acknowledgement, not a Caretaker authority grant.
        """
        if stop_application is not None and not callable(stop_application):
            raise TypeError("stop_application must be callable")

        def handler(decision: Mapping[str, Any]) -> dict[str, Any]:
            try:
                if stop_application is None:
                    raw_result = self.stop_application()
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
                result = stop_application(decision)
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

    def handle_worker_acceptance_observation(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Route the worker control endpoint through runtime ownership."""
        return runtime_handle_worker_acceptance_observation(self, *args, **kwargs)

    def handle_worker_authority_packet(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Route the worker control endpoint through runtime ownership."""
        return runtime_handle_worker_authority_packet(self, *args, **kwargs)

    def handle_worker_authority_queue_handoff(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Route the worker control endpoint through runtime ownership."""
        return runtime_handle_worker_authority_queue_handoff(self, *args, **kwargs)

    def handle_worker_replacement_packet(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Route the worker control endpoint through runtime ownership."""
        return runtime_handle_worker_replacement_packet(self, *args, **kwargs)

    def handle_worker_replacement_queue_handoff(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Route the worker control endpoint through runtime ownership."""
        return runtime_handle_worker_replacement_queue_handoff(self, *args, **kwargs)


    def reconcile_adaptive_aggregation_queues(
        self,
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
            queues = self._adaptive_aggregation_queue_registry.snapshot()
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
                worker = self.workers.get(worker_id)
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

    def run_control_cycle(
        self,
        *,
        supervisor_time: datetime | None = None,
        on_expired_workers: Callable[[tuple[WorkerHealth, ...], datetime], Any] | None = None,
        on_cycle: Callable[[datetime], Any] | None = None,
    ) -> dict[str, Any]:
        """Run one bounded supervisor cycle through the application runtime."""
        return run_supervisor_control_cycle(
            self,
            supervisor_time=supervisor_time,
            on_expired_workers=on_expired_workers,
            on_cycle=on_cycle,
        )

    def monitor_application(
        self,
        *,
        interval_seconds: float = 1.0,
        on_expired_workers: Callable[[tuple[WorkerHealth, ...], datetime], Any] | None = None,
        on_cycle: Callable[[datetime], Any] | None = None,
    ) -> None:
        """Monitor the application through the application runtime."""
        return monitor_application(
            self,
            interval_seconds=interval_seconds,
            on_expired_workers=on_expired_workers,
            on_cycle=on_cycle,
        )

    def stop_application(
        self,
        *,
        graceful_signal: int = signal.SIGTERM,
        timeout_seconds: float = 10.0,
    ) -> dict[str, object]:
        """Stop the application boundary through the application runtime."""
        return stop_application(
            self,
            graceful_signal=graceful_signal,
            timeout_seconds=timeout_seconds,
        )

    def stop(self) -> None:
        """Stop the application runtime through the ownership seam."""
        stop_runtime_supervisor(self)




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
