"""Application-runtime ownership boundary for Caretaker supervision.

The implementation currently delegates to the historical logging supervisor
for compatibility.  The public application runtime owns the composition seam
used by ``caretaker.run``; worker health, control, and shutdown internals can
move here incrementally without changing the logging API.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
import signal
from pathlib import Path
from typing import Any

from .logging.supervisor import CaretakerApplicationSupervisor
from .policy import RepairPolicy, validate_policy
from .runtime_supervision import (
    AdaptiveAggregationQueueRegistry,
    ApplicationWorkerLifecycle,
    accept_comparison_worker_result,
    build_authorized_restart_callback,
    bounded_diagnostic_value,
    build_incident_action_handler,
    build_replacement_action_handler,
    build_shutdown_action_handler,
    capture_worker_failure_evidence,
    compare_comparison_worker_result,
    handle_expired_worker_cohort,
    handle_worker_acceptance_observation,
    handle_worker_authority_packet,
    handle_worker_authority_queue_handoff,
    handle_worker_failure,
    handle_worker_failure_cohort,
    handle_worker_replacement_packet,
    handle_worker_replacement_queue_handoff,
    issue_comparison_worker_assignment,
    join_worker_evidence_reconciliations,
    reconcile_worker_failures,
    worker_failure_envelope,
    diagnostic_debug_enabled,
    reconcile_comparison_worker_reports,
    reconcile_adaptive_aggregation_queues,
    Watchdog,
    WorkRegistry,
    WorkerRegistry,
    monitor_application,
    run_supervisor_control_cycle,
    stop_application,
    stop_runtime_supervisor,
)


class ApplicationRuntimeSupervisor:
    """Application-scoped runtime owner with compatibility delegation.

    This class does not add authority or host-level process management.  It
    owns the application-runtime entry point and delegates the existing
    behavior until the implementation internals are extracted from the
    logging package.
    """

    def __init__(
        self,
        runtime: Any,
        *,
        application_pid: int | None = None,
        application_process_group_id: int | None = None,
        application_process: Any | None = None,
        acceptance_store: Any | None = None,
        acceptance_store_path: str | Path | None = None,
        failure_store: Any | None = None,
        repair_policy: RepairPolicy | None = None,
    ) -> None:
        if repair_policy is not None:
            validate_policy(repair_policy)
        self.repair_policy = repair_policy or RepairPolicy()
        self.recovery_policy = self.repair_policy.recovery
        self.rollout_policy = self.repair_policy.rollout
        self._implementation = CaretakerApplicationSupervisor(
            runtime,
            application_pid=application_pid,
            application_process_group_id=application_process_group_id,
            application_process=application_process,
            acceptance_store=acceptance_store,
            acceptance_store_path=acceptance_store_path,
            failure_store=failure_store,
        )

    @property
    def implementation(self) -> CaretakerApplicationSupervisor:
        """Return the compatibility implementation for diagnostics only."""

        return self._implementation

    def start(self) -> None:
        self._implementation.start()

    def stop(self) -> None:
        stop_runtime_supervisor(self._implementation)

    def run_control_cycle(
        self,
        *,
        supervisor_time: datetime | None = None,
        on_expired_workers: Callable[[tuple[Any, ...], datetime], Any] | None = None,
        on_cycle: Callable[[datetime], Any] | None = None,
    ) -> dict[str, Any]:
        """Run the application-owned control cycle through the runtime seam."""
        return run_supervisor_control_cycle(
            self._implementation,
            supervisor_time=supervisor_time,
            on_expired_workers=on_expired_workers,
            on_cycle=on_cycle,
        )

    def capture_worker_failure_evidence(
        self,
        worker: Any,
        *,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[Any, Any], Any] | None = None,
        require_complete_postmortem: bool = False,
        reconciliation_scope: str | None = None,
    ) -> dict[str, Any]:
        """Persist one rollback envelope through the runtime seam."""
        return capture_worker_failure_evidence(
            self._implementation,
            worker,
            diagnostic_debug=diagnostic_debug,
            critical_evidence=critical_evidence,
            collect_postmortem=collect_postmortem,
            require_complete_postmortem=require_complete_postmortem,
            reconciliation_scope=reconciliation_scope,
        )

    @staticmethod
    def diagnostic_debug_enabled() -> bool:
        """Return whether controlled diagnostic detail is enabled."""
        return diagnostic_debug_enabled()

    @staticmethod
    def bounded_diagnostic_value(value: Any, *, depth: int = 0) -> Any:
        """Return bounded JSON-shaped diagnostic detail."""
        return bounded_diagnostic_value(value, depth=depth)

    @staticmethod
    def worker_failure_envelope(worker: Any, *, diagnostic_debug: bool | None = None) -> dict[str, Any]:
        """Build a bounded worker failure envelope through the runtime seam."""
        return worker_failure_envelope(worker, diagnostic_debug=diagnostic_debug)

    def handle_worker_failure_cohort(
        self,
        workers: Iterable[Any],
        *,
        scope: str,
        recovery_policy: Any,
        recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[Any, Any], Any] | None = None,
        require_complete_postmortem: bool = False,
        minimum_sample_count: int = 30,
        z_threshold: float = 3.0,
    ) -> dict[str, Any]:
        """Handle a failed-worker cohort through the runtime seam."""
        return handle_worker_failure_cohort(
            self._implementation,
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

    def handle_worker_failure(
        self,
        worker: Any,
        *,
        policy: Any,
        create_incident: Callable[[Mapping[str, Any]], Any] | None = None,
        restart_worker: Callable[[Any], Any] | None = None,
        disable_component: Callable[[Any], Any] | None = None,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[Any, Any], Any] | None = None,
        require_complete_postmortem: bool = False,
        reconciliation_scope: str | None = None,
    ) -> dict[str, Any]:
        """Handle one failed worker through the runtime seam."""
        return handle_worker_failure(
            self._implementation,
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
        recovery_policy: Any | None = None,
        recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
    ) -> dict[str, Any]:
        """Reconcile worker failures through the runtime seam."""
        return reconcile_worker_failures(
            self._implementation,
            scope=scope,
            minimum_sample_count=minimum_sample_count,
            z_threshold=z_threshold,
            observed_at=observed_at,
            recovery_policy=recovery_policy,
            recovery_handlers=recovery_handlers,
        )

    def build_replacement_action_handler(self, **kwargs: Any) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        """Build a packet-verified replacement handler through the runtime seam."""
        return build_replacement_action_handler(self._implementation, **kwargs)

    @staticmethod
    def build_incident_action_handler(create_incident: Callable[[Mapping[str, Any]], Any]) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        """Build an incident action adapter through the runtime seam."""
        return build_incident_action_handler(create_incident)

    def build_authorized_restart_callback(self, **kwargs: Any) -> Callable[[Any], dict[str, Any]]:
        """Build a packet-verified restart callback through the runtime seam."""
        return build_authorized_restart_callback(self._implementation, **kwargs)

    def build_shutdown_action_handler(self, stop_application: Callable[[Mapping[str, Any]], Any] | None = None) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
        """Build a shutdown action adapter through the runtime seam."""
        return build_shutdown_action_handler(self._implementation, stop_application)

    def issue_comparison_worker_assignment(self, *args: Any, **kwargs: Any) -> Any:
        """Issue a bounded comparison assignment through the runtime seam."""
        return issue_comparison_worker_assignment(self._implementation, *args, **kwargs)

    def accept_comparison_worker_result(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Accept a packet-bound comparison result through the runtime seam."""
        return accept_comparison_worker_result(self._implementation, *args, **kwargs)

    def compare_comparison_worker_result(self, *args: Any, **kwargs: Any) -> Any:
        """Compare comparison-worker evidence through the runtime seam."""
        return compare_comparison_worker_result(self._implementation, *args, **kwargs)

    def reconcile_comparison_worker_reports(self, *args: Any, **kwargs: Any) -> Any:
        """Reconcile comparison reports through the runtime seam."""
        return reconcile_comparison_worker_reports(self._implementation, *args, **kwargs)

    def join_worker_evidence_reconciliations(self, *args: Any, **kwargs: Any) -> Any:
        """Join worker evidence through the runtime seam."""
        return join_worker_evidence_reconciliations(self._implementation, *args, **kwargs)

    def handle_worker_acceptance_observation(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Handle a worker acceptance observation through the runtime seam."""
        return handle_worker_acceptance_observation(self._implementation, *args, **kwargs)

    def handle_worker_authority_packet(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Admit or refresh a worker authority packet through the runtime seam."""
        return handle_worker_authority_packet(self._implementation, *args, **kwargs)

    def handle_worker_authority_queue_handoff(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Handle an authority queue handoff through the runtime seam."""
        return handle_worker_authority_queue_handoff(self._implementation, *args, **kwargs)

    def handle_worker_replacement_packet(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Admit a worker replacement packet through the runtime seam."""
        return handle_worker_replacement_packet(self._implementation, *args, **kwargs)

    def handle_worker_replacement_queue_handoff(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Handle a replacement queue handoff through the runtime seam."""
        return handle_worker_replacement_queue_handoff(self._implementation, *args, **kwargs)

    def reconcile_adaptive_aggregation_queues(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Reconcile adaptive aggregation queues through the runtime seam."""
        return reconcile_adaptive_aggregation_queues(self._implementation, *args, **kwargs)

    def handle_expired_worker_cohort(
        self,
        workers: Iterable[Any],
        *,
        supervisor_time: datetime,
        scope: str,
        recovery_policy: Any,
        recovery_handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]] | None = None,
        diagnostic_debug: bool | None = None,
        critical_evidence: bool = False,
        collect_postmortem: Callable[[Any, Any], Any] | None = None,
        require_complete_postmortem: bool = False,
        minimum_sample_count: int = 30,
        z_threshold: float = 3.0,
    ) -> dict[str, Any]:
        """Handle expired workers through the runtime seam."""
        return handle_expired_worker_cohort(
            self._implementation,
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

    def monitor_application(
        self,
        *,
        interval_seconds: float = 1.0,
        on_expired_workers: Callable[[tuple[Any, ...], datetime], Any] | None = None,
        on_cycle: Callable[[datetime], Any] | None = None,
    ) -> None:
        """Monitor the application boundary through the runtime seam."""
        return monitor_application(
            self._implementation,
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
        """Stop the application boundary through the runtime seam."""
        return stop_application(
            self._implementation,
            graceful_signal=graceful_signal,
            timeout_seconds=timeout_seconds,
        )

    def __getattr__(self, name: str) -> Any:
        # Compatibility for the existing run/control code while ownership is
        # extracted method-by-method. Private implementation details are not
        # exposed through this path.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._implementation, name)


__all__ = [
    "AdaptiveAggregationQueueRegistry",
    "ApplicationWorkerLifecycle",
    "ApplicationRuntimeSupervisor",
    "Watchdog",
    "WorkRegistry",
    "WorkerRegistry",
]
