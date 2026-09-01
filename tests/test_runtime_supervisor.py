from __future__ import annotations

from caretaker import ApplicationRuntimeSupervisor
from caretaker.logging.supervisor import CaretakerApplicationSupervisor
from caretaker.logging import Watchdog as LoggingWatchdog
from caretaker.logging import WorkRegistry as LoggingWorkRegistry
from caretaker.runtime_supervision import (
    AdaptiveAggregationQueueRegistry,
    ApplicationWorkerLifecycle,
    Watchdog,
    WorkRegistry,
    WorkerRegistry,
)


class _Runtime:
    def close(self) -> None:
        pass


def test_application_runtime_supervisor_owns_compatibility_composition() -> None:
    runtime = _Runtime()
    supervisor = ApplicationRuntimeSupervisor(runtime)

    assert isinstance(supervisor.implementation, CaretakerApplicationSupervisor)
    assert supervisor.runtime is runtime
    assert supervisor.workers is supervisor.implementation.workers


def test_application_runtime_supervisor_preserves_start_stop_surface() -> None:
    supervisor = ApplicationRuntimeSupervisor(_Runtime())

    supervisor.start()
    try:
        assert supervisor.watchdog is supervisor.implementation.watchdog
    finally:
        supervisor.stop()


def test_runtime_scheduling_and_watchdog_are_owned_outside_logging() -> None:
    assert WorkRegistry.__module__ == "caretaker.runtime_supervision"
    assert Watchdog.__module__ == "caretaker.runtime_supervision"
    assert LoggingWorkRegistry is WorkRegistry
    assert LoggingWatchdog is Watchdog


def test_logging_worker_registry_wraps_application_owned_implementation() -> None:
    from caretaker.logging import WorkerRegistry as LoggingWorkerRegistry

    assert issubclass(LoggingWorkerRegistry, WorkerRegistry)
    assert LoggingWorkerRegistry.__module__ == "caretaker.logging.supervisor"


def test_runtime_queue_registry_is_owned_outside_logging() -> None:
    assert AdaptiveAggregationQueueRegistry.__module__ == "caretaker.runtime_supervision"


def test_runtime_worker_registry_is_owned_outside_logging() -> None:
    assert WorkerRegistry.__module__ == "caretaker.runtime_supervision"


def test_runtime_worker_lifecycle_is_owned_outside_logging() -> None:
    from caretaker.logging import ApplicationWorkerLifecycle as LoggingWorkerLifecycle

    assert ApplicationWorkerLifecycle.__module__ == "caretaker.runtime_supervision"
    assert LoggingWorkerLifecycle is ApplicationWorkerLifecycle


def test_application_runtime_supervisor_exposes_control_cycle_owner() -> None:
    supervisor = ApplicationRuntimeSupervisor(_Runtime())
    result = supervisor.run_control_cycle()

    assert result["ok"] is True
    assert result["authority_granted"] is False


def test_runtime_boundary_functions_are_application_owned() -> None:
    from caretaker.runtime_supervision import (
        monitor_application,
        capture_worker_failure_evidence,
        handle_expired_worker_cohort,
        handle_worker_failure,
        handle_worker_failure_cohort,
        reconcile_worker_failures,
        accept_comparison_worker_result,
        compare_comparison_worker_result,
        issue_comparison_worker_assignment,
        join_worker_evidence_reconciliations,
        reconcile_comparison_worker_reports,
        handle_worker_acceptance_observation,
        handle_worker_authority_packet,
        handle_worker_authority_queue_handoff,
        handle_worker_replacement_packet,
        handle_worker_replacement_queue_handoff,
        build_authorized_restart_callback,
        build_replacement_action_handler,
        stop_application,
        stop_runtime_supervisor,
    )

    assert monitor_application.__module__ == "caretaker.runtime_supervision"
    assert capture_worker_failure_evidence.__module__ == "caretaker.runtime_supervision"
    assert handle_expired_worker_cohort.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_failure.__module__ == "caretaker.runtime_supervision"
    assert reconcile_worker_failures.__module__ == "caretaker.runtime_supervision"
    assert accept_comparison_worker_result.__module__ == "caretaker.runtime_supervision"
    assert compare_comparison_worker_result.__module__ == "caretaker.runtime_supervision"
    assert issue_comparison_worker_assignment.__module__ == "caretaker.runtime_supervision"
    assert join_worker_evidence_reconciliations.__module__ == "caretaker.runtime_supervision"
    assert reconcile_comparison_worker_reports.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_acceptance_observation.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_authority_packet.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_authority_queue_handoff.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_replacement_packet.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_replacement_queue_handoff.__module__ == "caretaker.runtime_supervision"
    assert build_authorized_restart_callback.__module__ == "caretaker.runtime_supervision"
    assert build_replacement_action_handler.__module__ == "caretaker.runtime_supervision"
    assert handle_worker_failure_cohort.__module__ == "caretaker.runtime_supervision"
    assert stop_application.__module__ == "caretaker.runtime_supervision"
    assert stop_runtime_supervisor.__module__ == "caretaker.runtime_supervision"
