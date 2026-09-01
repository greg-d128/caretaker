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
