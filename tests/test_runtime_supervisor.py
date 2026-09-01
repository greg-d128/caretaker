from __future__ import annotations

from caretaker import ApplicationRuntimeSupervisor
from caretaker.logging.supervisor import CaretakerApplicationSupervisor
from caretaker.logging import Watchdog as LoggingWatchdog
from caretaker.logging import WorkRegistry as LoggingWorkRegistry
from caretaker.runtime_supervision import (
    AdaptiveAggregationQueueRegistry,
    Watchdog,
    WorkRegistry,
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


def test_runtime_queue_registry_is_owned_outside_logging() -> None:
    assert AdaptiveAggregationQueueRegistry.__module__ == "caretaker.runtime_supervision"
