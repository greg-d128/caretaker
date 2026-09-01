from __future__ import annotations

from caretaker import ApplicationRuntimeSupervisor
from caretaker.logging.supervisor import CaretakerApplicationSupervisor


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
