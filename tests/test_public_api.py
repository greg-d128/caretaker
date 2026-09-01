import caretaker


def test_package_root_public_inventory_resolves_without_duplicates() -> None:
    names = caretaker.__all__

    assert len(names) == len(set(names))
    assert all(isinstance(name, str) and name for name in names)
    assert all(hasattr(caretaker, name) for name in names)


def test_runtime_supervisor_compatibility_exports_keep_runtime_ownership() -> None:
    from caretaker.logging import ApplicationWorkerLifecycle as LoggingLifecycle
    from caretaker.logging import Watchdog as LoggingWatchdog
    from caretaker.logging import WorkRegistry as LoggingWorkRegistry
    from caretaker.runtime_supervision import (
        ApplicationWorkerLifecycle,
        Watchdog,
        WorkRegistry,
    )

    assert LoggingLifecycle is ApplicationWorkerLifecycle
    assert LoggingWatchdog is Watchdog
    assert LoggingWorkRegistry is WorkRegistry
