from __future__ import annotations

import caretaker.decorators.api as decorator_api
from caretaker import (
    LoggingBinding,
    RepairAuthority,
    RepairEngine,
    RepairMode,
    RepairPolicy,
    StaticRepairProvider,
    caretaker,
)


class _RecordingRuntime:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def event(self, **kwargs) -> None:
        self.events.append(kwargs)


def test_repair_logging_uses_function_version_number(monkeypatch) -> None:
    runtime = _RecordingRuntime()
    monkeypatch.setattr(decorator_api, "get_logging_runtime", lambda: runtime)

    policy = RepairPolicy(
        logging=LoggingBinding(enabled=True, capture_calls=True),
        mode=RepairMode.DIAGNOSE,
        authority=RepairAuthority.ANALYZE_ONLY,
    )
    engine = RepairEngine(provider=StaticRepairProvider(()))

    @caretaker(policy=policy, engine=engine, target_id="test.logging-version")
    def sample(value: int) -> int:
        return value + 1

    assert sample(4) == 5
    assert len(runtime.events) == 2
    assert runtime.events[0]["function_version"] == 0
    assert runtime.events[0]["fields"]["function_version"] == 0
    assert runtime.events[1]["function_version"] == 0
    assert runtime.events[1]["fields"]["function_version"] == 0
