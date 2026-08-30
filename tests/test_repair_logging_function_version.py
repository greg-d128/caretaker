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


def test_repair_logging_captures_bounded_result_without_call_capture(monkeypatch) -> None:
    runtime = _RecordingRuntime()
    monkeypatch.setattr(decorator_api, "get_logging_runtime", lambda: runtime)

    policy = RepairPolicy(
        logging=LoggingBinding(
            enabled=True,
            capture_calls=False,
            capture_results=True,
        ),
        mode=RepairMode.DIAGNOSE,
        authority=RepairAuthority.ANALYZE_ONLY,
    )
    engine = RepairEngine(provider=StaticRepairProvider(()))

    @caretaker(policy=policy, engine=engine, target_id="test.logging-result")
    def sample() -> str:
        return "x" * 1000

    assert sample() == "x" * 1000
    assert len(runtime.events) == 1
    result = runtime.events[0]["fields"]["result"]
    assert result["type_name"] == "builtins.str"
    assert len(result["representation"]) == 513
    assert result["truncated"] is True
    assert result["value_hash"]
