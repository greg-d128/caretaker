from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from caretaker import (
    MonitoringDialect,
    MonitoringStreamError,
    MonitoringStreamPolicy,
    MonitoringStreamWriter,
    OperatorLoggingPolicy,
)
from caretaker.logging.metrics import MetricsCorrelation
from caretaker.logging.policy import MetricsBinding
from caretaker.logging.handler import LoggingRuntime
from caretaker.logging.policy import load_operator_policy


def _writer(tmp_path, dialect: MonitoringDialect) -> MonitoringStreamWriter:
    return MonitoringStreamWriter(
        MonitoringStreamPolicy(enabled=True, dialect=dialect),
        directory=tmp_path,
        application_id="payments",
        run_id="run-1",
        process_start_id="process-1",
    )


def test_monitoring_stream_is_disabled_by_default(tmp_path) -> None:
    writer = MonitoringStreamWriter(
        MonitoringStreamPolicy(),
        directory=tmp_path,
        application_id="payments",
        run_id="run-1",
        process_start_id="process-1",
    )

    assert writer.emit("caretaker.test", 1) is None
    writer.close()
    assert not (tmp_path / "caretaker_monitoring.log").exists()


@pytest.mark.parametrize("dialect", list(MonitoringDialect))
def test_monitoring_stream_renders_supported_dialects(tmp_path, dialect) -> None:
    writer = _writer(tmp_path, dialect)
    record = writer.emit(
        "caretaker.test.value",
        1.5,
        unit="seconds",
        dimensions={"region": "us-east"},
        timestamp=datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc),
    )
    writer.close()

    assert record is not None
    line = (tmp_path / "caretaker_monitoring.log").read_text().strip()
    assert line
    if dialect is MonitoringDialect.JSON_LINES:
        parsed = json.loads(line)
        assert parsed["metric"] == "caretaker.test.value"
        assert parsed["dimensions"] == {"region": "us-east"}
    elif dialect is MonitoringDialect.DATADOG:
        assert line.startswith("caretaker.test.value:1.5|g|#")
        assert "region:us-east" in line
    elif dialect is MonitoringDialect.SPLUNK_HEC:
        parsed = json.loads(line)
        assert parsed["sourcetype"] == "caretaker:metric"
        assert parsed["event"]["metric"] == "caretaker.test.value"
    else:
        parsed = json.loads(line)
        assert parsed["metrics"][0]["name"] == "caretaker.test.value"
        assert parsed["common"]["attributes"]["application_id"] == "payments"


def test_monitoring_stream_publishes_overhead_snapshot(tmp_path) -> None:
    writer = _writer(tmp_path, MonitoringDialect.JSON_LINES)
    records = writer.emit_overhead(
        {
            "scope": "caretaker_logging",
            "write_calls": 3,
            "accepted_records": 2,
            "queue_utilization": 0.25,
            "last_error": "not a metric",
        }
    )
    writer.close()

    assert {item["metric"] for item in records} == {
        "caretaker.logging.write_calls",
        "caretaker.logging.accepted_records",
        "caretaker.logging.queue_utilization",
    }
    assert len((tmp_path / "caretaker_monitoring.log").read_text().splitlines()) == 3


def test_logging_runtime_emits_overhead_to_enabled_monitoring_stream(tmp_path) -> None:
    runtime = LoggingRuntime(
        OperatorLoggingPolicy(
            directory=str(tmp_path),
            monitoring=MonitoringStreamPolicy(enabled=True),
        ),
        supervised=True,
    )
    try:
        runtime.event(
            logger_name="test.monitoring",
            severity=20,
            channel=__import__("caretaker.logging.models", fromlist=["LogChannel"]).LogChannel.APPLICATION,
            message="monitoring probe",
        )
        status = runtime.overhead_status()
    finally:
        runtime.close()

    assert status["accepted_records"] >= 1
    lines = (tmp_path / "caretaker_monitoring.log").read_text().splitlines()
    assert any("caretaker.logging.accepted_records" in line for line in lines)


def test_logging_runtime_exposes_policy_controlled_process_metrics(tmp_path) -> None:
    runtime = LoggingRuntime(
        OperatorLoggingPolicy(
            directory=str(tmp_path),
            monitoring=MonitoringStreamPolicy(enabled=True),
            metrics=MetricsBinding(enabled=True),
        ),
        supervised=True,
    )
    try:
        now = datetime.now(timezone.utc)
        records = runtime.collect_metrics(
            now - timedelta(seconds=2),
            now + timedelta(seconds=2),
            correlation=MetricsCorrelation(target_id="payments:checkout"),
        )
        status = runtime.metrics_status()
    finally:
        runtime.close()

    assert records
    assert status["enabled"] is True
    assert status["provider"] == "process"
    assert any(
        json.loads(line)["metric"].startswith("caretaker.process.")
        for line in (tmp_path / "caretaker_monitoring.log").read_text().splitlines()
    )


def test_monitoring_policy_loads_from_toml(tmp_path) -> None:
    policy_file = tmp_path / "caretaker.toml"
    policy_file.write_text(
        """
[logging]
directory = "./data"

[logging.monitoring]
enabled = true
dialect = "splunk_hec"
file_name = "metrics.log"
maximum_record_bytes = 2048
""",
        encoding="utf-8",
    )

    policy, _snapshot = load_operator_policy(policy_file)

    assert policy.monitoring == MonitoringStreamPolicy(
        enabled=True,
        dialect=MonitoringDialect.SPLUNK_HEC,
        file_name="metrics.log",
        maximum_record_bytes=2048,
    )


def test_monitoring_stream_rejects_unbounded_or_unsafe_values(tmp_path) -> None:
    with pytest.raises(ValueError, match="below logging.directory"):
        MonitoringStreamPolicy(enabled=True, file_name="../metrics.log")

    writer = _writer(tmp_path, MonitoringDialect.JSON_LINES)
    with pytest.raises(MonitoringStreamError, match="finite"):
        writer.emit("caretaker.test", float("nan"))
    with pytest.raises(MonitoringStreamError, match="dimension name"):
        writer.emit("caretaker.test", 1, dimensions={"bad key": "value"})
    writer.close()
