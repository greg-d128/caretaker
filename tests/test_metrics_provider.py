from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from caretaker import (
    MetricSample,
    MetricsContext,
    MetricsCorrelation,
    MetricsCollector,
    MonitoringDialect,
    MonitoringStreamPolicy,
    MonitoringStreamWriter,
    ProcessMetricsProvider,
)
from caretaker.logging.policy import (
    MetricsBinding,
    OperatorLoggingPolicy,
    validate_operator_logging_policy,
)


class _StaticMetricsProvider:
    provider_name = "process"

    def __init__(self, samples):
        self.samples = tuple(samples)
        self.started = False

    def start(self, context):
        self.started = True

    def stop(self):
        self.started = False

    def query(self, start, end):
        return self.samples


def _fake_proc_process(root, pid: int = 1234):
    process = root / str(pid)
    process.mkdir()
    stat_fields = ["S"] + ["0"] * 20
    stat_fields[11] = "200"
    stat_fields[12] = "50"
    stat_fields[17] = "4"
    (process / "stat").write_text(
        f"{pid} (worker with spaces) " + " ".join(stat_fields),
        encoding="utf-8",
    )
    (process / "status").write_text(
        "Name:\tworker\nVmRSS:\t12 kB\nVmSize:\t64 kB\n",
        encoding="utf-8",
    )
    (process / "io").write_text(
        "read_bytes: 7\nwrite_bytes: 8\n",
        encoding="utf-8",
    )
    return process


def test_process_metrics_provider_collects_bounded_process_snapshot(tmp_path) -> None:
    _fake_proc_process(tmp_path)
    provider = ProcessMetricsProvider(proc_root=tmp_path)
    provider.start(MetricsContext(application_id="payments", process_id=1234))

    now = datetime.now(timezone.utc)
    samples = provider.query(now - timedelta(seconds=2), now + timedelta(seconds=2))

    values = {sample.name: sample.value for sample in samples}
    assert values["caretaker.process.cpu_user_seconds"] == pytest.approx(2.0)
    assert values["caretaker.process.cpu_system_seconds"] == pytest.approx(0.5)
    assert values["caretaker.process.thread_count"] == pytest.approx(4.0)
    assert values["caretaker.process.rss_bytes"] == pytest.approx(12 * 1024)
    assert values["caretaker.process.virtual_memory_bytes"] == pytest.approx(64 * 1024)
    assert values["caretaker.process.read_bytes"] == pytest.approx(7.0)
    assert values["caretaker.process.write_bytes"] == pytest.approx(8.0)
    assert all(
        dict(sample.dimensions)
        == {"application_id": "payments", "process_id": "1234"}
        for sample in samples
    )


def test_process_metrics_provider_treats_missing_sources_as_unavailable(tmp_path) -> None:
    process = _fake_proc_process(tmp_path)
    (process / "io").unlink()
    provider = ProcessMetricsProvider(proc_root=tmp_path, include_io=True)
    provider.start(MetricsContext(application_id="payments", process_id=1234))

    now = datetime.now(timezone.utc)
    names = {sample.name for sample in provider.query(now - timedelta(seconds=1), now + timedelta(seconds=1))}

    assert "caretaker.process.cpu_user_seconds" in names
    assert "caretaker.process.read_bytes" not in names
    assert "caretaker.process.write_bytes" not in names


def test_process_metrics_provider_requires_active_context_and_valid_window(tmp_path) -> None:
    provider = ProcessMetricsProvider(proc_root=tmp_path)
    now = datetime.now(timezone.utc)
    assert provider.query(now - timedelta(seconds=1), now + timedelta(seconds=1)) == ()

    with pytest.raises(ValueError, match="must include timezone"):
        provider.query(datetime.now(), now)
    with pytest.raises(ValueError, match="must not be after"):
        provider.query(now + timedelta(seconds=1), now)

    provider.start(MetricsContext(application_id="payments", process_id=1234))
    assert provider.query(now - timedelta(seconds=10), now - timedelta(seconds=5)) == ()
    provider.stop()
    assert provider.query(now - timedelta(seconds=1), now + timedelta(seconds=1)) == ()


def test_monitoring_writer_publishes_provider_samples_through_bounds(tmp_path) -> None:
    writer = MonitoringStreamWriter(
        MonitoringStreamPolicy(enabled=True, dialect=MonitoringDialect.JSON_LINES),
        directory=tmp_path,
        application_id="payments",
        run_id="run-1",
        process_start_id="process-1",
    )
    occurred_at = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
    records = writer.emit_samples(
        [
            MetricSample(
                "caretaker.process.rss_bytes",
                occurred_at,
                12 * 1024,
                "bytes",
                (("process_id", "1234"),),
            )
        ]
    )
    writer.close()

    assert len(records) == 1
    parsed = json.loads((tmp_path / "caretaker_monitoring.log").read_text())
    assert parsed["metric"] == "caretaker.process.rss_bytes"
    assert parsed["dimensions"] == {"process_id": "1234"}


def test_metrics_collector_adds_bounded_evidence_correlations_and_applies_cadence(tmp_path) -> None:
    writer = MonitoringStreamWriter(
        MonitoringStreamPolicy(enabled=True, dialect=MonitoringDialect.JSON_LINES),
        directory=tmp_path,
        application_id="payments",
        run_id="run-1",
        process_start_id="process-1",
    )
    occurred_at = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
    provider = _StaticMetricsProvider(
        [MetricSample("caretaker.process.rss_bytes", occurred_at, 12 * 1024, "bytes", (("process_id", "1234"),))]
    )
    current = [occurred_at]
    collector = MetricsCollector(
        MetricsBinding(
            enabled=True,
            provider_name="process",
            sample_interval_seconds=5.0,
            correlate_by_call=True,
        ),
        writer=writer,
        context=MetricsContext(application_id="payments", process_id=1234),
        provider=provider,
        clock=lambda: current[0],
    )

    first = collector.collect(
        occurred_at,
        occurred_at,
        correlation=MetricsCorrelation(
            target_id="payments:checkout",
            call_id="call-1",
            incident_id="incident-1",
            guard_window_id="guard-1",
            baseline_id="baseline-1",
        ),
    )
    second = collector.collect(occurred_at, occurred_at)
    current[0] = occurred_at + timedelta(seconds=5)
    third = collector.collect(occurred_at, current[0])
    writer.close()

    assert len(first) == 1
    assert second == ()
    assert len(third) == 1
    assert json.loads((tmp_path / "caretaker_monitoring.log").read_text().splitlines()[0])["dimensions"] == {
        "baseline_id": "baseline-1",
        "call_id": "call-1",
        "guard_window_id": "guard-1",
        "incident_id": "incident-1",
        "process_id": "1234",
        "target_id": "payments:checkout",
    }
    assert collector.status()["skipped_count"] == 1


def test_metrics_collector_honors_correlation_privacy_settings(tmp_path) -> None:
    writer = MonitoringStreamWriter(
        MonitoringStreamPolicy(enabled=True, dialect=MonitoringDialect.JSON_LINES),
        directory=tmp_path,
        application_id="payments",
        run_id="run-1",
        process_start_id="process-1",
    )
    occurred_at = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)
    collector = MetricsCollector(
        MetricsBinding(
            enabled=True,
            provider_name="process",
            correlate_by_process=False,
            correlate_by_call=True,
            correlate_by_target=False,
            correlate_by_incident=False,
            correlate_by_guard_window=False,
            correlate_by_baseline=False,
        ),
        writer=writer,
        context=MetricsContext(application_id="payments", process_id=1234),
        provider=_StaticMetricsProvider(
            [MetricSample("caretaker.process.rss_bytes", occurred_at, 1, "bytes", (("process_id", "1234"),))]
        ),
        clock=lambda: occurred_at,
    )
    collector.collect(
        occurred_at,
        occurred_at,
        correlation=MetricsCorrelation(
            target_id="target",
            call_id="call",
            incident_id="incident",
            guard_window_id="guard",
            baseline_id="baseline",
        ),
    )
    writer.close()

    parsed = json.loads((tmp_path / "caretaker_monitoring.log").read_text())
    assert parsed["dimensions"] == {"call_id": "call"}


def test_metrics_policy_requires_monitoring_and_supported_bounds(tmp_path) -> None:
    base = OperatorLoggingPolicy.application_defaults(
        directory=str(tmp_path), application_id="payments"
    )
    with pytest.raises(ValueError, match="requires logging.monitoring"):
        validate_operator_logging_policy(replace(base, metrics=MetricsBinding(enabled=True)))
    with pytest.raises(ValueError, match="provider_name"):
        validate_operator_logging_policy(
            replace(
                base,
                metrics=MetricsBinding(enabled=True, provider_name="unknown"),
                monitoring=MonitoringStreamPolicy(enabled=True),
            )
        )
