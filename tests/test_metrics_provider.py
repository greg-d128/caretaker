from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from caretaker import (
    MetricSample,
    MetricsContext,
    MonitoringDialect,
    MonitoringStreamPolicy,
    MonitoringStreamWriter,
    ProcessMetricsProvider,
)


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
