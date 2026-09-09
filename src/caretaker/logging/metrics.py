from __future__ import annotations

import json
import math
import os
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID

from ..rooted_io import RootedFilesystem

MONITORING_STREAM_SCHEMA_VERSION = 1
_METRIC_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
_DIMENSION_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")


class MonitoringStreamError(ValueError):
    """Raised when a monitoring record cannot be safely serialized."""


class MonitoringDialect(str, Enum):
    """Wire formats for the output-only monitoring stream."""

    JSON_LINES = "JSON_LINES"
    DATADOG = "DATADOG"
    SPLUNK_HEC = "SPLUNK_HEC"
    NEW_RELIC = "NEW_RELIC"


@dataclass(frozen=True, slots=True)
class MonitoringStreamPolicy:
    """Policy for the optional local monitoring stream.

    The stream is disabled by default.  It is an output-only file intended for
    a local collector; it never accepts commands or feeds policy decisions.
    """

    enabled: bool = False
    file_name: str = "caretaker_monitoring.log"
    dialect: MonitoringDialect = MonitoringDialect.JSON_LINES
    maximum_record_bytes: int = 4096

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("monitoring.enabled must be a boolean")
        if not isinstance(self.file_name, str) or not self.file_name.strip():
            raise ValueError("monitoring.file_name must be a non-empty string")
        path = Path(self.file_name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("monitoring.file_name must remain below logging.directory")
        if not isinstance(self.dialect, MonitoringDialect):
            try:
                object.__setattr__(self, "dialect", MonitoringDialect(str(self.dialect).upper()))
            except ValueError as exc:
                raise ValueError("monitoring.dialect is unsupported") from exc
        if (
            isinstance(self.maximum_record_bytes, bool)
            or not isinstance(self.maximum_record_bytes, int)
            or not 512 <= self.maximum_record_bytes <= 65_536
        ):
            raise ValueError(
                "monitoring.maximum_record_bytes must be between 512 and 65536"
            )


@dataclass(frozen=True, slots=True)
class MetricSample:
    name: str
    timestamp: datetime
    value: float
    unit: str | None = None
    dimensions: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class MetricsContext:
    application_id: str
    process_id: int


@dataclass(frozen=True, slots=True)
class MetricsCorrelation:
    """Optional evidence identifiers attached to one metrics snapshot.

    These are identifiers only.  The collector never reads their referenced
    records and never treats a metric as policy, approval, or authority input.
    Keeping the correlation contract here lets Guard, incident, and baseline
    producers use the same bounded monitoring dimensions without coupling the
    metrics provider to those subsystems.
    """

    target_id: str | None = None
    call_id: str | None = None
    incident_id: UUID | str | None = None
    guard_window_id: UUID | str | None = None
    baseline_id: UUID | str | None = None


class MetricsProvider(Protocol):
    @property
    def provider_name(self) -> str: ...
    def start(self, context: MetricsContext) -> None: ...
    def stop(self) -> None: ...
    def query(self, start: datetime, end: datetime) -> tuple[MetricSample, ...]: ...


class NullMetricsProvider:
    provider_name = "null"

    def start(self, context: MetricsContext) -> None:
        return None

    def stop(self) -> None:
        return None

    def query(self, start: datetime, end: datetime) -> tuple[MetricSample, ...]:
        return ()


class ProcessMetricsProvider:
    """Collect a bounded, non-privileged snapshot for one process.

    The provider reads only process-scoped procfs files and treats unavailable
    optional sources as absent samples. It never escalates privileges or
    interprets a missing source as proof that the process had no activity.
    ``query`` returns a point-in-time snapshot when that instant falls inside
    the requested interval; historical storage remains the collector's job.
    """

    provider_name = "process"

    def __init__(
        self,
        *,
        proc_root: str | Path = "/proc",
        include_io: bool = True,
    ) -> None:
        if not isinstance(include_io, bool):
            raise ValueError("include_io must be a boolean")
        self.proc_root = Path(proc_root)
        self.include_io = include_io
        self._context: MetricsContext | None = None
        try:
            self._clock_ticks = int(os.sysconf("SC_CLK_TCK"))
        except (AttributeError, OSError, ValueError):
            self._clock_ticks = 100
        if self._clock_ticks <= 0:
            self._clock_ticks = 100

    def start(self, context: MetricsContext) -> None:
        if not isinstance(context, MetricsContext):
            raise TypeError("metrics context must be a MetricsContext")
        if isinstance(context.process_id, bool) or not isinstance(context.process_id, int):
            raise ValueError("metrics context process_id must be an integer")
        if context.process_id <= 0:
            raise ValueError("metrics context process_id must be positive")
        self._context = context

    def stop(self) -> None:
        self._context = None

    def query(self, start: datetime, end: datetime) -> tuple[MetricSample, ...]:
        for value, label in ((start, "start"), (end, "end")):
            if value.tzinfo is None:
                raise ValueError(f"metrics query {label} must include timezone")
        if start > end:
            raise ValueError("metrics query start must not be after end")
        context = self._context
        if context is None:
            return ()
        occurred_at = datetime.now(timezone.utc)
        if not start.astimezone(timezone.utc) <= occurred_at <= end.astimezone(timezone.utc):
            return ()
        process_root = self.proc_root / str(context.process_id)
        dimensions = (
            ("application_id", str(context.application_id)),
            ("process_id", str(context.process_id)),
        )
        samples: list[MetricSample] = []
        stat_values = self._read_stat(process_root / "stat")
        if stat_values is not None:
            user_ticks, system_ticks, thread_count = stat_values
            samples.extend(
                (
                    MetricSample(
                        "caretaker.process.cpu_user_seconds",
                        occurred_at,
                        user_ticks / self._clock_ticks,
                        "seconds",
                        dimensions,
                    ),
                    MetricSample(
                        "caretaker.process.cpu_system_seconds",
                        occurred_at,
                        system_ticks / self._clock_ticks,
                        "seconds",
                        dimensions,
                    ),
                    MetricSample(
                        "caretaker.process.thread_count",
                        occurred_at,
                        float(thread_count),
                        "count",
                        dimensions,
                    ),
                )
            )
        status_values = self._read_status(process_root / "status")
        for name, value, unit in (
            ("caretaker.process.rss_bytes", status_values.get("VmRSS"), "bytes"),
            ("caretaker.process.virtual_memory_bytes", status_values.get("VmSize"), "bytes"),
        ):
            if value is not None:
                samples.append(MetricSample(name, occurred_at, float(value), unit, dimensions))
        if self.include_io:
            for key, name in (
                ("read_bytes", "caretaker.process.read_bytes"),
                ("write_bytes", "caretaker.process.write_bytes"),
            ):
                value = self._read_io(process_root / "io", key)
                if value is not None:
                    samples.append(MetricSample(name, occurred_at, float(value), "bytes", dimensions))
        return tuple(samples)

    @staticmethod
    def _read_stat(path: Path) -> tuple[int, int, int] | None:
        try:
            raw = path.read_text(encoding="utf-8")
            closing = raw.rfind(") ")
            if closing < 0:
                return None
            fields = raw[closing + 2 :].split()
            if len(fields) <= 17:
                return None
            user_ticks = int(fields[11])
            system_ticks = int(fields[12])
            thread_count = int(fields[17])
            if min(user_ticks, system_ticks, thread_count) < 0:
                return None
            return user_ticks, system_ticks, thread_count
        except (OSError, UnicodeError, ValueError):
            return None

    @staticmethod
    def _read_status(path: Path) -> dict[str, int]:
        values: dict[str, int] = {}
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return values
        for line in lines:
            name, separator, raw = line.partition(":")
            if not separator:
                continue
            fields = raw.strip().split()
            if not fields:
                continue
            try:
                value = int(fields[0])
            except ValueError:
                continue
            if value < 0:
                continue
            if name in {"VmRSS", "VmSize"} and len(fields) >= 2 and fields[1].lower() == "kb":
                value *= 1024
            if name in {"VmRSS", "VmSize", "Threads"}:
                values[name] = value
        return values

    @staticmethod
    def _read_io(path: Path, key: str) -> int | None:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return None
        for line in lines:
            name, separator, raw = line.partition(":")
            if separator and name.strip() == key:
                try:
                    value = int(raw.strip())
                except ValueError:
                    return None
                return value if value >= 0 else None
        return None


class MetricsCollector:
    """Policy-controlled adapter from a provider to the monitoring stream.

    Collection is explicit and bounded: callers request a snapshot, the
    configured cadence suppresses duplicate requests, and only the configured
    number of provider samples is published.  The default policy remains
    disabled, and the built-in provider is process-scoped and non-privileged.
    """

    def __init__(
        self,
        binding: Any,
        *,
        writer: "MonitoringStreamWriter",
        context: MetricsContext,
        provider: MetricsProvider | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(context, MetricsContext):
            raise TypeError("metrics context must be a MetricsContext")
        self.binding = binding
        self.writer = writer
        self.context = context
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._provider = provider or self._build_provider(binding)
        self._started = False
        self._last_sample_at: datetime | None = None
        self._sample_count = 0
        self._skipped_count = 0
        self._truncated_count = 0

    @staticmethod
    def _build_provider(binding: Any) -> MetricsProvider:
        if not bool(getattr(binding, "enabled", False)):
            return NullMetricsProvider()
        name = str(getattr(binding, "provider_name", None) or "process").strip().lower()
        if name == "process":
            return ProcessMetricsProvider()
        raise ValueError(f"unsupported metrics provider: {name}")

    @property
    def provider(self) -> MetricsProvider:
        return self._provider

    def start(self) -> None:
        if self._started:
            return
        if bool(getattr(self.binding, "enabled", False)):
            self._provider.start(self.context)
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return
        self._provider.stop()
        self._started = False

    def update_binding(self, binding: Any) -> None:
        """Apply a validated policy update without retaining stale authority."""
        old_name = str(getattr(self.binding, "provider_name", None) or "process").strip().lower()
        new_name = str(getattr(binding, "provider_name", None) or "process").strip().lower()
        old_enabled = bool(getattr(self.binding, "enabled", False))
        new_enabled = bool(getattr(binding, "enabled", False))
        if old_enabled != new_enabled or old_name != new_name:
            self.stop()
            self.binding = binding
            self._provider = self._build_provider(binding)
            self._last_sample_at = None
            self.start()
            return
        self.binding = binding
        if new_enabled and not self._started:
            self.start()
        elif not new_enabled and self._started:
            self.stop()

    def collect(
        self,
        start: datetime,
        end: datetime,
        *,
        correlation: MetricsCorrelation | None = None,
        force: bool = False,
    ) -> tuple[dict[str, Any], ...]:
        """Collect and publish one bounded metrics snapshot.

        ``force`` is intended for explicit incident or operator capture.  It
        still observes the provider and record bounds, but bypasses cadence
        suppression and is not an authority-changing operation.
        """
        if not isinstance(correlation, (MetricsCorrelation, type(None))):
            raise TypeError("metrics correlation must be a MetricsCorrelation")
        _validate_metric_window(start, end)
        if not bool(getattr(self.binding, "enabled", False)) or not self.writer.enabled:
            return ()
        if not self._started:
            self.start()
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("metrics collector clock must include timezone")
        now = now.astimezone(timezone.utc)
        interval = float(getattr(self.binding, "sample_interval_seconds", 5.0))
        if (
            not force
            and self._last_sample_at is not None
            and (now - self._last_sample_at).total_seconds() < interval
        ):
            self._skipped_count += 1
            return ()
        samples = self._provider.query(start, end)
        self._last_sample_at = now
        maximum = int(getattr(self.binding, "maximum_samples_per_snapshot", 64))
        if len(samples) > maximum:
            self._truncated_count += len(samples) - maximum
            samples = samples[:maximum]
        correlated = tuple(
            self._correlate(sample, correlation or MetricsCorrelation())
            for sample in samples
        )
        records = self.writer.emit_samples(correlated)
        self._sample_count += len(records)
        return records

    def status(self) -> dict[str, Any]:
        """Return bounded operational evidence without provider contents."""
        return {
            "schema_version": 1,
            "enabled": bool(getattr(self.binding, "enabled", False)),
            "provider": self._provider.provider_name,
            "started": self._started,
            "sample_count": self._sample_count,
            "skipped_count": self._skipped_count,
            "truncated_count": self._truncated_count,
            "last_sample_at": self._last_sample_at.isoformat() if self._last_sample_at else None,
        }

    def _correlate(self, sample: MetricSample, correlation: MetricsCorrelation) -> MetricSample:
        dimensions = dict(sample.dimensions)
        if not bool(getattr(self.binding, "correlate_by_process", True)):
            dimensions.pop("process_id", None)
        fields = (
            ("target_id", correlation.target_id, "correlate_by_target"),
            ("call_id", correlation.call_id, "correlate_by_call"),
            ("incident_id", correlation.incident_id, "correlate_by_incident"),
            ("guard_window_id", correlation.guard_window_id, "correlate_by_guard_window"),
            ("baseline_id", correlation.baseline_id, "correlate_by_baseline"),
        )
        for name, value, setting in fields:
            if value is not None and bool(getattr(self.binding, setting, True)):
                dimensions[name] = _bounded_correlation_id(value, name)
        return MetricSample(
            name=sample.name,
            timestamp=sample.timestamp,
            value=sample.value,
            unit=sample.unit,
            dimensions=tuple(sorted(dimensions.items())),
        )


def _validate_metric_window(start: datetime, end: datetime) -> None:
    for value, label in ((start, "start"), (end, "end")):
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError(f"metrics query {label} must include timezone")
    if start > end:
        raise ValueError("metrics query start must not be after end")


def _bounded_correlation_id(value: UUID | str, name: str) -> str:
    if not isinstance(value, (UUID, str)):
        raise MonitoringStreamError(f"metrics {name} correlation must be a string or UUID")
    text = str(value).strip()
    if not text or len(text) > 128 or any(ord(char) < 0x20 for char in text):
        raise MonitoringStreamError(f"metrics {name} correlation is empty or invalid")
    return text


class MonitoringStreamWriter:
    """Write bounded, output-only metrics for external collectors.

    The writer intentionally has no read or command interface.  It accepts
    only numeric values and bounded dimensions, and checks the rendered line
    size before writing so a monitoring record cannot consume unbounded local
    resources.  The local file is evidence/telemetry, never an authority
    input.
    """

    def __init__(
        self,
        policy: MonitoringStreamPolicy,
        *,
        directory: str | Path,
        application_id: str,
        run_id: UUID | str,
        process_start_id: UUID | str,
    ) -> None:
        self.policy = policy
        self.directory = Path(directory)
        self._rooted = RootedFilesystem(self.directory)
        self.application_id = self._bounded_text(application_id, "application_id", 128)
        self.run_id = self._bounded_text(str(run_id), "run_id", 128)
        self.process_start_id = self._bounded_text(
            str(process_start_id), "process_start_id", 128
        )
        self.path = self.directory / policy.file_name
        self._lock = threading.RLock()
        self._file = None
        self._closed = False
        self._sequence = 0
        if policy.enabled:
            self._file = self._rooted.open_append(self.path, text=True)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                # The stream remains usable on platforms without chmod support;
                # the containing policy directory still controls its location.
                pass

    @property
    def enabled(self) -> bool:
        return self._file is not None and not self._closed

    def update_policy(self, policy: MonitoringStreamPolicy) -> tuple[str, ...]:
        """Apply only non-startup policy changes and report ignored changes."""
        warnings: list[str] = []
        if policy.file_name != self.policy.file_name:
            warnings.append(
                "logging.monitoring.file_name is startup-bound; the existing file remains active"
            )
        if policy.dialect != self.policy.dialect:
            warnings.append(
                "logging.monitoring.dialect is startup-bound; the existing format remains active"
            )
        if policy.maximum_record_bytes != self.policy.maximum_record_bytes:
            warnings.append(
                "logging.monitoring.maximum_record_bytes is startup-bound; the existing limit remains active"
            )
        if policy.enabled != self.policy.enabled:
            warnings.append(
                "logging.monitoring.enabled is run-bound; a new run is required"
            )
        self.policy = MonitoringStreamPolicy(
            enabled=self.policy.enabled,
            file_name=self.policy.file_name,
            dialect=self.policy.dialect,
            maximum_record_bytes=self.policy.maximum_record_bytes,
        )
        return tuple(warnings)

    def emit(
        self,
        name: str,
        value: int | float,
        *,
        unit: str | None = None,
        dimensions: Mapping[str, str] | None = None,
        timestamp: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Append one metric and return its canonical record."""
        if not self.enabled:
            return None
        metric_name = self._bounded_metric_name(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise MonitoringStreamError("monitoring metric value must be numeric")
        numeric_value = float(value)
        if not math.isfinite(numeric_value):
            raise MonitoringStreamError("monitoring metric value must be finite")
        if isinstance(value, int):
            serialized_value: int | float = value
        else:
            serialized_value = numeric_value
        normalized_unit = (
            self._bounded_text(unit, "unit", 64) if unit is not None else None
        )
        normalized_dimensions = self._dimensions(dimensions)
        occurred_at = timestamp or datetime.now(timezone.utc)
        if occurred_at.tzinfo is None:
            raise MonitoringStreamError("monitoring timestamp must include timezone")
        occurred_at = occurred_at.astimezone(timezone.utc)
        with self._lock:
            if not self.enabled:
                return None
            self._sequence += 1
            record = {
                "schema_version": MONITORING_STREAM_SCHEMA_VERSION,
                "stream_sequence": self._sequence,
                "metric": metric_name,
                "value": serialized_value,
                "unit": normalized_unit,
                "occurred_at": occurred_at.isoformat(),
                "application_id": self.application_id,
                "run_id": self.run_id,
                "process_start_id": self.process_start_id,
                "dimensions": normalized_dimensions,
            }
            line = self._render(record)
            if len(line.encode("utf-8")) > self.policy.maximum_record_bytes:
                raise MonitoringStreamError(
                    "monitoring record exceeds maximum_record_bytes"
                )
            self._file.write(line + "\n")
            return record

    def emit_overhead(self, status: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
        """Publish the bounded logging-path overhead snapshot as metrics."""
        if not isinstance(status, Mapping):
            raise MonitoringStreamError("monitoring overhead status must be a mapping")
        dimensions = {"scope": str(status.get("scope") or "caretaker_logging")}
        units = {
            "queue_utilization": "ratio",
            "write_seconds_total": "seconds",
            "write_seconds_max": "seconds",
            "flush_seconds_total": "seconds",
            "flush_seconds_max": "seconds",
        }
        records: list[dict[str, Any]] = []
        for name in (
            "write_calls",
            "accepted_records",
            "dropped_records",
            "failed_writes",
            "flush_batches",
            "flush_records",
            "queue_depth",
            "queue_capacity",
            "queue_utilization",
            "maximum_queue_depth",
            "write_seconds_total",
            "write_seconds_max",
            "flush_seconds_total",
            "flush_seconds_max",
        ):
            value = status.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            record = self.emit(
                f"caretaker.logging.{name}",
                value,
                unit=units.get(name, "count"),
                dimensions=dimensions,
            )
            if record is not None:
                records.append(record)
        return tuple(records)

    def emit_samples(self, samples: Iterable[MetricSample]) -> tuple[dict[str, Any], ...]:
        """Publish provider samples through the same bounded stream contract."""
        records: list[dict[str, Any]] = []
        for sample in samples:
            if not isinstance(sample, MetricSample):
                raise MonitoringStreamError("monitoring samples must be MetricSample records")
            dimensions = dict(sample.dimensions)
            record = self.emit(
                sample.name,
                sample.value,
                unit=sample.unit,
                dimensions=dimensions,
                timestamp=sample.timestamp,
            )
            if record is not None:
                records.append(record)
        return tuple(records)

    def flush(self) -> None:
        with self._lock:
            if self._file is not None and not self._closed:
                self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self.flush()
            if self._file is not None:
                self._file.close()
            self._closed = True

    @staticmethod
    def _bounded_text(value: Any, name: str, limit: int) -> str:
        text = str(value).strip()
        if not text or len(text) > limit or any(ord(char) < 0x20 for char in text):
            raise MonitoringStreamError(f"monitoring {name} is empty or invalid")
        return text

    @classmethod
    def _bounded_metric_name(cls, value: Any) -> str:
        text = str(value).strip()
        if _METRIC_NAME.fullmatch(text) is None:
            raise MonitoringStreamError("monitoring metric name is invalid")
        return text

    @classmethod
    def _dimensions(cls, value: Mapping[str, str] | None) -> dict[str, str]:
        if value is None:
            return {}
        if not isinstance(value, Mapping) or len(value) > 32:
            raise MonitoringStreamError("monitoring dimensions must contain at most 32 entries")
        result: dict[str, str] = {}
        for key, raw_value in value.items():
            name = str(key).strip()
            if _DIMENSION_NAME.fullmatch(name) is None:
                raise MonitoringStreamError("monitoring dimension name is invalid")
            result[name] = cls._bounded_text(raw_value, f"dimension {name}", 128)
        return dict(sorted(result.items()))

    def _render(self, record: Mapping[str, Any]) -> str:
        dialect = self.policy.dialect
        if dialect is MonitoringDialect.JSON_LINES:
            return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if dialect is MonitoringDialect.DATADOG:
            tags = {
                "application_id": record["application_id"],
                "run_id": record["run_id"],
                **dict(record["dimensions"]),
            }
            if record.get("unit"):
                tags["unit"] = record["unit"]
            rendered_tags = ",".join(
                f"{key}:{self._tag_value(value)}"
                for key, value in sorted(tags.items())
            )
            return f"{record['metric']}:{record['value']}|g|#{rendered_tags}"
        if dialect is MonitoringDialect.SPLUNK_HEC:
            event = {
                "metric": record["metric"],
                "value": record["value"],
                "unit": record["unit"],
                "dimensions": record["dimensions"],
                "stream_sequence": record["stream_sequence"],
            }
            return json.dumps(
                {
                    "time": datetime.fromisoformat(str(record["occurred_at"])).timestamp(),
                    "host": record["application_id"],
                    "source": "caretaker",
                    "sourcetype": "caretaker:metric",
                    "event": event,
                    "fields": {"run_id": record["run_id"], "process_start_id": record["process_start_id"]},
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        if dialect is MonitoringDialect.NEW_RELIC:
            attributes = {
                "application_id": record["application_id"],
                "run_id": record["run_id"],
                "process_start_id": record["process_start_id"],
                **dict(record["dimensions"]),
            }
            if record.get("unit"):
                attributes["unit"] = record["unit"]
            timestamp_ms = int(
                datetime.fromisoformat(str(record["occurred_at"])).timestamp() * 1000
            )
            return json.dumps(
                {
                    "common": {"timestamp": timestamp_ms, "attributes": attributes},
                    "metrics": [{"name": record["metric"], "type": "gauge", "value": record["value"]}],
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        raise MonitoringStreamError("monitoring dialect is unsupported")

    @staticmethod
    def _tag_value(value: Any) -> str:
        return str(value).replace("\\", "\\\\").replace(",", "\\,").replace("|", "\\|")
