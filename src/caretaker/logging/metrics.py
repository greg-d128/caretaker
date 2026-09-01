from __future__ import annotations

import json
import math
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import UUID


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
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.path.open("a", encoding="utf-8", buffering=1)
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
