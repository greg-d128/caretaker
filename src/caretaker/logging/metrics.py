from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


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
