from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from threading import RLock
from typing import Iterable

from .domain import LogEventSnapshot
from .runtime import current_call_id, current_incident_id, current_target_id


logger = logging.getLogger("caretaker")
logger.addHandler(logging.NullHandler())


class CorrelatedLogHandler(logging.Handler):
    """Captures bounded application log context without configuring root logging."""

    def __init__(self, capacity: int = 5_000) -> None:
        super().__init__()
        self._records: deque[LogEventSnapshot] = deque(maxlen=capacity)
        self._lock = RLock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            snapshot = LogEventSnapshot(
                timestamp=datetime.fromtimestamp(record.created, timezone.utc),
                level=record.levelname,
                logger_name=record.name,
                message=record.getMessage(),
                target_id=current_target_id.get(),
                call_id=current_call_id.get(),
                incident_id=current_incident_id.get(),
            )
            with self._lock:
                self._records.append(snapshot)
        except Exception:
            self.handleError(record)

    def recent(
        self,
        *,
        target_id: str | None = None,
        call_id: object | None = None,
        limit: int = 200,
    ) -> tuple[LogEventSnapshot, ...]:
        with self._lock:
            records = [
                record for record in self._records
                if (target_id is None or record.target_id == target_id)
                and (call_id is None or record.call_id == call_id)
            ]
            return tuple(records[-limit:])
