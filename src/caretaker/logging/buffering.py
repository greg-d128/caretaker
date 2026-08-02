from __future__ import annotations

import logging
import queue
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from .models import BackpressureAction, EmergencyAction, LogChannel, LogEnvelope, StorageHealth
from .policy import OperatorLoggingPolicy
from .segments import SegmentManifest, SegmentWriter


class LoggingStorageError(RuntimeError):
    pass


class ApplicationStopRequested(SystemExit):
    pass


class BufferedSegmentSink:
    """Bounded asynchronous writer used by direct and supervised logging.

    The caller never performs SQLite work or compression. Backpressure and
    storage-emergency behavior are selected by the operator policy.
    """

    def __init__(self, writer: SegmentWriter, policy: OperatorLoggingPolicy) -> None:
        self.writer = writer
        self.policy = policy
        self.codec = writer.codec
        self._queue: queue.Queue[LogEnvelope | object] = queue.Queue(maxsize=policy.buffering.queue_capacity)
        self._stop_token = object()
        self._closed = False
        self._dropped = 0
        self._last_error: Exception | None = None
        self._thread = threading.Thread(target=self._run, name="caretaker-log-writer", daemon=True)
        self._thread.start()

    def reserve_sequence(self, record_id):
        return self.writer.reserve_sequence(record_id)

    def update_policy(self, policy: OperatorLoggingPolicy) -> tuple[str, ...]:
        warnings = list(self.writer.update_policy(policy))
        if policy.buffering.queue_capacity != self.policy.buffering.queue_capacity:
            warnings.append("logging.buffering.queue_capacity is startup-bound; the existing queue remains active")
        self.policy = self.writer.policy
        return tuple(warnings)

    @property
    def dropped_records(self) -> int:
        return self._dropped

    @property
    def last_error(self) -> Exception | None:
        return self._last_error

    def storage_health(self) -> StorageHealth:
        try:
            usage = shutil.disk_usage(Path(self.policy.directory))
        except OSError:
            return StorageHealth.UNAVAILABLE
        minimum_bytes = self.policy.storage_emergency.minimum_free_bytes
        minimum_percent = self.policy.storage_emergency.minimum_free_percent
        percent = (usage.free / usage.total * 100.0) if usage.total else 0.0
        if (minimum_bytes is not None and usage.free <= minimum_bytes) or (
            minimum_percent is not None and percent <= minimum_percent
        ):
            return StorageHealth.EMERGENCY
        pressure_bytes = minimum_bytes * 2 if minimum_bytes is not None else None
        pressure_percent = minimum_percent * 2 if minimum_percent is not None else None
        if (pressure_bytes is not None and usage.free <= pressure_bytes) or (
            pressure_percent is not None and percent <= pressure_percent
        ):
            return StorageHealth.PRESSURE
        return StorageHealth.NORMAL

    def write(self, envelope: LogEnvelope) -> bool:
        if self._closed:
            return False
        health = self.storage_health()
        if health is StorageHealth.UNAVAILABLE:
            return self._apply_emergency(self.policy.storage_emergency.unavailable_action, envelope)
        if health is StorageHealth.EMERGENCY:
            return self._apply_emergency(self.policy.storage_emergency.emergency_action, envelope)
        if health is StorageHealth.PRESSURE:
            action = self.policy.storage_emergency.pressure_action
            if action is not EmergencyAction.DROP_LOW_PRIORITY:
                return self._apply_emergency(action, envelope)
            if envelope.severity < logging.WARNING and envelope.channel is LogChannel.APPLICATION:
                self._dropped += 1
                return False
        try:
            self._queue.put_nowait(envelope)
            return True
        except queue.Full:
            return self._backpressure(envelope)

    def _backpressure(self, envelope: LogEnvelope) -> bool:
        high_priority = envelope.severity >= logging.ERROR or envelope.channel in {
            LogChannel.GUARD, LogChannel.REPAIR, LogChannel.INTEGRITY, LogChannel.EMERGENCY,
        }
        action = self.policy.backpressure.high_priority_action if high_priority else self.policy.backpressure.action
        if action is BackpressureAction.BLOCK:
            try:
                self._queue.put(envelope, timeout=self.policy.backpressure.block_timeout_seconds)
                return True
            except queue.Full:
                self._dropped += 1
                return False
        if action is BackpressureAction.DROP_DEBUG:
            if envelope.severity <= logging.DEBUG:
                self._dropped += 1
                return False
            return self._emergency_sync(envelope)
        if action is BackpressureAction.SAMPLE:
            self._dropped += 1
            return False
        if action is BackpressureAction.DROP_OLDEST:
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except queue.Empty:
                pass
            self._queue.put_nowait(envelope)
            self._dropped += 1
            return True
        if action is BackpressureAction.EMERGENCY_SYNC_WRITE:
            return self._emergency_sync(envelope)
        if action is BackpressureAction.BYPASS_LOGGING:
            self._dropped += 1
            return False
        if action is BackpressureAction.STOP_APPLICATION:
            raise ApplicationStopRequested("Caretaker logging backpressure policy requested application shutdown")
        self._dropped += 1
        return False

    def _apply_emergency(self, action: EmergencyAction, envelope: LogEnvelope) -> bool:
        if action is EmergencyAction.BLOCK:
            return self._backpressure(envelope)
        if action is EmergencyAction.DROP_LOW_PRIORITY:
            if envelope.severity < logging.ERROR and envelope.channel is LogChannel.APPLICATION:
                self._dropped += 1
                return False
            return self._emergency_sync(envelope)
        if action is EmergencyAction.SWITCH_TO_EMERGENCY_STORAGE:
            return self._emergency_sync(envelope)
        if action in {EmergencyAction.STOP_LOGGING, EmergencyAction.STOP_ANALYSIS}:
            self._dropped += 1
            return False
        if action is EmergencyAction.STOP_APPLICATION:
            raise ApplicationStopRequested("Caretaker storage-emergency policy requested application shutdown")
        if action is EmergencyAction.THROTTLE_APPLICATION:
            time.sleep(min(1.0, self.policy.backpressure.block_timeout_seconds))
            return self._backpressure(envelope)
        return False

    def _emergency_sync(self, envelope: LogEnvelope) -> bool:
        try:
            self.writer.write(envelope)
            self.writer.flush()
            return True
        except Exception as exc:
            self._last_error = exc
            self._dropped += 1
            return False

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._stop_token:
                    return
                assert isinstance(item, LogEnvelope)
                batch = [item]
                while len(batch) < self.policy.buffering.batch_records:
                    try:
                        next_item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if next_item is self._stop_token:
                        self._queue.task_done()
                        for record in batch:
                            self.writer.write(record)
                        return
                    batch.append(next_item)  # type: ignore[arg-type]
                for record in batch:
                    self.writer.write(record)
                self.writer.flush()
                for _ in batch[1:]:
                    self._queue.task_done()
            except Exception as exc:
                self._last_error = exc
            finally:
                self._queue.task_done()

    def flush(self) -> None:
        self._queue.join()
        self.writer.flush()

    def close(self, *, attachment_manifest_hash: str | None = None) -> SegmentManifest | None:
        if self._closed:
            return None
        self.flush()
        self._queue.put(self._stop_token)
        self._thread.join(timeout=10)
        self._closed = True
        return self.writer.close(attachment_manifest_hash=attachment_manifest_hash)
