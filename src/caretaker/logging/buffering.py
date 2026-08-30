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
        self._metrics_lock = threading.Lock()
        self._write_calls = 0
        self._accepted_records = 0
        self._failed_writes = 0
        self._write_seconds_total = 0.0
        self._write_seconds_max = 0.0
        self._flush_batches = 0
        self._flush_records = 0
        self._flush_seconds_total = 0.0
        self._flush_seconds_max = 0.0
        self._maximum_queue_depth = 0
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
        started = time.perf_counter()
        accepted = False
        failed = False
        try:
            accepted = self._write(envelope)
            return accepted
        except BaseException:
            failed = True
            raise
        finally:
            elapsed = max(0.0, time.perf_counter() - started)
            with self._metrics_lock:
                self._write_calls += 1
                if accepted:
                    self._accepted_records += 1
                if failed:
                    self._failed_writes += 1
                self._write_seconds_total += elapsed
                self._write_seconds_max = max(self._write_seconds_max, elapsed)
                self._maximum_queue_depth = max(
                    self._maximum_queue_depth,
                    self._queue.qsize(),
                )

    def _write(self, envelope: LogEnvelope) -> bool:
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
            if item is self._stop_token:
                self._queue.task_done()
                return
            assert isinstance(item, LogEnvelope)
            batch = [item]
            stop_after_batch = False
            deadline = time.monotonic() + self.policy.buffering.flush_interval_seconds
            while len(batch) < self.policy.buffering.batch_records:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    next_item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                if next_item is self._stop_token:
                    self._queue.task_done()
                    stop_after_batch = True
                    break
                assert isinstance(next_item, LogEnvelope)
                batch.append(next_item)
            flush_started = time.perf_counter()
            try:
                for record in batch:
                    self.writer.write(record)
                self.writer.flush()
            except Exception as exc:
                self._last_error = exc
            finally:
                elapsed = max(0.0, time.perf_counter() - flush_started)
                with self._metrics_lock:
                    self._flush_batches += 1
                    self._flush_records += len(batch)
                    self._flush_seconds_total += elapsed
                    self._flush_seconds_max = max(self._flush_seconds_max, elapsed)
                for _ in batch:
                    self._queue.task_done()
            if stop_after_batch:
                return

    def flush(self) -> None:
        self._queue.join()
        self.writer.flush()

    def overhead_status(self) -> dict[str, Any]:
        """Return bounded wall-clock and queue evidence for operator status.

        These are observations of the logging path, not a complete CPU or
        application-overhead measurement. They never affect backpressure or
        policy decisions.
        """
        with self._metrics_lock:
            write_calls = self._write_calls
            accepted_records = self._accepted_records
            failed_writes = self._failed_writes
            write_seconds_total = self._write_seconds_total
            write_seconds_max = self._write_seconds_max
            flush_batches = self._flush_batches
            flush_records = self._flush_records
            flush_seconds_total = self._flush_seconds_total
            flush_seconds_max = self._flush_seconds_max
            maximum_queue_depth = self._maximum_queue_depth
        queue_depth = self._queue.qsize()
        capacity = self._queue.maxsize
        return {
            "measurement": "logging_path_wall_clock",
            "write_calls": write_calls,
            "accepted_records": accepted_records,
            "dropped_records": self._dropped,
            "failed_writes": failed_writes,
            "write_seconds_total": write_seconds_total,
            "write_seconds_max": write_seconds_max,
            "flush_batches": flush_batches,
            "flush_records": flush_records,
            "flush_seconds_total": flush_seconds_total,
            "flush_seconds_max": flush_seconds_max,
            "queue_depth": queue_depth,
            "queue_capacity": capacity,
            "queue_utilization": (queue_depth / capacity) if capacity else 0.0,
            "maximum_queue_depth": maximum_queue_depth,
            "last_error": (
                type(self._last_error).__name__
                if self._last_error is not None
                else None
            ),
        }

    def close(self, *, attachment_manifest_hash: str | None = None) -> SegmentManifest | None:
        if self._closed:
            return None
        self.flush()
        self._queue.put(self._stop_token)
        self._thread.join(timeout=10)
        self._closed = True
        return self.writer.close(attachment_manifest_hash=attachment_manifest_hash)
