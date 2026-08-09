from __future__ import annotations

import gzip
import hashlib
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping
from uuid import UUID, uuid4

from .policy import (
    ProcessSelector,
    SystemCollectionPolicy,
    SystemSourceDefinition,
    SystemTimestampMode,
)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    proc_start_ticks: int
    process_start_id: UUID
    parent_pid: int | None
    executable: str | None
    command_summary: str | None


@dataclass(frozen=True, slots=True)
class SystemSourceStatus:
    source_id: str
    path: str
    state: str
    last_success_at: datetime | None
    last_error: str | None


@dataclass(frozen=True, slots=True)
class SystemSourceCaptureResult:
    source_id: str
    path: str
    process: ProcessIdentity | None
    state: str
    bytes_captured: int
    content_hash: str | None
    output_path: str | None
    read_started_offset_ns: int | None
    read_completed_offset_ns: int | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SystemCollectionCycle:
    cycle_id: UUID
    sequence: int
    capture_timestamp_utc: datetime
    capture_clock_value: int
    selected_processes: tuple[ProcessIdentity, ...]
    source_results: tuple[SystemSourceCaptureResult, ...]


class RotatingSystemStream:
    def __init__(self, path: Path, policy: SystemCollectionPolicy) -> None:
        self.base_path = path
        self.policy = policy
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._sequence = 0
        self._open()

    def _open(self) -> None:
        self._sequence += 1
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.path = self.base_path.with_name(f"{self.base_path.stem}-{stamp}-{self._sequence}{self.base_path.suffix}")
        self._file = self.path.open("ab", buffering=0)
        self._created = datetime.now(timezone.utc)

    def write(self, data: bytes) -> Path:
        with self._lock:
            age = (datetime.now(timezone.utc) - self._created).total_seconds()
            if self._file.tell() and (
                self._file.tell() + len(data) > self.policy.rotation.maximum_segment_bytes
                or age >= self.policy.rotation.maximum_segment_seconds
            ):
                self.close_segment()
                self._open()
            self._file.write(data)
            return self.path

    def close_segment(self) -> Path | None:
        with self._lock:
            if self._file.closed:
                return None
            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
            if self.policy.compression.enabled:
                compressed = self.path.with_suffix(self.path.suffix + ".gz")
                with self.path.open("rb") as source, gzip.open(compressed, "wb", compresslevel=self.policy.compression.level) as target:
                    shutil.copyfileobj(source, target)
            self._retention()
            return self.path

    def _retention(self) -> None:
        paths = sorted(self.base_path.parent.glob(f"{self.base_path.stem}-*{self.base_path.suffix}*"), key=lambda item: item.stat().st_mtime)
        age_days = self.policy.retention.maximum_age_days
        if age_days is not None:
            cutoff = time.time() - age_days * 86400
            for path in paths:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
        maximum = self.policy.retention.maximum_segments
        if maximum is not None and len(paths) > maximum:
            for path in paths[:len(paths) - maximum]:
                path.unlink(missing_ok=True)

    def close(self) -> None:
        self.close_segment()


class SystemDataCollector:
    """Application-scoped `/proc` and `/sys` snapshot collector.

    The collector runs with application privileges, never calls sudo, and keeps
    system records in an output tree independent from application logs.
    Source bodies are intentionally left nearly raw for external parsers.
    """

    def __init__(self, policy: SystemCollectionPolicy, *, application_pid: int) -> None:
        self.policy = policy
        self.application_pid = application_pid
        self.output_root = Path(policy.output.directory)
        self.output_root.mkdir(parents=True, exist_ok=True)
        self._streams: dict[str, RotatingSystemStream] = {}
        self._process_start_ids: dict[tuple[int, int], UUID] = {}
        self._statuses: dict[str, SystemSourceStatus] = {}
        self._sequence = 0
        self._stop = threading.Event()

    @property
    def statuses(self) -> tuple[SystemSourceStatus, ...]:
        return tuple(self._statuses.values())

    def collect_once(self) -> SystemCollectionCycle:
        self._sequence += 1
        cycle_id = uuid4()
        timestamp = datetime.now(timezone.utc)
        clock = time.monotonic_ns()
        selected = self.select_processes()
        results: list[SystemSourceCaptureResult] = []
        for source in self.policy.host_sources:
            if source.enabled:
                results.append(self._capture(source, cycle_id, self._sequence, timestamp, clock, None))
        for configured in self.policy.sys_paths:
            source = SystemSourceDefinition(f"sys_{hashlib.sha256(configured.encode()).hexdigest()[:12]}", configured)
            results.append(self._capture(source, cycle_id, self._sequence, timestamp, clock, None))
        for process in selected:
            for source in self.policy.process_sources:
                if source.enabled:
                    results.append(self._capture(source, cycle_id, self._sequence, timestamp, clock, process))
        return SystemCollectionCycle(
            cycle_id=cycle_id, sequence=self._sequence,
            capture_timestamp_utc=timestamp, capture_clock_value=clock,
            selected_processes=selected, source_results=tuple(results),
        )

    def run(self) -> None:
        if not self.policy.enabled:
            return
        while not self._stop.is_set():
            started = time.monotonic()
            self.collect_once()
            remaining = max(0.0, self.policy.interval_seconds - (time.monotonic() - started))
            self._stop.wait(remaining)
        self.close()

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        for stream in self._streams.values():
            stream.close()

    def select_processes(self) -> tuple[ProcessIdentity, ...]:
        selector = self.policy.process_selector
        all_processes = _proc_processes()
        selected_pids: set[int] = set(selector.explicit_pids)
        if selector.include_application_root:
            selected_pids.add(self.application_pid)
        if selector.include_descendants:
            changed = True
            while changed:
                changed = False
                for pid, info in all_processes.items():
                    if info["ppid"] in selected_pids and pid not in selected_pids:
                        selected_pids.add(pid)
                        changed = True
        includes = [re.compile(pattern) for pattern in selector.command_regexes]
        excludes = [re.compile(pattern) for pattern in selector.exclude_command_regexes]
        identities: list[ProcessIdentity] = []
        for pid, info in all_processes.items():
            command = info.get("cmdline", "")
            executable = info.get("executable")
            if includes and not any(pattern.search(command) for pattern in includes) and pid not in selected_pids:
                continue
            if selector.executable_paths and executable not in selector.executable_paths and pid not in selected_pids:
                continue
            if any(pattern.search(command) for pattern in excludes):
                continue
            if pid not in selected_pids and not includes and not selector.executable_paths:
                continue
            start_ticks = int(info["start_ticks"])
            key = (pid, start_ticks)
            identities.append(ProcessIdentity(
                pid=pid, proc_start_ticks=start_ticks,
                process_start_id=self._process_start_ids.setdefault(key, uuid4()),
                parent_pid=int(info["ppid"]), executable=executable,
                command_summary=(
                    self.policy.redaction.mask_cmdline(command)
                    if self.policy.redaction.capture_cmdline and self.policy.redaction.mask_cmdline
                    else command if self.policy.redaction.capture_cmdline else "<not captured>"
                ),
            ))
        return tuple(sorted(identities, key=lambda item: item.pid))

    def _capture(
        self,
        source: SystemSourceDefinition,
        cycle_id: UUID,
        sequence: int,
        timestamp: datetime,
        clock: int,
        process: ProcessIdentity | None,
    ) -> SystemSourceCaptureResult:
        path_text = source.path_template.format(pid=process.pid if process else "")
        path = Path(path_text)
        started = time.monotonic_ns() - clock
        try:
            if path.name == "cmdline" and not self.policy.redaction.capture_cmdline:
                body = b"<not captured>"
            else:
                body = path.read_bytes()
            if path.name == "cmdline" and self.policy.redaction.capture_cmdline:
                body = body.replace(b"\0", b" ")
                if self.policy.redaction.mask_cmdline:
                    body = self.policy.redaction.mask_cmdline(body.decode(errors="replace")).encode()
            completed = time.monotonic_ns() - clock
            stream_key, output_path = self._stream_for(source, process)
            header = (
                "@@caretaker-system-record\n"
                f"schema_version=1\nwriter_version=0.6.0a1\ncycle_id={cycle_id}\n"
                f"sequence={sequence}\ntimestamp_utc={timestamp.isoformat()}\n"
                f"capture_clock_value={clock}\nread_started_offset_ns={started}\n"
                f"read_completed_offset_ns={completed}\nsource={path_text}\n"
                f"pid={process.pid if process else ''}\nproc_start_ticks={process.proc_start_ticks if process else ''}\n"
                f"body_bytes={len(body)}\n@@body\n"
            ).encode()
            block = header + body + (b"" if body.endswith(b"\n") else b"\n") + b"@@end\n"
            actual_path = self._streams[stream_key].write(block)
            now = datetime.now(timezone.utc)
            self._statuses[source.source_id] = SystemSourceStatus(source.source_id, path_text, "AVAILABLE", now, None)
            return SystemSourceCaptureResult(
                source_id=source.source_id, path=path_text, process=process,
                state="CAPTURED", bytes_captured=len(body), content_hash=hashlib.sha256(body).hexdigest(),
                output_path=str(actual_path), read_started_offset_ns=started,
                read_completed_offset_ns=completed,
            )
        except Exception as exc:
            self._statuses[source.source_id] = SystemSourceStatus(
                source.source_id, path_text, "UNAVAILABLE", self._statuses.get(source.source_id, SystemSourceStatus(source.source_id, path_text, "", None, None)).last_success_at,
                f"{type(exc).__name__}: {exc}",
            )
            return SystemSourceCaptureResult(
                source_id=source.source_id, path=path_text, process=process,
                state="UNAVAILABLE", bytes_captured=0, content_hash=None, output_path=None,
                read_started_offset_ns=started, read_completed_offset_ns=time.monotonic_ns() - clock,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _stream_for(self, source: SystemSourceDefinition, process: ProcessIdentity | None) -> tuple[str, Path]:
        if process:
            directory = self.output_root / "processes" / f"{process.pid}-{process.proc_start_ticks}"
            key = f"process:{process.pid}:{process.proc_start_ticks}:{source.source_id}"
        else:
            directory = self.output_root / "host"
            key = f"host:{source.source_id}"
        path = directory / f"{source.source_id}{self.policy.output.file_extension}"
        if key not in self._streams:
            self._streams[key] = RotatingSystemStream(path, self.policy)
        return key, path


def _proc_processes() -> dict[int, dict[str, object]]:
    result: dict[int, dict[str, object]] = {}
    proc = Path("/proc")
    if not proc.exists():
        return result
    for child in proc.iterdir():
        if not child.name.isdigit():
            continue
        pid = int(child.name)
        try:
            stat_text = (child / "stat").read_text()
            end = stat_text.rfind(")")
            fields = stat_text[end + 2:].split()
            ppid = int(fields[1])
            start_ticks = int(fields[19])
            cmdline = (child / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            try:
                executable = os.readlink(child / "exe")
            except OSError:
                executable = None
            result[pid] = {"ppid": ppid, "start_ticks": start_ticks, "cmdline": cmdline, "executable": executable}
        except (OSError, ValueError, IndexError):
            continue
    return result
