from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from uuid import UUID, uuid4

from .models import LogEnvelope, RuntimeRecordIntegrityMode, SignatureStatus
from .policy import OperatorLoggingPolicy
from .records import HEADER, RecordFormatError, TLVLogCodec
from .signing import EphemeralSignerProcess, KeyEvolutionSigner


@dataclass(frozen=True, slots=True)
class SegmentManifest:
    segment_id: UUID
    path: str
    first_sequence: int
    last_sequence: int
    record_count: int
    created_at: datetime
    closed_at: datetime
    content_hash: str
    previous_segment_hash: str | None
    compressed_path: str | None
    signature_status: SignatureStatus
    signature_path: str | None


class SegmentIndex:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with sqlite3.connect(path) as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS segments (
                    segment_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    first_sequence INTEGER NOT NULL,
                    last_sequence INTEGER NOT NULL,
                    record_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    closed_at TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    previous_segment_hash TEXT,
                    compressed_path TEXT,
                    signature_status TEXT NOT NULL,
                    signature_path TEXT
                );
                CREATE TABLE IF NOT EXISTS records (
                    record_id TEXT PRIMARY KEY,
                    segment_id TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    logger_name TEXT NOT NULL,
                    target_id TEXT,
                    call_id TEXT,
                    incident_id TEXT,
                    offset_bytes INTEGER NOT NULL,
                    length_bytes INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS records_time_idx ON records(occurred_at);
                CREATE INDEX IF NOT EXISTS records_target_idx ON records(target_id, occurred_at);
                """
            )

    def record(self, envelope: LogEnvelope, *, segment_id: UUID, offset: int, length: int) -> None:
        with self._lock, sqlite3.connect(self.path) as connection:
            connection.execute(
                """INSERT OR REPLACE INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(envelope.record_id), str(segment_id), envelope.sequence_number,
                    envelope.occurred_at.isoformat(), envelope.channel.name, envelope.severity,
                    envelope.logger_name, envelope.target_id,
                    str(envelope.call_id) if envelope.call_id else None,
                    str(envelope.incident_id) if envelope.incident_id else None,
                    offset, length,
                ),
            )

    def close_segment(self, manifest: SegmentManifest) -> None:
        with self._lock, sqlite3.connect(self.path) as connection:
            connection.execute(
                """INSERT OR REPLACE INTO segments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(manifest.segment_id), manifest.path, manifest.first_sequence,
                    manifest.last_sequence, manifest.record_count, manifest.created_at.isoformat(),
                    manifest.closed_at.isoformat(), manifest.content_hash,
                    manifest.previous_segment_hash, manifest.compressed_path,
                    manifest.signature_status.name, manifest.signature_path,
                ),
            )

    def rebuild(self, segment_paths: Iterable[str | Path], *, codec: TLVLogCodec | None = None) -> int:
        """Rebuild the derived record index from authoritative segment files."""
        codec = codec or TLVLogCodec()
        with self._lock, sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM records")
        count = 0
        for path_value in segment_paths:
            path = Path(path_value)
            records = read_segment(path, codec=codec)
            offset = 0
            segment_id_text = path.stem.split("-")[-1].removesuffix(".ctlog")
            try:
                segment_id = UUID(segment_id_text)
            except ValueError:
                segment_id = uuid4()
            for record in records:
                encoded = codec.encode(record)
                self.record(record, segment_id=segment_id, offset=offset, length=len(encoded))
                offset += len(encoded)
                count += 1
        return count

    def query_records(self, *, target_id: str | None = None, limit: int = 1000) -> tuple[dict[str, object], ...]:
        sql = "SELECT record_id, segment_id, sequence_number, occurred_at, channel, severity, logger_name, target_id, call_id, incident_id, offset_bytes, length_bytes FROM records"
        params: list[object] = []
        if target_id is not None:
            sql += " WHERE target_id = ?"
            params.append(target_id)
        sql += " ORDER BY occurred_at DESC LIMIT ?"
        params.append(limit)
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            return tuple(dict(row) for row in connection.execute(sql, params))


class SegmentWriter:
    def __init__(
        self,
        policy: OperatorLoggingPolicy,
        *,
        run_id: UUID,
        process_start_id: UUID,
    ) -> None:
        self.policy = policy
        self.run_id = run_id
        self.process_start_id = process_start_id
        self.root = Path(policy.directory)
        self.segment_dir = self.root / "application" / "events"
        self.manifest_dir = self.root / "application" / "manifests"
        self.segment_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        index_path = Path(policy.indexing.sqlite_path) if policy.indexing.sqlite_path else self.root / "index" / "logging.sqlite"
        self.index = SegmentIndex(index_path)
        self.codec = TLVLogCodec(maximum_record_bytes=policy.codec.maximum_record_bytes)
        self._lock = threading.RLock()
        self._previous_hash: str | None = self._load_previous_hash()
        self._global_sequence = self._load_last_sequence()
        self._reserved_sequences: dict[UUID, int] = {}
        self._signer = self._create_signer()
        self._open_new()

    def update_policy(self, policy: OperatorLoggingPolicy) -> tuple[str, ...]:
        """Apply hot-reloadable writer settings and report restart-bound changes."""
        warnings: list[str] = []
        if policy.directory != self.policy.directory:
            warnings.append("logging.directory is startup-bound; the existing directory remains active")
        if policy.codec != self.policy.codec:
            warnings.append("logging.codec is startup-bound; the existing record codec remains active")
        if policy.indexing != self.policy.indexing:
            warnings.append("logging.indexing is startup-bound; the existing index remains active")
        if policy.signing != self.policy.signing:
            warnings.append("logging.signing is run-bound; a new supervised run is required")
        self.policy = replace(
            policy,
            directory=self.policy.directory,
            codec=self.policy.codec,
            indexing=self.policy.indexing,
            signing=self.policy.signing,
        )
        return tuple(warnings)

    def _create_signer(self):
        if self.policy.signing.mode is not RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED:
            return None
        args = dict(
            application_id=self.policy.application_id,
            run_id=self.run_id,
            process_start_id=self.process_start_id,
            policy=self.policy.signing,
            first_event_sequence=0,
        )
        return EphemeralSignerProcess(**args) if self.policy.signing.run_signer_in_separate_process else KeyEvolutionSigner(**args)


    def _load_last_sequence(self) -> int:
        try:
            with sqlite3.connect(self.index.path) as connection:
                row = connection.execute("SELECT COALESCE(MAX(sequence_number), 0) FROM records").fetchone()
                return int(row[0]) if row else 0
        except Exception:
            return 0

    def _load_previous_hash(self) -> str | None:
        manifests = sorted(self.manifest_dir.glob("*.json")) if self.manifest_dir.exists() else []
        if not manifests:
            return None
        try:
            return json.loads(manifests[-1].read_text())["content_hash"]
        except Exception:
            return None

    def _open_new(self) -> None:
        self.segment_id = uuid4()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.path = self.segment_dir / f"{stamp}-{self.segment_id}.ctlog"
        self._file = self.path.open("ab", buffering=0)
        self._created_at = datetime.now(timezone.utc)
        self._first_sequence: int | None = None
        self._last_sequence = -1
        self._record_count = 0

    def _rotation_due(self, next_size: int) -> bool:
        current_size = self._file.tell()
        age = (datetime.now(timezone.utc) - self._created_at).total_seconds()
        return current_size + next_size > self.policy.rotation.maximum_segment_bytes or age >= self.policy.rotation.maximum_segment_seconds

    def reserve_sequence(self, record_id: UUID) -> int:
        with self._lock:
            existing = self._reserved_sequences.get(record_id)
            if existing is not None:
                return existing
            self._global_sequence += 1
            self._reserved_sequences[record_id] = self._global_sequence
            return self._global_sequence

    def write(self, envelope: LogEnvelope) -> None:
        with self._lock:
            reserved = self._reserved_sequences.pop(envelope.record_id, None)
            if reserved is None:
                self._global_sequence += 1
                assigned_sequence = self._global_sequence
            else:
                assigned_sequence = reserved
            if envelope.sequence_number != assigned_sequence:
                fields = dict(envelope.fields)
                fields.setdefault("emitter_sequence_number", envelope.sequence_number)
                envelope = replace(envelope, sequence_number=assigned_sequence, fields=fields)
            record = self.codec.encode(envelope)
            if self._record_count and self._rotation_due(len(record)):
                self.close_segment()
                self._open_new()
            offset = self._file.tell()
            self._file.write(record)
            self._first_sequence = envelope.sequence_number if self._first_sequence is None else self._first_sequence
            self._last_sequence = envelope.sequence_number
            self._record_count += 1
            if self.policy.indexing.enabled:
                self.index.record(envelope, segment_id=self.segment_id, offset=offset, length=len(record))

    def flush(self) -> None:
        with self._lock:
            self._file.flush()
            os.fsync(self._file.fileno())

    def close_segment(self, *, attachment_manifest_hash: str | None = None) -> SegmentManifest | None:
        with self._lock:
            if self._file.closed:
                return None
            self.flush()
            self._file.close()
            closed = datetime.now(timezone.utc)
            content_hash = hashlib.sha256(self.path.read_bytes()).hexdigest()
            compressed_path: str | None = None
            if self.policy.compression.enabled and self.policy.compression.compress_closed_segments:
                compressed = self.path.with_suffix(self.path.suffix + ".gz")
                with self.path.open("rb") as source, gzip.open(compressed, "wb", compresslevel=self.policy.compression.level) as target:
                    shutil.copyfileobj(source, target)
                compressed_path = str(compressed)
            signature_status = SignatureStatus.HASHED_AND_CHAINED
            signature_path: str | None = None
            signed = None
            transitions = ()
            if self._signer is not None and self._record_count:
                kwargs = dict(
                    segment_id=self.segment_id,
                    segment_hash=content_hash,
                    previous_segment_hash=self._previous_hash,
                    first_event_sequence=self._first_sequence or 0,
                    last_event_sequence=self._last_sequence,
                    event_count=self._record_count,
                    attachment_manifest_hash=attachment_manifest_hash,
                )
                if isinstance(self._signer, EphemeralSignerProcess):
                    signed, transitions = self._signer.sign_manifest(**kwargs)
                else:
                    signed = self._signer.sign_manifest(**kwargs)
                    transitions = tuple(self._signer.transitions)
                signature_status = SignatureStatus.EPHEMERAL_SIGNED
                signature_file = self.manifest_dir / f"{self.segment_id}.signature.json"
                signature_file.write_text(json.dumps({
                    "identity": _jsonable(self._signer.identity),
                    "manifest": _jsonable(signed),
                    "transitions": [_jsonable(item) for item in transitions],
                }, indent=2, sort_keys=True))
                signature_path = str(signature_file)
            manifest = SegmentManifest(
                segment_id=self.segment_id,
                path=str(self.path),
                first_sequence=self._first_sequence or 0,
                last_sequence=self._last_sequence,
                record_count=self._record_count,
                created_at=self._created_at,
                closed_at=closed,
                content_hash=content_hash,
                previous_segment_hash=self._previous_hash,
                compressed_path=compressed_path,
                signature_status=signature_status,
                signature_path=signature_path,
            )
            manifest_path = self.manifest_dir / f"{self.segment_id}.json"
            manifest_path.write_text(json.dumps(_jsonable(manifest), indent=2, sort_keys=True))
            self.index.close_segment(manifest)
            self._previous_hash = content_hash
            self._enforce_retention()
            return manifest

    def _enforce_retention(self) -> None:
        paths = sorted(self.segment_dir.glob("*.ctlog*"), key=lambda item: item.stat().st_mtime)
        maximum = self.policy.retention.maximum_segments
        if maximum is not None and len(paths) > maximum:
            for path in paths[:len(paths) - maximum]:
                path.unlink(missing_ok=True)
        age_days = self.policy.retention.maximum_age_days
        if age_days is not None:
            cutoff = time.time() - age_days * 86400
            for path in paths:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
        max_bytes = self.policy.retention.maximum_total_bytes
        if max_bytes is not None:
            paths = [path for path in paths if path.exists()]
            total = sum(path.stat().st_size for path in paths)
            for path in paths:
                if total <= max_bytes:
                    break
                size = path.stat().st_size
                path.unlink(missing_ok=True)
                total -= size

    def close(self, *, attachment_manifest_hash: str | None = None) -> SegmentManifest | None:
        manifest = self.close_segment(attachment_manifest_hash=attachment_manifest_hash)
        if self._signer is not None:
            self._signer.close()
        return manifest


def _jsonable(value):
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        import base64
        return base64.b64encode(value).decode()
    if hasattr(value, "name"):
        return value.name
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def read_segment(path: str | Path, *, codec: TLVLogCodec | None = None) -> tuple[LogEnvelope, ...]:
    codec = codec or TLVLogCodec()
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    records: list[LogEnvelope] = []
    with opener(path, "rb") as source:
        while True:
            prefix = source.read(HEADER.size)
            if not prefix:
                break
            if len(prefix) < HEADER.size:
                # A truncated final record is a recoverable warning condition.
                break
            try:
                total = codec.record_length(prefix)
            except RecordFormatError:
                break
            remainder = source.read(total - HEADER.size)
            if len(remainder) != total - HEADER.size:
                break
            records.append(codec.decode(prefix + remainder))
    return tuple(records)
