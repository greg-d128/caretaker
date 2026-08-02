from __future__ import annotations

import gzip
import hashlib
import json
import os
import random
import time
from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

from .models import (
    AttachmentReference,
    AttachmentSamplingDecision,
    CompressionAlgorithm,
    EvidencePriority,
    SignatureStatus,
)
from .policy import AttachmentPolicy


class AttachmentStore:
    """Compressed, rotating supplemental evidence stream.

    The primary 4 KiB event references attachments by event sequence and hash.
    The attachment corpus is not the primary log source of truth.
    """

    def __init__(self, root: str | Path, policy: AttachmentPolicy) -> None:
        self.root = Path(root)
        self.policy = policy
        self.segment_dir = self.root / "application" / "attachments"
        self.manifest_dir = self.root / "application" / "attachment-manifests"
        self.segment_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._arrival_times: deque[float] = deque()
        self._previous_hash: str | None = None
        self._file = None
        self._entries: list[dict[str, object]] = []

    def update_policy(self, policy: AttachmentPolicy) -> None:
        """Apply attachment sampling, rotation, compression, and retention changes."""
        with self._lock:
            self.policy = policy

    def _open_segment(self) -> None:
        self.segment_id = uuid4()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.path = self.segment_dir / f"{stamp}-{self.segment_id}.ctattach"
        self._file = self.path.open("ab", buffering=0)
        self._created = datetime.now(timezone.utc)
        self._entries: list[dict[str, object]] = []

    def _sampling_probability(self, priority: EvidencePriority) -> float:
        if priority in self.policy.always_preserve_priorities:
            return 1.0
        maximum = self.policy.maximum_rate_per_minute
        if maximum is None or maximum <= 0:
            return 1.0
        now = time.monotonic()
        while self._arrival_times and self._arrival_times[0] < now - 60:
            self._arrival_times.popleft()
        observed = len(self._arrival_times) + 1
        self._arrival_times.append(now)
        if observed <= maximum:
            return 1.0
        return max(self.policy.minimum_sampling_probability, maximum / observed)

    def store(
        self,
        *,
        event_id: UUID,
        event_sequence: int,
        content_type: str,
        payload: bytes,
        priority: EvidencePriority = EvidencePriority.ORDINARY,
        schema_version: int = 1,
    ) -> AttachmentReference:
        content_hash = hashlib.sha256(payload).hexdigest()
        if not self.policy.enabled:
            return self._reference(event_id, event_sequence, content_type, schema_version, payload, b"", content_hash, False, AttachmentSamplingDecision.DISABLED)
        if self.policy.maximum_attachment_bytes is not None and len(payload) > self.policy.maximum_attachment_bytes:
            return self._reference(event_id, event_sequence, content_type, schema_version, payload, b"", content_hash, False, AttachmentSamplingDecision.TOO_LARGE)
        probability = self._sampling_probability(priority)
        if random.random() > probability:
            return self._reference(event_id, event_sequence, content_type, schema_version, payload, b"", content_hash, False, AttachmentSamplingDecision.SAMPLED_OUT)
        compressed = gzip.compress(payload, compresslevel=self.policy.compression.level) if self.policy.compression.enabled else payload
        with self._lock:
            if self._file is None:
                self._open_segment()
            assert self._file is not None
            entry_header = json.dumps({
                "attachment_id": str(uuid4()),
                "event_id": str(event_id),
                "event_sequence": event_sequence,
                "content_type": content_type,
                "schema_version": schema_version,
                "uncompressed_bytes": len(payload),
                "compressed_bytes": len(compressed),
                "content_hash": content_hash,
                "compressed_hash": hashlib.sha256(compressed).hexdigest(),
                "sampling_probability": probability,
            }, sort_keys=True, separators=(",", ":")).encode()
            block = len(entry_header).to_bytes(4, "big") + entry_header + len(compressed).to_bytes(8, "big") + compressed
            if self._entries and (
                self._file.tell() + len(block) > self.policy.rotation.maximum_segment_bytes
                or (datetime.now(timezone.utc) - self._created).total_seconds() >= self.policy.rotation.maximum_segment_seconds
            ):
                self.close_segment()
                self._open_segment()
            offset = self._file.tell()
            self._file.write(block)
            entry = json.loads(entry_header)
            entry.update({"offset": offset, "total_bytes": len(block)})
            self._entries.append(entry)
            return AttachmentReference(
                attachment_id=UUID(entry["attachment_id"]), event_id=event_id, event_sequence=event_sequence,
                content_type=content_type, schema_version=schema_version,
                uncompressed_bytes=len(payload), compressed_bytes=len(compressed),
                compression=CompressionAlgorithm.GZIP if self.policy.compression.enabled else CompressionAlgorithm.NONE,
                content_hash=content_hash, compressed_hash=entry["compressed_hash"],
                attachment_segment_id=self.segment_id, segment_offset=offset, stored=True,
                sampling_decision=AttachmentSamplingDecision.STORED,
                signature_status=SignatureStatus.HASHED_AND_CHAINED,
            )

    def _reference(self, event_id, event_sequence, content_type, schema_version, payload, compressed, content_hash, stored, decision):
        return AttachmentReference(
            attachment_id=uuid4(), event_id=event_id, event_sequence=event_sequence,
            content_type=content_type, schema_version=schema_version,
            uncompressed_bytes=len(payload), compressed_bytes=len(compressed),
            compression=CompressionAlgorithm.GZIP if compressed else CompressionAlgorithm.NONE,
            content_hash=content_hash, compressed_hash=hashlib.sha256(compressed).hexdigest() if compressed else "",
            attachment_segment_id=None, segment_offset=None, stored=stored,
            sampling_decision=decision, signature_status=SignatureStatus.UNSIGNED,
        )

    def close_segment(self) -> dict[str, object] | None:
        with self._lock:
            if self._file is None or self._file.closed:
                return None
            self._file.flush()
            os.fsync(self._file.fileno())
            self._file.close()
            segment_hash = hashlib.sha256(self.path.read_bytes()).hexdigest()
            manifest = {
                "manifest_id": str(uuid4()),
                "segment_id": str(self.segment_id),
                "path": str(self.path),
                "created_at": self._created.isoformat(),
                "closed_at": datetime.now(timezone.utc).isoformat(),
                "segment_hash": segment_hash,
                "previous_segment_hash": self._previous_hash,
                "attachment_count": len(self._entries),
                "attachments": self._entries,
            }
            (self.manifest_dir / f"{self.segment_id}.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
            self._previous_hash = segment_hash
            self._retention()
            self._file = None
            self._entries = []
            return manifest

    def _retention(self) -> None:
        paths = sorted(self.segment_dir.glob("*.ctattach"), key=lambda item: item.stat().st_mtime)
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

    def close(self) -> dict[str, object] | None:
        return self.close_segment()
