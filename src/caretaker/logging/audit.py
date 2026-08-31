from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .models import EvidencePriority


AUDIT_SCHEMA_VERSION = 1
_EVENT_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")


class AuditStreamError(RuntimeError):
    """Raised when the local audit stream cannot preserve its integrity."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")


def _json_default(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, EvidencePriority):
        return value.name
    raise TypeError(f"Unsupported audit value: {type(value).__name__}")


def _copy_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AuditStreamError("Audit fields must be mappings")
    return {str(key): item for key, item in value.items()}


class AuditStreamWriter:
    """Small append-only writer for high-value Caretaker decisions.

    The stream is deliberately not a logging handler and has no read or command
    interface.  Each line is self-contained JSON so an external collector can
    ship it without understanding the primary binary event format.  The local
    file remains bounded by the configured event size; larger evidence must be
    represented by references in ``details``.
    """

    def __init__(
        self,
        policy: Any,
        *,
        directory: str | Path,
        run_id: UUID,
        process_start_id: UUID,
        supervisor_id: UUID | str | None = None,
    ) -> None:
        self.policy = policy
        self.run_id = run_id
        self.process_start_id = process_start_id
        self.supervisor_id = str(supervisor_id) if supervisor_id is not None else None
        self.path = Path(directory) / policy.file_name
        self._lock = threading.RLock()
        self._closed = False
        self._sequence = 0
        self._previous_hash: str | None = None
        self._file = None
        if not policy.enabled:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._recover_existing()
        self._file = self.path.open("ab", buffering=0)

    @property
    def enabled(self) -> bool:
        return self._file is not None and not self._closed

    @property
    def previous_hash(self) -> str | None:
        return self._previous_hash

    def _recover_existing(self) -> None:
        if not self.path.exists():
            return
        last_valid_offset = 0
        last_sequence = 0
        previous_hash: str | None = None
        with self.path.open("rb") as stream:
            while True:
                line_start = stream.tell()
                line = stream.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    # A process can die after writing a complete prefix.  It is
                    # safe to discard only this incomplete final line.
                    break
                try:
                    event = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AuditStreamError(
                        f"Malformed complete audit record at byte {line_start}"
                    ) from exc
                self._validate_existing(event, last_sequence, previous_hash)
                last_valid_offset = stream.tell()
                last_sequence = int(event["stream_sequence"])
                previous_hash = str(event["integrity"]["content_sha256"])
        if last_valid_offset != self.path.stat().st_size:
            with self.path.open("r+b") as stream:
                stream.truncate(last_valid_offset)
        self._sequence = last_sequence
        self._previous_hash = previous_hash

    def _validate_existing(
        self,
        event: Any,
        previous_sequence: int,
        previous_hash: str | None,
    ) -> None:
        if not isinstance(event, Mapping):
            raise AuditStreamError("Audit record is not an object")
        sequence = event.get("stream_sequence")
        if not isinstance(sequence, int) or sequence != previous_sequence + 1:
            raise AuditStreamError("Audit stream sequence is not contiguous")
        integrity = event.get("integrity")
        if not isinstance(integrity, Mapping):
            raise AuditStreamError("Audit record has no integrity object")
        expected_previous = integrity.get("previous_event_hash")
        if self.policy.hash_chain and expected_previous != previous_hash:
            raise AuditStreamError("Audit stream previous-event hash does not match")
        body = dict(event)
        body.pop("integrity", None)
        expected_content = hashlib.sha256(_canonical(body)).hexdigest()
        if integrity.get("content_sha256") != expected_content:
            raise AuditStreamError("Audit record content hash does not match")

    def update_policy(self, policy: Any) -> tuple[str, ...]:
        warnings: list[str] = []
        if policy.file_name != self.policy.file_name:
            warnings.append("logging.audit.file_name is startup-bound; the existing file remains active")
        if policy.enabled != self.policy.enabled:
            warnings.append("logging.audit.enabled is run-bound; a new run is required")
        if policy.hash_chain != self.policy.hash_chain:
            warnings.append("logging.audit.hash_chain is run-bound; a new run is required")
        if policy.maximum_event_bytes != self.policy.maximum_event_bytes:
            warnings.append("logging.audit.maximum_event_bytes is startup-bound; the existing limit remains active")
        return tuple(warnings)

    def emit(
        self,
        event_type: str,
        *,
        actor: Mapping[str, Any] | None = None,
        scope: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        outcome: Mapping[str, Any] | None = None,
        details: Mapping[str, Any] | None = None,
        priority: EvidencePriority = EvidencePriority.IMPORTANT,
        occurred_at: datetime | None = None,
        monotonic_ns: int | None = None,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        if not isinstance(event_type, str) or _EVENT_TYPE.fullmatch(event_type) is None:
            raise AuditStreamError("Audit event_type must be an uppercase registry name")
        if not isinstance(priority, EvidencePriority):
            raise AuditStreamError("Audit priority must be an EvidencePriority")
        with self._lock:
            if self._closed or self._file is None:
                return None
            self._sequence += 1
            timestamp = occurred_at or datetime.now(timezone.utc)
            body: dict[str, Any] = {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "event_type": event_type,
                "event_version": 1,
                "event_id": str(uuid4()),
                "stream_sequence": self._sequence,
                "occurred_at": timestamp.isoformat(),
                "monotonic_ns": monotonic_ns if monotonic_ns is not None else time.monotonic_ns(),
                "process_start_id": str(self.process_start_id),
                "run_id": str(self.run_id),
                "supervisor_id": self.supervisor_id,
                "priority": priority.name,
                "actor": _copy_mapping(actor),
                "scope": _copy_mapping(scope),
                "policy": _copy_mapping(policy),
                "outcome": _copy_mapping(outcome),
                "details": _copy_mapping(details),
            }
            content_hash = hashlib.sha256(_canonical(body)).hexdigest()
            event = dict(body)
            event["integrity"] = {
                "previous_event_hash": self._previous_hash if self.policy.hash_chain else None,
                "content_sha256": content_hash,
                "hash_chain": self.policy.hash_chain,
            }
            encoded = _canonical(event) + b"\n"
            if len(encoded) > self.policy.maximum_event_bytes:
                self._sequence -= 1
                raise AuditStreamError(
                    f"Audit event is {len(encoded)} bytes; maximum is "
                    f"{self.policy.maximum_event_bytes}"
                )
            try:
                self._file.write(encoded)
                if priority is EvidencePriority.CRITICAL and self.policy.flush_critical:
                    self._file.flush()
                    os.fsync(self._file.fileno())
            except OSError as exc:
                raise AuditStreamError("Unable to persist audit event") from exc
            self._previous_hash = content_hash
            return event

    def flush(self) -> None:
        with self._lock:
            if self._file is not None and not self._closed:
                self._file.flush()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._file is not None:
                self._file.flush()
                self._file.close()
            self._closed = True
