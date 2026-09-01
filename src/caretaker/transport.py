"""Bounded application-local transport primitives.

The application owns the queue and its process topology.  Caretaker places
only canonical JSON bytes on the queue, verifies the envelope on receipt, and
leaves authority, admission, and policy decisions to the existing supervisor
boundaries.  The same primitive works with :mod:`queue` and an application-
owned ``multiprocessing.Queue`` without making either queue an authority
channel.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
import queue
from typing import Any
from uuid import UUID, uuid4


APPLICATION_TRANSPORT_SCHEMA_VERSION = 1
APPLICATION_TRANSPORT_MAX_MESSAGE_BYTES = 128 * 1024
APPLICATION_TRANSPORT_MAX_MESSAGE_TYPE_CHARS = 64
APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES = 256


class ApplicationTransportError(ValueError):
    """Raised when an application-local transport cannot preserve a message."""


def _canonical_json(value: Any, *, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApplicationTransportError(f"{label} is not bounded JSON data") from exc


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class ApplicationLocalQueueTransport:
    """Send and receive bounded, integrity-checked JSON messages on a queue.

    The queue must be supplied by the embedding application.  ``send`` is
    non-blocking and raises :class:`ApplicationTransportError` when the queue
    is full.  A received message is untrusted data; its ``sender_pid`` is
    provenance only and must never be used as an authentication decision.
    """

    def __init__(
        self,
        channel: Any,
        *,
        maximum_message_bytes: int = APPLICATION_TRANSPORT_MAX_MESSAGE_BYTES,
    ) -> None:
        if not callable(getattr(channel, "put_nowait", None)):
            raise TypeError("application transport channel must provide put_nowait")
        if not callable(getattr(channel, "get_nowait", None)):
            raise TypeError("application transport channel must provide get_nowait")
        if not 1 <= int(maximum_message_bytes) <= APPLICATION_TRANSPORT_MAX_MESSAGE_BYTES:
            raise ValueError(
                "maximum_message_bytes must be between 1 and "
                f"{APPLICATION_TRANSPORT_MAX_MESSAGE_BYTES}"
            )
        self.channel = channel
        self.maximum_message_bytes = int(maximum_message_bytes)

    def send(
        self,
        message_type: str,
        payload: Mapping[str, Any],
        *,
        message_id: str | UUID | None = None,
    ) -> dict[str, Any]:
        if not isinstance(message_type, str) or not message_type.strip():
            raise ValueError("application transport message_type cannot be empty")
        message_type = message_type.strip()
        if len(message_type) > APPLICATION_TRANSPORT_MAX_MESSAGE_TYPE_CHARS:
            raise ValueError(
                "application transport message_type exceeds "
                f"{APPLICATION_TRANSPORT_MAX_MESSAGE_TYPE_CHARS} characters"
            )
        if not isinstance(payload, Mapping):
            raise TypeError("application transport payload must be an object")
        try:
            parsed_message_id = UUID(str(message_id)) if message_id is not None else uuid4()
        except (TypeError, ValueError) as exc:
            raise ValueError("application transport message_id must be a UUID") from exc

        payload_object = dict(payload)
        payload_bytes = _canonical_json(
            payload_object,
            label="application transport payload",
        )
        body = {
            "schema_version": APPLICATION_TRANSPORT_SCHEMA_VERSION,
            "message_id": str(parsed_message_id),
            "message_type": message_type,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sender_pid": os.getpid(),
            "payload": payload_object,
            "payload_sha256": _sha256(payload_bytes),
        }
        content_hash = _sha256(
            _canonical_json(body, label="application transport envelope")
        )
        encoded = _canonical_json(
            {**body, "content_sha256": content_hash},
            label="application transport envelope",
        )
        if len(encoded) > self.maximum_message_bytes:
            raise ApplicationTransportError(
                f"application transport message exceeds {self.maximum_message_bytes} bytes"
            )
        try:
            self.channel.put_nowait(encoded)
        except queue.Full as exc:
            raise ApplicationTransportError("application transport queue is full") from exc
        except (OSError, ValueError, EOFError) as exc:
            raise ApplicationTransportError("application transport queue is unavailable") from exc
        return {
            "message_id": str(parsed_message_id),
            "message_type": message_type,
            "bytes": len(encoded),
            "content_sha256": content_hash,
        }

    def receive(self, *, timeout: float = 0.0) -> dict[str, Any] | None:
        if float(timeout) < 0:
            raise ValueError("application transport receive timeout cannot be negative")
        try:
            if timeout:
                raw = self.channel.get(timeout=float(timeout))
            else:
                raw = self.channel.get_nowait()
        except queue.Empty:
            return None
        except (OSError, ValueError, EOFError) as exc:
            raise ApplicationTransportError("application transport queue is unavailable") from exc
        if not isinstance(raw, (bytes, bytearray)):
            raise ApplicationTransportError("application transport message must be bytes")
        encoded = bytes(raw)
        if len(encoded) > self.maximum_message_bytes:
            raise ApplicationTransportError(
                f"application transport message exceeds {self.maximum_message_bytes} bytes"
            )
        try:
            envelope = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApplicationTransportError(
                "application transport message is invalid JSON"
            ) from exc
        if not isinstance(envelope, Mapping):
            raise ApplicationTransportError(
                "application transport envelope must be an object"
            )
        expected = {
            "schema_version",
            "message_id",
            "message_type",
            "created_at",
            "sender_pid",
            "payload",
            "payload_sha256",
            "content_sha256",
        }
        if set(envelope) != expected:
            raise ApplicationTransportError("application transport envelope fields are invalid")
        if envelope.get("schema_version") != APPLICATION_TRANSPORT_SCHEMA_VERSION:
            raise ApplicationTransportError("unsupported application transport schema")
        try:
            message_id = UUID(str(envelope["message_id"]))
        except (TypeError, ValueError) as exc:
            raise ApplicationTransportError(
                "application transport message_id is invalid"
            ) from exc
        message_type = envelope.get("message_type")
        if (
            not isinstance(message_type, str)
            or not message_type.strip()
            or len(message_type) > APPLICATION_TRANSPORT_MAX_MESSAGE_TYPE_CHARS
        ):
            raise ApplicationTransportError("application transport message_type is invalid")
        if (
            isinstance(envelope.get("sender_pid"), bool)
            or not isinstance(envelope.get("sender_pid"), int)
            or envelope["sender_pid"] < 0
        ):
            raise ApplicationTransportError("application transport sender_pid is invalid")
        payload = envelope.get("payload")
        if not isinstance(payload, Mapping):
            raise ApplicationTransportError(
                "application transport payload must be an object"
            )
        payload_bytes = _canonical_json(
            dict(payload),
            label="application transport payload",
        )
        payload_hash = envelope.get("payload_sha256")
        if not isinstance(payload_hash, str) or payload_hash != _sha256(payload_bytes):
            raise ApplicationTransportError("application transport payload hash is invalid")
        body = {key: envelope[key] for key in expected if key != "content_sha256"}
        content_hash = envelope.get("content_sha256")
        if not isinstance(content_hash, str) or content_hash != _sha256(
            _canonical_json(body, label="application transport envelope")
        ):
            raise ApplicationTransportError(
                "application transport content hash is invalid"
            )
        return {
            "schema_version": APPLICATION_TRANSPORT_SCHEMA_VERSION,
            "message_id": str(message_id),
            "message_type": message_type.strip(),
            "created_at": envelope["created_at"],
            "sender_pid": envelope["sender_pid"],
            "payload": dict(payload),
            "payload_sha256": payload_hash,
            "content_sha256": content_hash,
        }

    def drain(
        self,
        *,
        limit: int = APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES,
    ) -> tuple[dict[str, Any], ...]:
        if not 1 <= int(limit) <= APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES:
            raise ValueError(
                "application transport drain limit must be between 1 and "
                f"{APPLICATION_TRANSPORT_MAX_DRAIN_MESSAGES}"
            )
        messages: list[dict[str, Any]] = []
        for _ in range(int(limit)):
            message = self.receive()
            if message is None:
                break
            messages.append(message)
        return tuple(messages)
