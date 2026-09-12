from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Mapping
from uuid import UUID

from .models import LogChannel, LogEnvelope

MAGIC = b"CTLG"
FORMAT_VERSION = 1
HEADER = struct.Struct(">4sHHI32s")
TLV_HEADER = struct.Struct(">HHI")
TAG_WRITER_VERSION = 1
TAG_RECORD_JSON = 2
MAX_RECORD_BYTES = 4096


class RecordFormatError(ValueError):
    pass


def _json_default(value: Any) -> Any:
    if isinstance(value, UUID):
        return {"$uuid": str(value)}
    if isinstance(value, datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, Enum):
        return {"$enum": f"{type(value).__name__}.{value.name}"}
    raise TypeError(f"Unsupported value: {type(value).__name__}")


def _object_hook(value: dict[str, Any]) -> Any:
    if "$uuid" in value:
        return UUID(value["$uuid"])
    if "$datetime" in value:
        return datetime.fromisoformat(value["$datetime"])
    if "$enum" in value:
        type_name, name = value["$enum"].split(".", 1)
        if type_name == "LogChannel":
            return LogChannel[name]
        return name
    return value


def _tlv(tag: int, version: int, data: bytes) -> bytes:
    return TLV_HEADER.pack(tag, version, len(data)) + data


class TLVLogCodec:
    """Versioned, TIFF-like framed record codec.

    Older readers skip unknown TLV fields. The primary record is intentionally
    limited to one typical 4 KiB filesystem block.
    """

    def __init__(self, *, maximum_record_bytes: int = MAX_RECORD_BYTES) -> None:
        self.maximum_record_bytes = maximum_record_bytes

    def encode(self, envelope: LogEnvelope, *, extra_fields: Iterable[tuple[int, int, bytes]] = ()) -> bytes:
        payload = json.dumps(
            asdict(envelope),
            default=_json_default,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        body = _tlv(TAG_WRITER_VERSION, 1, envelope.writer_version.encode())
        body += _tlv(TAG_RECORD_JSON, envelope.schema_version, payload)
        for tag, version, data in extra_fields:
            body += _tlv(tag, version, data)
        total = HEADER.size + len(body)
        if total > self.maximum_record_bytes:
            raise RecordFormatError(
                f"Encoded record is {total} bytes; maximum is {self.maximum_record_bytes}. "
                "Store large evidence in the attachment stream."
            )
        checksum = hashlib.sha256(body).digest()
        return HEADER.pack(MAGIC, FORMAT_VERSION, 0, total, checksum) + body

    def decode(self, record: bytes) -> LogEnvelope:
        if len(record) < HEADER.size:
            raise RecordFormatError("Record is shorter than the fixed header")
        magic, format_version, _flags, total, expected = HEADER.unpack(record[:HEADER.size])
        if magic != MAGIC:
            raise RecordFormatError("Invalid Caretaker record magic")
        if format_version > FORMAT_VERSION:
            # Parse known TLVs where possible. Unknown versions are tolerated.
            pass
        if total != len(record):
            raise RecordFormatError(f"Record length mismatch: header={total}, observed={len(record)}")
        body = record[HEADER.size:]
        if hashlib.sha256(body).digest() != expected:
            raise RecordFormatError("Record checksum mismatch")
        offset = 0
        payload: bytes | None = None
        while offset < len(body):
            if offset + TLV_HEADER.size > len(body):
                raise RecordFormatError("Truncated TLV header")
            tag, _version, length = TLV_HEADER.unpack(body[offset:offset + TLV_HEADER.size])
            offset += TLV_HEADER.size
            end = offset + length
            if end > len(body):
                raise RecordFormatError("Truncated TLV field")
            value = body[offset:end]
            offset = end
            if tag == TAG_RECORD_JSON:
                payload = value
        if payload is None:
            raise RecordFormatError("Record does not contain a known envelope field")
        data = json.loads(payload.decode(), object_hook=_object_hook)
        # asdict converts tuples to lists only through JSON; normalize them here.
        for field in ("guard_deviation_ids", "behavior_event_ids", "attachment_ids"):
            data[field] = tuple(data.get(field, ()))
        if isinstance(data.get("channel"), str):
            data["channel"] = LogChannel[data["channel"]]
        return LogEnvelope(**data)

    def record_length(self, prefix: bytes) -> int:
        if len(prefix) < HEADER.size:
            raise RecordFormatError("Insufficient bytes for record header")
        magic, _version, _flags, total, _checksum = HEADER.unpack(prefix[:HEADER.size])
        if magic != MAGIC:
            raise RecordFormatError("Invalid Caretaker record magic")
        return total
