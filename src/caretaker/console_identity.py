"""Ephemeral console identity publication and durable public-key records."""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID


CONSOLE_IDENTITY_SCHEMA_VERSION = 1
_PUBLIC_KEY_BYTES = 32
_MAX_IDENTITY_TEXT = 256


def normalize_console_public_identity(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Validate the public portion of an ephemeral console identity.

    Private key material is rejected rather than ignored so a caller cannot
    accidentally place it in the audit stream or identity database.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("console identity must be an object")
    if any(str(key).lower() in {"private_key", "private_key_bytes", "secret"} for key in value):
        raise ValueError("console identity cannot contain private key material")
    try:
        identity_id = str(UUID(str(value.get("identity_id"))))
    except (TypeError, ValueError) as exc:
        raise ValueError("console identity_id must be a UUID") from exc
    algorithm = str(value.get("algorithm") or "").strip().lower()
    encoding = str(value.get("encoding") or "").strip().lower()
    if algorithm != "ed25519" or encoding != "base64":
        raise ValueError("console identity must use base64-encoded ed25519")
    encoded_key = value.get("public_key")
    if not isinstance(encoded_key, str) or len(encoded_key) > _MAX_IDENTITY_TEXT:
        raise ValueError("console public_key must be a bounded base64 string")
    try:
        public_key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("console public_key is not valid base64") from exc
    if len(public_key) != _PUBLIC_KEY_BYTES:
        raise ValueError("console public_key must contain 32 bytes")
    fingerprint = str(value.get("public_key_fingerprint") or "").strip().lower()
    expected = hashlib.sha256(public_key).hexdigest()
    if fingerprint != expected:
        raise ValueError("console public_key_fingerprint does not match public_key")
    return {
        "identity_id": identity_id,
        "algorithm": algorithm,
        "encoding": encoding,
        "public_key": encoded_key,
        "public_key_fingerprint": fingerprint,
    }


class ConsoleIdentityStore:
    """Durable public-key journal for console invocation attribution."""

    def __init__(self, root: str | Path) -> None:
        self.path = Path(root) / "security" / "console-identities.sqlite"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS console_identities (
                    invocation_id TEXT PRIMARY KEY,
                    identity_id TEXT NOT NULL UNIQUE,
                    public_key BLOB NOT NULL,
                    public_key_fingerprint TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    encoding TEXT NOT NULL,
                    process_id INTEGER NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT
                )
                """
            )

    def record_start(
        self,
        invocation_id: str,
        *,
        identity: Mapping[str, Any],
        process_id: int,
        uid: int,
        gid: int,
        started_at: datetime | None = None,
    ) -> dict[str, Any]:
        try:
            invocation = str(UUID(str(invocation_id)))
        except (TypeError, ValueError) as exc:
            raise ValueError("invocation_id must be a UUID") from exc
        normalized = normalize_console_public_identity(identity)
        if normalized is None:
            raise ValueError("console invocation identity is required")
        timestamp = (started_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        key = base64.b64decode(normalized["public_key"], validate=True)
        row = {
            "invocation_id": invocation,
            "identity_id": normalized["identity_id"],
            "public_key": normalized["public_key"],
            "public_key_fingerprint": normalized["public_key_fingerprint"],
            "algorithm": normalized["algorithm"],
            "encoding": normalized["encoding"],
            "process_id": int(process_id),
            "uid": int(uid),
            "gid": int(gid),
            "started_at": timestamp.isoformat(),
            "ended_at": None,
        }
        with self._lock, sqlite3.connect(self.path) as connection:
            existing = connection.execute(
                "SELECT identity_id, public_key_fingerprint FROM console_identities WHERE invocation_id = ?",
                (invocation,),
            ).fetchone()
            if existing is not None:
                if tuple(existing) != (row["identity_id"], row["public_key_fingerprint"]):
                    raise ValueError("console invocation identity conflicts with an existing record")
                return self.get(invocation) or row
            try:
                connection.execute(
                    """
                    INSERT INTO console_identities
                    (invocation_id, identity_id, public_key, public_key_fingerprint,
                     algorithm, encoding, process_id, uid, gid, started_at, ended_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["invocation_id"], row["identity_id"], key,
                        row["public_key_fingerprint"], row["algorithm"], row["encoding"],
                        row["process_id"], row["uid"], row["gid"], row["started_at"], None,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("console identity is already recorded") from exc
        return row

    def record_end(
        self,
        invocation_id: str,
        *,
        process_id: int,
        ended_at: datetime | None = None,
    ) -> dict[str, Any] | None:
        invocation = str(UUID(str(invocation_id)))
        timestamp = (ended_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        with self._lock, sqlite3.connect(self.path) as connection:
            cursor = connection.execute(
                "UPDATE console_identities SET ended_at = ? WHERE invocation_id = ? AND process_id = ?",
                (timestamp, invocation, int(process_id)),
            )
            if cursor.rowcount != 1:
                raise PermissionError("console invocation identity is not owned by this process")
        return self.get(invocation)

    def get(self, invocation_id: str) -> dict[str, Any] | None:
        invocation = str(UUID(str(invocation_id)))
        with self._lock, sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT invocation_id, identity_id, public_key, public_key_fingerprint, algorithm, encoding, process_id, uid, gid, started_at, ended_at FROM console_identities WHERE invocation_id = ?",
                (invocation,),
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["public_key"] = base64.b64encode(value["public_key"]).decode("ascii")
        return value
