from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing as mp
import os
import resource
import time
from dataclasses import replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Mapping, Protocol
from uuid import UUID, uuid4

from .models import (
    KeyTransition,
    RuntimeIdentityAnchoringState,
    RuntimeRecordIntegrityMode,
    RuntimeSignedArtifact,
    RuntimeSignedManifest,
    RuntimeSigningIdentity,
)
from .policy import RuntimeSigningPolicy


class SigningUnavailable(RuntimeError):
    pass


class ExternalManifestSigner(Protocol):
    """Backward-compatible external signer contract.

    New integrations should implement ``sign_artifact``.  Caretaker also accepts
    the older ``sign_manifest`` method for external signers during migration.
    ``public_identity`` should expose at least a stable identity and, for local
    verification, an Ed25519 ``public_key`` (bytes or base64 text).
    """

    def public_identity(self) -> Mapping[str, Any]: ...
    def sign_manifest(self, payload: bytes) -> bytes: ...


class ExternalArtifactSigner(Protocol):
    def public_identity(self) -> Mapping[str, Any]: ...
    def sign_artifact(self, payload: bytes) -> bytes: ...


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:
        raise SigningUnavailable(
            "Ephemeral signing requires the optional 'cryptography' package; "
            "install Caretaker[signing]"
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey, serialization


def _public_bytes(private_key) -> bytes:
    _, _, serialization = _crypto()
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _convert(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, Mapping):
        return {
            str(key): _convert(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_convert(item) for item in value]
    return value


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(_convert(payload), sort_keys=True, separators=(",", ":")).encode()


def _artifact_unsigned(artifact: RuntimeSignedArtifact) -> dict[str, Any]:
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_kind": artifact.artifact_kind,
        "application_id": artifact.application_id,
        "run_id": artifact.run_id,
        "process_start_id": artifact.process_start_id,
        "signer_identity_id": artifact.signer_identity_id,
        "signer_mode": artifact.signer_mode.name,
        "public_key_fingerprint": artifact.public_key_fingerprint,
        "key_epoch": artifact.key_epoch,
        "content_hash": artifact.content_hash,
        "previous_artifact_hash": artifact.previous_artifact_hash,
        "context": dict(artifact.context),
        "signed_at": artifact.signed_at,
    }


def serialize_signed_artifact(artifact: RuntimeSignedArtifact) -> dict[str, Any]:
    value = _convert(_artifact_unsigned(artifact))
    value["signature"] = base64.b64encode(artifact.signature).decode("ascii")
    return value


def deserialize_signed_artifact(value: Mapping[str, Any]) -> RuntimeSignedArtifact:
    return RuntimeSignedArtifact(
        artifact_id=UUID(str(value["artifact_id"])),
        artifact_kind=str(value["artifact_kind"]),
        application_id=str(value["application_id"]),
        run_id=UUID(str(value["run_id"])),
        process_start_id=UUID(str(value["process_start_id"])),
        signer_identity_id=str(value["signer_identity_id"]),
        signer_mode=RuntimeRecordIntegrityMode[str(value["signer_mode"])],
        public_key_fingerprint=(
            str(value["public_key_fingerprint"])
            if value.get("public_key_fingerprint")
            else None
        ),
        key_epoch=int(value["key_epoch"]) if value.get("key_epoch") is not None else None,
        content_hash=str(value["content_hash"]),
        previous_artifact_hash=(
            str(value["previous_artifact_hash"])
            if value.get("previous_artifact_hash")
            else None
        ),
        context=dict(value.get("context") or {}),
        signed_at=datetime.fromisoformat(str(value["signed_at"])),
        signature=base64.b64decode(str(value["signature"])),
    )


def verify_signed_artifact(artifact: RuntimeSignedArtifact, public_key: bytes) -> bool:
    if artifact.public_key_fingerprint:
        if hashlib.sha256(public_key).hexdigest() != artifact.public_key_fingerprint:
            return False
    _, Ed25519PublicKey, _ = _crypto()
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            artifact.signature, _canonical(_artifact_unsigned(artifact))
        )
        return True
    except Exception:
        return False


def public_key_from_identity_records(
    records: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
    fingerprint: str,
) -> bytes | None:
    for row in reversed(tuple(records)):
        record = row.get("record") or {}
        if str(record.get("public_key_fingerprint") or "") != fingerprint:
            continue
        public_key = _record_public_key(record)
        if public_key is not None:
            return public_key
    return None


def verify_identity_record_set(
    records: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
    fingerprint: str,
    *,
    require_complete_hash_chain: bool = True,
) -> tuple[bool, str | None]:
    """Verify exported public identity records without requiring the original journal path."""
    rows = sorted(
        (dict(row) for row in records),
        key=lambda row: int(row.get("sequence") or 0),
    )
    if require_complete_hash_chain:
        previous: str | None = None
        for row in rows:
            if row.get("previous_record_hash") != previous:
                return False, "exported signing identity records do not form a complete hash chain"
            unsigned = {key: value for key, value in row.items() if key != "record_sha256"}
            expected = hashlib.sha256(_canonical(unsigned)).hexdigest()
            observed = str(row.get("record_sha256") or "")
            if expected != observed:
                return False, "exported signing identity record SHA-256 is invalid"
            previous = observed

    target_row: Mapping[str, Any] | None = None
    for row in rows:
        record = row.get("record") or {}
        if (
            row.get("record_type") in {"IDENTITY_CREATED", "IDENTITY_EPOCH", "EXTERNAL_IDENTITY"}
            and str(record.get("public_key_fingerprint") or "") == fingerprint
        ):
            target_row = row
    if target_row is None:
        return False, "signing identity fingerprint is absent from exported identity records"
    if target_row.get("record_type") == "EXTERNAL_IDENTITY":
        return (
            True,
            None,
        ) if public_key_from_identity_records(rows, fingerprint) is not None else (
            False,
            "external signing identity has no locally verifiable public key",
        )

    target = target_row.get("record") or {}
    identity_id = str(target.get("identity_id") or "")
    target_epoch = int(target.get("key_epoch") or 0)
    identities: dict[int, Mapping[str, Any]] = {}
    transitions: dict[tuple[int, int], Mapping[str, Any]] = {}
    for row in rows:
        record = row.get("record") or {}
        if str(record.get("identity_id") or "") != identity_id:
            continue
        if row.get("record_type") in {"IDENTITY_CREATED", "IDENTITY_EPOCH"}:
            identities[int(record.get("key_epoch") or 0)] = record
        elif row.get("record_type") == "KEY_TRANSITION":
            transitions[(int(record.get("from_epoch") or 0), int(record.get("to_epoch") or 0))] = record
    if not identity_id or target_epoch < 1 or 1 not in identities:
        return False, "ephemeral signing identity chain is incomplete"
    current_key = _record_public_key(identities[1])
    if current_key is None:
        return False, "ephemeral signing identity epoch 1 has no public key"
    if hashlib.sha256(current_key).hexdigest() != str(identities[1].get("public_key_fingerprint") or ""):
        return False, "ephemeral signing identity epoch 1 fingerprint is invalid"
    try:
        identity_uuid = UUID(identity_id)
        run_uuid = UUID(str(identities[1].get("run_id") or target.get("run_id")))
    except ValueError:
        return False, "ephemeral signing identity contains an invalid UUID"
    for epoch in range(1, target_epoch):
        record = transitions.get((epoch, epoch + 1))
        next_identity = identities.get(epoch + 1)
        if record is None or next_identity is None:
            return False, f"ephemeral signing identity chain is incomplete at epoch {epoch}"
        new_key = _record_public_key(record, field="new_public_key")
        signature = _record_public_key(record, field="signature")
        if new_key is None or signature is None:
            return False, f"ephemeral key transition {epoch}->{epoch + 1} is malformed"
        transition = KeyTransition(
            from_epoch=epoch,
            to_epoch=epoch + 1,
            old_public_key_fingerprint=str(record.get("old_public_key_fingerprint") or ""),
            new_public_key=new_key,
            new_public_key_fingerprint=str(record.get("new_public_key_fingerprint") or ""),
            created_at=datetime.fromisoformat(str(record.get("created_at"))),
            signature=signature,
            next_event_sequence=int(record.get("next_event_sequence") or 0),
        )
        if transition.old_public_key_fingerprint != hashlib.sha256(current_key).hexdigest():
            return False, f"ephemeral key transition {epoch}->{epoch + 1} has the wrong old-key fingerprint"
        if transition.new_public_key_fingerprint != hashlib.sha256(new_key).hexdigest():
            return False, f"ephemeral key transition {epoch}->{epoch + 1} has the wrong new-key fingerprint"
        if not KeyEvolutionSigner.verify_transition(
            transition, current_key, identity_id=identity_uuid, run_id=run_uuid
        ):
            return False, f"ephemeral key transition {epoch}->{epoch + 1} signature is invalid"
        if _record_public_key(next_identity) != new_key:
            return False, f"ephemeral identity epoch {epoch + 1} does not match its signed transition"
        if int(next_identity.get("first_event_sequence") or 0) != transition.next_event_sequence:
            return False, f"ephemeral identity epoch {epoch + 1} has the wrong first event sequence"
        current_key = new_key
    if hashlib.sha256(current_key).hexdigest() != fingerprint:
        return False, "ephemeral signing identity chain does not terminate at the requested key"
    return True, None


class SigningIdentityJournal:
    """Independent hash-chained public signing-identity log.

    This journal deliberately contains no private key material.  It is separate
    from the application event stream so operators can retain signing identities
    for as long as any dependent snapshots or archives remain verifiable.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        run_id: UUID,
        enabled: bool = True,
        maximum_age_days: int | None = 3650,
        maximum_files: int | None = None,
    ) -> None:
        self.root = Path(root)
        self.directory = self.root / "security" / "signing-identities"
        self.enabled = enabled
        self.maximum_age_days = maximum_age_days
        self.maximum_files = maximum_files
        self.run_id = run_id
        self.path = self.directory / f"{run_id}.jsonl"
        self._lock = RLock()
        self._seen_identity_fingerprints: set[str] = set()
        self._seen_transition_keys: set[tuple[str, int, int]] = set()
        self._previous_hash: str | None = None
        self._sequence = 0
        if self.enabled:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                self.directory.chmod(0o700)
            except OSError:
                pass
            self._load_tail()
            self._enforce_retention()

    def _load_tail(self) -> None:
        if not self.path.exists():
            return
        try:
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                self._sequence = max(self._sequence, int(row.get("sequence") or 0))
                self._previous_hash = str(row.get("record_sha256") or self._previous_hash or "") or None
                record = row.get("record") or {}
                fingerprint = record.get("public_key_fingerprint")
                if fingerprint:
                    self._seen_identity_fingerprints.add(str(fingerprint))
                if row.get("record_type") == "KEY_TRANSITION":
                    key = (
                        str(record.get("identity_id") or ""),
                        int(record.get("from_epoch") or 0),
                        int(record.get("to_epoch") or 0),
                    )
                    self._seen_transition_keys.add(key)
        except Exception:
            # A corrupt journal must not be silently overwritten as though it
            # were empty.  Append a fresh record chained to the file hash so the
            # discontinuity remains visible.
            self._previous_hash = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def _append(self, record_type: str, record: Mapping[str, Any]) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._sequence += 1
            unsigned = {
                "schema_version": 1,
                "sequence": self._sequence,
                "record_type": record_type,
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "previous_record_hash": self._previous_hash,
                "record": _convert(record),
            }
            digest = hashlib.sha256(_canonical(unsigned)).hexdigest()
            row = dict(unsigned)
            row["record_sha256"] = digest
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
            self._previous_hash = digest

    def record_identity(
        self,
        identity: RuntimeSigningIdentity,
        *,
        signer_mode: RuntimeRecordIntegrityMode = RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
    ) -> None:
        fingerprint = identity.public_key_fingerprint
        if fingerprint in self._seen_identity_fingerprints:
            return
        self._append(
            "IDENTITY_CREATED" if identity.key_epoch == 1 else "IDENTITY_EPOCH",
            {
                "identity_id": identity.identity_id,
                "application_id": identity.application_id,
                "run_id": identity.run_id,
                "process_start_id": identity.process_start_id,
                "algorithm": identity.algorithm,
                "public_key": identity.public_key,
                "public_key_fingerprint": fingerprint,
                "generated_at": identity.generated_at,
                "first_event_sequence": identity.first_event_sequence,
                "key_epoch": identity.key_epoch,
                "anchoring_state": identity.anchoring_state.name,
                "anchor_references": identity.anchor_references,
                "signer_mode": signer_mode.name,
            },
        )
        self._seen_identity_fingerprints.add(fingerprint)

    def record_external_identity(self, identity: Mapping[str, Any]) -> None:
        public_key = _external_public_key(identity)
        fingerprint = str(identity.get("public_key_fingerprint") or "")
        if not fingerprint and public_key:
            fingerprint = hashlib.sha256(public_key).hexdigest()
        marker = fingerprint or str(identity.get("identity_id") or identity.get("key_id") or "external")
        if marker in self._seen_identity_fingerprints:
            return
        record = dict(identity)
        if public_key is not None:
            record["public_key"] = public_key
        record["public_key_fingerprint"] = fingerprint or None
        record["signer_mode"] = RuntimeRecordIntegrityMode.EXTERNAL_SIGNED.name
        self._append("EXTERNAL_IDENTITY", record)
        self._seen_identity_fingerprints.add(marker)

    def record_transition(
        self,
        *,
        identity: RuntimeSigningIdentity,
        transition: KeyTransition,
    ) -> None:
        key = (str(identity.identity_id), transition.from_epoch, transition.to_epoch)
        if key in self._seen_transition_keys:
            return
        self._append(
            "KEY_TRANSITION",
            {
                "identity_id": identity.identity_id,
                "run_id": identity.run_id,
                "from_epoch": transition.from_epoch,
                "to_epoch": transition.to_epoch,
                "old_public_key_fingerprint": transition.old_public_key_fingerprint,
                "new_public_key": transition.new_public_key,
                "new_public_key_fingerprint": transition.new_public_key_fingerprint,
                "created_at": transition.created_at,
                "next_event_sequence": transition.next_event_sequence,
                "signature": transition.signature,
            },
        )
        self._seen_transition_keys.add(key)

    def record_closed(self, identity_id: str, *, public_key_fingerprint: str | None) -> None:
        self._append(
            "IDENTITY_CLOSED",
            {
                "identity_id": identity_id,
                "public_key_fingerprint": public_key_fingerprint,
            },
        )

    def records(self) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        if not self.directory.exists():
            return ()
        for path in sorted(self.directory.glob("*.jsonl")):
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        rows.append(json.loads(line))
            except Exception:
                continue
        return tuple(rows)

    def public_key(self, fingerprint: str) -> bytes | None:
        for row in reversed(self.records()):
            record = row.get("record") or {}
            if str(record.get("public_key_fingerprint") or "") != fingerprint:
                continue
            value = record.get("public_key")
            if value:
                try:
                    return base64.b64decode(value)
                except Exception:
                    return None
        return None

    def verify_journal(self) -> tuple[bool, tuple[str, ...]]:
        """Verify the append-only hash chain of every retained identity journal."""
        errors: list[str] = []
        if not self.directory.exists():
            return True, ()
        for path in sorted(self.directory.glob("*.jsonl")):
            previous: str | None = None
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                errors.append(f"{path.name}: cannot read journal: {exc}")
                continue
            for line_number, line in enumerate(lines, start=1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"{path.name}:{line_number}: invalid JSON: {exc}")
                    continue
                observed_previous = row.get("previous_record_hash")
                if observed_previous != previous:
                    errors.append(
                        f"{path.name}:{line_number}: previous_record_hash does not match retained chain"
                    )
                unsigned = {key: value for key, value in row.items() if key != "record_sha256"}
                expected = hashlib.sha256(_canonical(unsigned)).hexdigest()
                observed = str(row.get("record_sha256") or "")
                if expected != observed:
                    errors.append(f"{path.name}:{line_number}: record SHA-256 is invalid")
                previous = observed or expected
        return not errors, tuple(errors)

    def verify_identity(self, fingerprint: str) -> tuple[bool, str | None]:
        """Verify a retained signing identity and its ephemeral key-evolution chain."""
        valid, errors = self.verify_journal()
        if not valid:
            return False, errors[0] if errors else "signing identity journal is invalid"
        return verify_identity_record_set(
            self.records(),
            fingerprint,
            require_complete_hash_chain=False,
        )

    def export_records(self, fingerprints: set[str]) -> tuple[dict[str, Any], ...]:
        if not fingerprints:
            return ()
        selected: list[dict[str, Any]] = []
        identity_ids: set[str] = set()
        for row in self.records():
            record = row.get("record") or {}
            if (
                str(record.get("public_key_fingerprint") or "") in fingerprints
                or str(record.get("new_public_key_fingerprint") or "") in fingerprints
                or str(record.get("old_public_key_fingerprint") or "") in fingerprints
            ):
                selected.append(row)
                if record.get("identity_id"):
                    identity_ids.add(str(record["identity_id"]))
        if identity_ids:
            for row in self.records():
                record = row.get("record") or {}
                if str(record.get("identity_id") or "") in identity_ids and row not in selected:
                    selected.append(row)
        selected.sort(key=lambda row: (str(row.get("occurred_at") or ""), int(row.get("sequence") or 0)))
        return tuple(selected)

    def _enforce_retention(self) -> None:
        if not self.directory.exists():
            return
        paths = sorted(self.directory.glob("*.jsonl"), key=lambda item: item.stat().st_mtime)
        if self.maximum_age_days is not None:
            cutoff = time.time() - self.maximum_age_days * 86400
            for path in tuple(paths):
                if path != self.path and path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
            paths = [path for path in paths if path.exists()]
        if self.maximum_files is not None and len(paths) > self.maximum_files:
            candidates = [path for path in paths if path != self.path]
            for path in candidates[: max(0, len(paths) - self.maximum_files)]:
                path.unlink(missing_ok=True)


class KeyEvolutionSigner:
    """Ephemeral Ed25519 signer with policy-controlled key evolution."""

    def __init__(
        self,
        *,
        application_id: str,
        run_id: UUID,
        process_start_id: UUID,
        policy: RuntimeSigningPolicy,
        first_event_sequence: int = 0,
    ) -> None:
        Ed25519PrivateKey, _, _ = _crypto()
        self.application_id = application_id
        self.run_id = run_id
        self.process_start_id = process_start_id
        self.policy = policy
        self.identity_id = uuid4()
        self._private_key = Ed25519PrivateKey.generate()
        self._epoch = 1
        self._epoch_started = datetime.now(timezone.utc)
        self._segments_in_epoch = 0
        self._closed = False
        self.transitions: list[KeyTransition] = []
        self.identity = self._identity(first_event_sequence)

    def _identity(self, first_event_sequence: int) -> RuntimeSigningIdentity:
        public_key = _public_bytes(self._private_key)
        return RuntimeSigningIdentity(
            identity_id=self.identity_id,
            application_id=self.application_id,
            run_id=self.run_id,
            process_start_id=self.process_start_id,
            algorithm="ed25519",
            public_key=public_key,
            public_key_fingerprint=hashlib.sha256(public_key).hexdigest(),
            generated_at=self._epoch_started,
            first_event_sequence=first_event_sequence,
            key_epoch=self._epoch,
            anchoring_state=RuntimeIdentityAnchoringState.SELF_RECORDED,
        )

    def _rotation_due(self, now: datetime) -> bool:
        seconds = self.policy.key_epoch_maximum_seconds
        segments = self.policy.key_epoch_maximum_segments
        return bool(
            (seconds is not None and (now - self._epoch_started).total_seconds() >= seconds)
            or (segments is not None and self._segments_in_epoch >= segments)
        )

    def rotate_if_due(self, *, next_event_sequence: int, now: datetime | None = None) -> KeyTransition | None:
        if self._closed:
            raise RuntimeError("Signer identity is closed")
        now = now or datetime.now(timezone.utc)
        if not self._rotation_due(now):
            return None
        Ed25519PrivateKey, _, _ = _crypto()
        old_key = self._private_key
        old_public = _public_bytes(old_key)
        new_key = Ed25519PrivateKey.generate()
        new_public = _public_bytes(new_key)
        unsigned = {
            "identity_id": self.identity_id,
            "run_id": self.run_id,
            "from_epoch": self._epoch,
            "to_epoch": self._epoch + 1,
            "old_public_key_fingerprint": hashlib.sha256(old_public).hexdigest(),
            "new_public_key": new_public,
            "new_public_key_fingerprint": hashlib.sha256(new_public).hexdigest(),
            "created_at": now,
            "next_event_sequence": next_event_sequence,
        }
        signature = old_key.sign(_canonical(unsigned))
        transition = KeyTransition(
            from_epoch=self._epoch,
            to_epoch=self._epoch + 1,
            old_public_key_fingerprint=unsigned["old_public_key_fingerprint"],
            new_public_key=new_public,
            new_public_key_fingerprint=unsigned["new_public_key_fingerprint"],
            created_at=now,
            signature=signature,
            next_event_sequence=next_event_sequence,
        )
        self.transitions.append(transition)
        self._private_key = new_key
        self._epoch += 1
        self._epoch_started = now
        self._segments_in_epoch = 0
        self.identity = self._identity(next_event_sequence)
        del old_key
        return transition

    def sign_artifact(
        self,
        *,
        artifact_kind: str,
        content_hash: str,
        previous_artifact_hash: str | None = None,
        context: Mapping[str, Any] | None = None,
        next_event_sequence: int = 0,
        now: datetime | None = None,
    ) -> RuntimeSignedArtifact:
        now = now or datetime.now(timezone.utc)
        self.rotate_if_due(next_event_sequence=next_event_sequence, now=now)
        unsigned = {
            "artifact_id": uuid4(),
            "artifact_kind": artifact_kind,
            "application_id": self.application_id,
            "run_id": self.run_id,
            "process_start_id": self.process_start_id,
            "signer_identity_id": str(self.identity_id),
            "signer_mode": RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED.name,
            "public_key_fingerprint": self.identity.public_key_fingerprint,
            "key_epoch": self._epoch,
            "content_hash": content_hash,
            "previous_artifact_hash": previous_artifact_hash,
            "context": dict(context or {}),
            "signed_at": now,
        }
        signature = self._private_key.sign(_canonical(unsigned))
        return RuntimeSignedArtifact(
            artifact_id=unsigned["artifact_id"],
            artifact_kind=artifact_kind,
            application_id=self.application_id,
            run_id=self.run_id,
            process_start_id=self.process_start_id,
            signer_identity_id=str(self.identity_id),
            signer_mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            public_key_fingerprint=self.identity.public_key_fingerprint,
            key_epoch=self._epoch,
            content_hash=content_hash,
            previous_artifact_hash=previous_artifact_hash,
            context=dict(context or {}),
            signed_at=now,
            signature=signature,
        )

    def sign_manifest(
        self,
        *,
        segment_id: UUID,
        segment_hash: str,
        previous_segment_hash: str | None,
        first_event_sequence: int,
        last_event_sequence: int,
        event_count: int,
        attachment_manifest_hash: str | None = None,
        now: datetime | None = None,
    ) -> RuntimeSignedManifest:
        now = now or datetime.now(timezone.utc)
        self.rotate_if_due(next_event_sequence=first_event_sequence, now=now)
        unsigned = {
            "manifest_id": uuid4(),
            "runtime_identity_id": self.identity_id,
            "application_id": self.application_id,
            "run_id": self.run_id,
            "process_start_id": self.process_start_id,
            "public_key_fingerprint": self.identity.public_key_fingerprint,
            "key_epoch": self._epoch,
            "segment_id": segment_id,
            "segment_hash": segment_hash,
            "previous_segment_hash": previous_segment_hash,
            "first_event_sequence": first_event_sequence,
            "last_event_sequence": last_event_sequence,
            "event_count": event_count,
            "attachment_manifest_hash": attachment_manifest_hash,
            "signed_at": now,
        }
        signature = self._private_key.sign(_canonical(unsigned))
        self._segments_in_epoch += 1
        return RuntimeSignedManifest(
            manifest_id=unsigned["manifest_id"],
            runtime_identity_id=self.identity_id,
            key_epoch=self._epoch,
            segment_id=segment_id,
            segment_hash=segment_hash,
            previous_segment_hash=previous_segment_hash,
            first_event_sequence=first_event_sequence,
            last_event_sequence=last_event_sequence,
            event_count=event_count,
            attachment_manifest_hash=attachment_manifest_hash,
            signed_at=now,
            signature=signature,
        )

    @staticmethod
    def verify_transition(
        transition: KeyTransition,
        old_public_key: bytes,
        *,
        identity_id: UUID,
        run_id: UUID,
        next_event_sequence: int | None = None,
    ) -> bool:
        _, Ed25519PublicKey, _ = _crypto()
        unsigned = {
            "identity_id": identity_id,
            "run_id": run_id,
            "from_epoch": transition.from_epoch,
            "to_epoch": transition.to_epoch,
            "old_public_key_fingerprint": transition.old_public_key_fingerprint,
            "new_public_key": transition.new_public_key,
            "new_public_key_fingerprint": transition.new_public_key_fingerprint,
            "created_at": transition.created_at,
            "next_event_sequence": (
                transition.next_event_sequence
                if next_event_sequence is None
                else next_event_sequence
            ),
        }
        try:
            Ed25519PublicKey.from_public_bytes(old_public_key).verify(
                transition.signature, _canonical(unsigned)
            )
            return True
        except Exception:
            return False

    @staticmethod
    def verify_manifest(manifest: RuntimeSignedManifest, public_key: bytes, *, context: Mapping[str, Any]) -> bool:
        _, Ed25519PublicKey, _ = _crypto()
        unsigned = {
            "manifest_id": manifest.manifest_id,
            "runtime_identity_id": manifest.runtime_identity_id,
            "application_id": context["application_id"],
            "run_id": context["run_id"],
            "process_start_id": context["process_start_id"],
            "public_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
            "key_epoch": manifest.key_epoch,
            "segment_id": manifest.segment_id,
            "segment_hash": manifest.segment_hash,
            "previous_segment_hash": manifest.previous_segment_hash,
            "first_event_sequence": manifest.first_event_sequence,
            "last_event_sequence": manifest.last_event_sequence,
            "event_count": manifest.event_count,
            "attachment_manifest_hash": manifest.attachment_manifest_hash,
            "signed_at": manifest.signed_at,
        }
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(manifest.signature, _canonical(unsigned))
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._private_key = None
        self._closed = True


def _signer_worker(connection, config: dict[str, Any]) -> None:
    try:
        if config.get("disable_core_dumps", True):
            try:
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
        signer = KeyEvolutionSigner(**config["signer_args"])
        connection.send(("identity", signer.identity))
        while True:
            command, payload = connection.recv()
            if command == "sign":
                manifest = signer.sign_manifest(**payload)
                connection.send(("manifest", manifest, tuple(signer.transitions), signer.identity))
            elif command == "sign_artifact":
                artifact = signer.sign_artifact(**payload)
                connection.send(("artifact", artifact, tuple(signer.transitions), signer.identity))
            elif command == "identity":
                connection.send(("identity", signer.identity))
            elif command == "close":
                signer.close()
                connection.send(("closed", True))
                return
            else:
                connection.send(("error", f"unknown signer command: {command}"))
    finally:
        connection.close()


class EphemeralSignerProcess:
    def __init__(self, **signer_args: Any) -> None:
        parent, child = mp.Pipe()
        self._connection = parent
        self._process = mp.Process(
            target=_signer_worker,
            args=(child, {"signer_args": signer_args, "disable_core_dumps": signer_args["policy"].disable_signer_core_dumps}),
            daemon=True,
            name="caretaker-ephemeral-signer",
        )
        self._process.start()
        kind, identity = self._connection.recv()
        if kind != "identity":
            raise SigningUnavailable(f"Signer failed to initialize: {identity}")
        self.identity = identity

    def sign_manifest(self, **payload: Any) -> tuple[RuntimeSignedManifest, tuple[KeyTransition, ...]]:
        self._connection.send(("sign", payload))
        response = self._connection.recv()
        kind = response[0]
        if kind != "manifest":
            raise SigningUnavailable(str(response[1:]))
        _, manifest, transitions, identity = response
        self.identity = identity
        return manifest, transitions

    def sign_artifact(self, **payload: Any) -> tuple[RuntimeSignedArtifact, tuple[KeyTransition, ...]]:
        self._connection.send(("sign_artifact", payload))
        response = self._connection.recv()
        kind = response[0]
        if kind != "artifact":
            raise SigningUnavailable(str(response[1:]))
        _, artifact, transitions, identity = response
        self.identity = identity
        return artifact, transitions

    def close(self) -> None:
        if self._process.is_alive():
            self._connection.send(("close", {}))
            self._connection.recv()
            self._process.join(timeout=5)
        self._connection.close()


def _record_public_key(record: Mapping[str, Any], *, field: str = "public_key") -> bytes | None:
    value = record.get(field)
    if not value:
        return None
    if isinstance(value, bytes):
        return value
    try:
        return base64.b64decode(str(value))
    except Exception:
        return None


def _external_public_key(identity: Mapping[str, Any]) -> bytes | None:
    value = identity.get("public_key")
    if isinstance(value, bytes):
        return value
    if isinstance(value, str) and value:
        try:
            return base64.b64decode(value)
        except Exception:
            return None
    return None


class RuntimeArtifactSigningService:
    """Shared signer for secure event manifests and other runtime artifacts."""

    def __init__(
        self,
        *,
        policy: RuntimeSigningPolicy,
        application_id: str,
        run_id: UUID,
        process_start_id: UUID,
        root: str | Path,
        external_signer: ExternalArtifactSigner | ExternalManifestSigner | None = None,
        first_event_sequence: int = 0,
    ) -> None:
        self.policy = policy
        self.application_id = application_id
        self.run_id = run_id
        self.process_start_id = process_start_id
        self.mode = policy.mode
        self.external_signer = external_signer
        self.journal = SigningIdentityJournal(
            root,
            run_id=run_id,
            enabled=policy.identity_journal_enabled,
            maximum_age_days=policy.identity_journal_maximum_age_days,
            maximum_files=policy.identity_journal_maximum_files,
        )
        self._backend: KeyEvolutionSigner | EphemeralSignerProcess | None = None
        if self.mode is RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED:
            args = dict(
                application_id=application_id,
                run_id=run_id,
                process_start_id=process_start_id,
                policy=policy,
                first_event_sequence=first_event_sequence,
            )
            self._backend = (
                EphemeralSignerProcess(**args)
                if policy.run_signer_in_separate_process
                else KeyEvolutionSigner(**args)
            )
            self.journal.record_identity(self._backend.identity)
        elif self.mode is RuntimeRecordIntegrityMode.EXTERNAL_SIGNED:
            if external_signer is None:
                raise SigningUnavailable(
                    "EXTERNAL_SIGNED mode requires an external signer; Caretaker will not silently fall back to ephemeral signing"
                )
            self.journal.record_external_identity(external_signer.public_identity())

    @property
    def identity(self) -> RuntimeSigningIdentity | Mapping[str, Any] | None:
        if self._backend is not None:
            return self._backend.identity
        if self.external_signer is not None:
            return self.external_signer.public_identity()
        return None

    def _sync_ephemeral_journal(self, transitions: tuple[KeyTransition, ...]) -> None:
        if self._backend is None:
            return
        identity = self._backend.identity
        for transition in transitions:
            self.journal.record_transition(identity=identity, transition=transition)
        self.journal.record_identity(identity)

    def sign_artifact(
        self,
        *,
        artifact_kind: str,
        content_hash: str,
        previous_artifact_hash: str | None = None,
        context: Mapping[str, Any] | None = None,
        next_event_sequence: int = 0,
    ) -> RuntimeSignedArtifact | None:
        if self.mode is RuntimeRecordIntegrityMode.HASH_CHAINED:
            return None
        if self.mode is RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED:
            assert self._backend is not None
            kwargs = dict(
                artifact_kind=artifact_kind,
                content_hash=content_hash,
                previous_artifact_hash=previous_artifact_hash,
                context=context or {},
                next_event_sequence=next_event_sequence,
            )
            if isinstance(self._backend, EphemeralSignerProcess):
                artifact, transitions = self._backend.sign_artifact(**kwargs)
            else:
                artifact = self._backend.sign_artifact(**kwargs)
                transitions = tuple(self._backend.transitions)
            self._sync_ephemeral_journal(transitions)
            return artifact

        assert self.external_signer is not None
        identity = dict(self.external_signer.public_identity())
        public_key = _external_public_key(identity)
        fingerprint = str(identity.get("public_key_fingerprint") or "") or (
            hashlib.sha256(public_key).hexdigest() if public_key else None
        )
        artifact = RuntimeSignedArtifact(
            artifact_id=uuid4(),
            artifact_kind=artifact_kind,
            application_id=self.application_id,
            run_id=self.run_id,
            process_start_id=self.process_start_id,
            signer_identity_id=str(identity.get("identity_id") or identity.get("key_id") or fingerprint or "external"),
            signer_mode=RuntimeRecordIntegrityMode.EXTERNAL_SIGNED,
            public_key_fingerprint=fingerprint,
            key_epoch=(int(identity["key_epoch"]) if identity.get("key_epoch") is not None else None),
            content_hash=content_hash,
            previous_artifact_hash=previous_artifact_hash,
            context=dict(context or {}),
            signed_at=datetime.now(timezone.utc),
            signature=b"",
        )
        payload = _canonical(_artifact_unsigned(artifact))
        if hasattr(self.external_signer, "sign_artifact"):
            signature = self.external_signer.sign_artifact(payload)  # type: ignore[attr-defined]
        elif hasattr(self.external_signer, "sign_manifest"):
            signature = self.external_signer.sign_manifest(payload)  # type: ignore[attr-defined]
        else:
            raise SigningUnavailable("External signer provides no sign_artifact/sign_manifest method")
        self.journal.record_external_identity(identity)
        return replace(artifact, signature=signature)

    def sign_event_manifest(
        self,
        *,
        segment_id: UUID,
        segment_hash: str,
        previous_segment_hash: str | None,
        first_event_sequence: int,
        last_event_sequence: int,
        event_count: int,
        attachment_manifest_hash: str | None = None,
    ) -> tuple[RuntimeSignedManifest | RuntimeSignedArtifact | None, tuple[KeyTransition, ...]]:
        if self.mode is RuntimeRecordIntegrityMode.HASH_CHAINED:
            return None, ()
        if self.mode is RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED:
            assert self._backend is not None
            kwargs = dict(
                segment_id=segment_id,
                segment_hash=segment_hash,
                previous_segment_hash=previous_segment_hash,
                first_event_sequence=first_event_sequence,
                last_event_sequence=last_event_sequence,
                event_count=event_count,
                attachment_manifest_hash=attachment_manifest_hash,
            )
            if isinstance(self._backend, EphemeralSignerProcess):
                manifest, transitions = self._backend.sign_manifest(**kwargs)
            else:
                manifest = self._backend.sign_manifest(**kwargs)
                transitions = tuple(self._backend.transitions)
            self._sync_ephemeral_journal(transitions)
            return manifest, transitions
        artifact = self.sign_artifact(
            artifact_kind="event-segment-manifest",
            content_hash=segment_hash,
            previous_artifact_hash=previous_segment_hash,
            context={
                "segment_id": str(segment_id),
                "first_event_sequence": first_event_sequence,
                "last_event_sequence": last_event_sequence,
                "event_count": event_count,
                "attachment_manifest_hash": attachment_manifest_hash,
            },
            next_event_sequence=first_event_sequence,
        )
        return artifact, ()

    def close(self) -> None:
        identity = self.identity
        if isinstance(identity, RuntimeSigningIdentity):
            identity_id = str(identity.identity_id)
            fingerprint = identity.public_key_fingerprint
        elif isinstance(identity, Mapping):
            identity_id = str(identity.get("identity_id") or identity.get("key_id") or "external")
            fingerprint = str(identity.get("public_key_fingerprint") or "") or None
        else:
            identity_id = "none"
            fingerprint = None
        if self.mode is not RuntimeRecordIntegrityMode.HASH_CHAINED:
            self.journal.record_closed(identity_id, public_key_fingerprint=fingerprint)
        if self._backend is not None:
            self._backend.close()
