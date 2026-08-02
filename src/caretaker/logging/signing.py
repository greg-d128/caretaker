from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing as mp
import os
import resource
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol
from uuid import UUID, uuid4

from .models import (
    KeyTransition,
    RuntimeIdentityAnchoringState,
    RuntimeSignedManifest,
    RuntimeSigningIdentity,
)
from .policy import RuntimeSigningPolicy


class SigningUnavailable(RuntimeError):
    pass


class ExternalManifestSigner(Protocol):
    def public_identity(self) -> Mapping[str, Any]: ...
    def sign_manifest(self, payload: bytes) -> bytes: ...


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


def _canonical(payload: Mapping[str, Any]) -> bytes:
    def convert(value: Any) -> Any:
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, bytes):
            return base64.b64encode(value).decode()
        if isinstance(value, Mapping):
            return {str(key): convert(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
        if isinstance(value, (tuple, list)):
            return [convert(item) for item in value]
        return value
    return json.dumps(convert(payload), sort_keys=True, separators=(",", ":")).encode()


class KeyEvolutionSigner:
    """Ephemeral Ed25519 signer with policy-controlled key evolution.

    At rotation, the old key signs a transition to the new public key before the
    old private-key object is released. Python cannot prove complete memory
    zeroization; the implementation does not persist or intentionally disclose
    private-key material.
    """

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
        )
        self.transitions.append(transition)
        self._private_key = new_key
        self._epoch += 1
        self._epoch_started = now
        self._segments_in_epoch = 0
        self.identity = self._identity(next_event_sequence)
        # Release the last reference held by this method. Backends and Python
        # allocators may retain copies; documentation states this limitation.
        del old_key
        return transition

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
        next_event_sequence: int,
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
            "next_event_sequence": next_event_sequence,
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

    def close(self) -> None:
        if self._process.is_alive():
            self._connection.send(("close", {}))
            self._connection.recv()
            self._process.join(timeout=5)
        self._connection.close()
