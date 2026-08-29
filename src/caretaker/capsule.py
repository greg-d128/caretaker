"""Bounded, data-only Incident Capsule storage.

Capsules are immutable revision files.  Adding an artifact or recording a
communication creates a new revision and leaves the previous revision intact.
The store deliberately does not deserialize application objects: captured
values are reduced to bounded JSON-compatible data at capture time.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4

CAPSULE_SCHEMA_VERSION = 1
ARTIFACT_SCHEMA_VERSION = 1


class IncidentCapsuleLevel(Enum):
    MINIMAL = auto()
    STANDARD = auto()
    DIAGNOSTIC = auto()
    FORENSIC = auto()


@dataclass(frozen=True, slots=True)
class IncidentCapsulePolicy:
    """Capture and resource limits for Incident Capsules.

    The levels select which already-captured Incident sections are copied into
    the capsule.  They never request new application authority or bypass the
    logging/state-capture policy that produced the source Incident.
    """

    enabled: bool = True
    level: IncidentCapsuleLevel = IncidentCapsuleLevel.MINIMAL
    maximum_capsule_bytes: int = 2 * 1024 * 1024
    maximum_artifact_bytes: int = 512 * 1024
    maximum_artifacts: int = 64
    maximum_communications: int = 256
    maximum_depth: int = 8
    maximum_collection_items: int = 128
    maximum_text_characters: int = 16_384
    allow_operator_artifacts: bool = True


@dataclass(frozen=True, slots=True)
class CapsuleArtifact:
    artifact_id: UUID
    kind: str
    created_at: datetime
    content_sha256: str
    relative_path: str
    source: str
    operator_identity: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CommunicationRecord:
    communication_id: UUID
    recorded_at: datetime
    direction: str
    channel: str
    audience_profile_id: str | None
    status: str
    content_sha256: str | None = None
    source: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class IncidentCapsule:
    capsule_id: UUID
    incident_id: UUID
    run_id: UUID | None
    revision: int
    created_at: datetime
    previous_revision_sha256: str | None
    policy_fingerprint: str | None
    authority_policy_generation: int | None
    authority_policy_fingerprint: str | None
    incident_state: Mapping[str, Any]
    artifacts: tuple[CapsuleArtifact, ...] = ()
    communications: tuple[CommunicationRecord, ...] = ()


class IncidentCapsuleError(ValueError):
    """Raised when a capsule or side artifact cannot be safely stored."""


class IncidentCapsuleIntegrityError(IncidentCapsuleError):
    """Raised when an immutable capsule revision fails verification."""


def validate_incident_capsule_policy(policy: IncidentCapsulePolicy) -> None:
    errors: list[str] = []
    for name in (
        "maximum_capsule_bytes",
        "maximum_artifact_bytes",
        "maximum_artifacts",
        "maximum_communications",
        "maximum_depth",
        "maximum_collection_items",
        "maximum_text_characters",
    ):
        if getattr(policy, name) <= 0:
            errors.append(f"{name} must be greater than zero")
    if errors:
        raise IncidentCapsuleError("Invalid Incident Capsule policy: " + "; ".join(errors))


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def bounded_safe_data(
    value: Any,
    *,
    policy: IncidentCapsulePolicy,
    name: str | None = None,
    depth: int = 0,
) -> Any:
    """Convert values to bounded JSON data without preserving executable objects."""

    if _sensitive_name(name):
        return {
            "type": _type_name(value),
            "value": "<redacted>",
            "redacted": True,
        }
    if depth >= policy.maximum_depth:
        return {"type": _type_name(value), "truncated": True}
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"type": "float", "value": repr(value)}
    if isinstance(value, str):
        if _integrity_text_name(name) and re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
            return value
        return _redact_text(value, policy)
    if isinstance(value, (UUID, Path)):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.name
    if dataclasses.is_dataclass(value):
        return bounded_safe_data(
            {
                item.name: getattr(value, item.name)
                for item in dataclasses.fields(value)
            },
            policy=policy,
            name=name,
            depth=depth + 1,
        )
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda item: str(item[0]))
        result: dict[str, Any] = {}
        for key, item in items[: policy.maximum_collection_items]:
            original_key = str(key)
            key_text = _bounded_text(original_key, policy.maximum_text_characters)
            result[key_text] = bounded_safe_data(
                item,
                policy=policy,
                # Use the original field name for redaction. A short display key
                # must not make a sensitive field look non-sensitive.
                name=original_key,
                depth=depth + 1,
            )
        if len(items) > policy.maximum_collection_items:
            result["<truncated_items>"] = len(items) - policy.maximum_collection_items
        return result
    if isinstance(value, (tuple, list, set, frozenset)):
        values = list(value)
        result = [
            bounded_safe_data(item, policy=policy, depth=depth + 1)
            for item in values[: policy.maximum_collection_items]
        ]
        if len(values) > policy.maximum_collection_items:
            result.append({"<truncated_items>": len(values) - policy.maximum_collection_items})
        return result
    return {
        "type": _type_name(value),
        "representation": _bounded_repr(value, policy.maximum_text_characters),
    }


class IncidentCapsuleStore:
    """Filesystem store for immutable capsule revisions and side artifacts."""

    def __init__(
        self,
        directory: str | Path,
        *,
        policy: IncidentCapsulePolicy | None = None,
        artifact_signer: Any | None = None,
    ) -> None:
        self.directory = Path(directory).expanduser().resolve() / "incident-capsules"
        self.artifact_directory = self.directory / "artifacts"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.artifact_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.artifact_directory.chmod(0o700)
        self.policy = policy or IncidentCapsulePolicy()
        validate_incident_capsule_policy(self.policy)
        self.artifact_signer = artifact_signer
        self._lock = threading.RLock()

    def create_for_incident(
        self,
        incident: Any,
        *,
        policy: IncidentCapsulePolicy | None = None,
        authority_policy_generation: int | None = None,
        authority_policy_fingerprint: str | None = None,
    ) -> dict[str, Any]:
        active_policy = policy or self.policy
        validate_incident_capsule_policy(active_policy)
        if not active_policy.enabled:
            raise IncidentCapsuleError("Incident Capsule capture is disabled by policy")
        incident_id = _uuid_value(incident, "incident_id")
        if incident_id is None:
            raise IncidentCapsuleError("Incident Capsule requires an incident_id")
        run_id = _uuid_value(incident, "run_id")
        policy_fingerprint = _string_value(incident, "policy_fingerprint")
        state = _incident_state(incident, active_policy)
        return self._create_revision(
            capsule_id=uuid4(),
            incident_id=incident_id,
            run_id=run_id,
            revision=1,
            previous_revision_sha256=None,
            policy_fingerprint=policy_fingerprint,
            authority_policy_generation=authority_policy_generation
            if authority_policy_generation is not None
            else _int_value(incident, "authority_policy_generation"),
            authority_policy_fingerprint=authority_policy_fingerprint
            or _string_value(incident, "authority_policy_fingerprint"),
            incident_state=state,
            artifacts=(),
            communications=(),
            policy=active_policy,
        )

    def create_placeholder(
        self,
        incident_id: UUID | str,
        *,
        run_id: UUID | str | None = None,
        incident_state: Mapping[str, Any] | None = None,
        policy_fingerprint: str | None = None,
        authority_policy_generation: int | None = None,
        authority_policy_fingerprint: str | None = None,
        policy: IncidentCapsulePolicy | None = None,
    ) -> dict[str, Any]:
        active_policy = policy or self.policy
        validate_incident_capsule_policy(active_policy)
        if not active_policy.enabled:
            raise IncidentCapsuleError("Incident Capsule capture is disabled by policy")
        parsed_incident = UUID(str(incident_id))
        parsed_run = UUID(str(run_id)) if run_id else None
        return self._create_revision(
            capsule_id=uuid4(),
            incident_id=parsed_incident,
            run_id=parsed_run,
            revision=1,
            previous_revision_sha256=None,
            policy_fingerprint=policy_fingerprint,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
            incident_state=bounded_safe_data(
                dict(incident_state or {}), policy=active_policy
            ),
            artifacts=(),
            communications=(),
            policy=active_policy,
        )

    def latest_for_incident(self, incident_id: UUID | str) -> dict[str, Any] | None:
        parsed = UUID(str(incident_id))
        candidate_ids: set[UUID] = set()
        for path in self.directory.glob("*.json"):
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                payload = envelope.get("capsule")
                if not isinstance(payload, Mapping) or UUID(str(payload.get("incident_id"))) != parsed:
                    continue
                candidate_ids.add(UUID(str(payload["capsule_id"])))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue

        latest: dict[str, Any] | None = None
        latest_key: tuple[int, str] | None = None
        for capsule_id in candidate_ids:
            try:
                envelope = self.load(capsule_id)
                payload = envelope.get("capsule")
                if not isinstance(payload, Mapping) or UUID(str(payload.get("incident_id"))) != parsed:
                    continue
                key = (int(payload.get("revision") or 0), str(payload.get("created_at") or ""))
                if latest_key is None or key > latest_key:
                    latest = envelope
                    latest_key = key
            except IncidentCapsuleIntegrityError:
                raise
            except (OSError, ValueError, TypeError, json.JSONDecodeError, KeyError):
                continue
        return latest

    def load(self, capsule_id: UUID | str, revision: int | None = None) -> dict[str, Any]:
        parsed = UUID(str(capsule_id))
        all_paths = sorted(
            self.directory.glob(f"{parsed}.r*.json"),
            key=_revision_number,
        )
        if revision is not None:
            paths = [path for path in all_paths if path.name == f"{parsed}.r{int(revision)}.json"]
        else:
            paths = all_paths
        if not paths:
            raise KeyError(f"No Incident Capsule found for {parsed}")
        target = paths[-1]
        expected_revision = _revision_number(target)
        chain_paths = [path for path in all_paths if _revision_number(path) <= expected_revision]
        previous_digest: str | None = None
        for expected_number, path in enumerate(chain_paths, start=1):
            actual_number = _revision_number(path)
            if actual_number != expected_number:
                raise IncidentCapsuleIntegrityError(
                    f"capsule revision chain is incomplete before revision {expected_revision}"
                )
            envelope = json.loads(path.read_text(encoding="utf-8"))
            self._verify_envelope(envelope, path=path)
            payload = envelope["capsule"]
            if UUID(str(payload.get("capsule_id"))) != parsed or int(payload.get("revision")) != actual_number:
                raise IncidentCapsuleIntegrityError(f"capsule revision identity is invalid at {path}")
            if payload.get("previous_revision_sha256") != previous_digest:
                raise IncidentCapsuleIntegrityError(f"capsule revision chain is invalid at {path}")
            previous_digest = str(envelope["integrity"]["content_sha256"])
        return envelope

    def list_summaries(
        self,
        *,
        incident_id: UUID | str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return bounded read-only summaries, including invalid capsules."""

        parsed_incident = UUID(str(incident_id)) if incident_id else None
        capsule_ids: set[UUID] = set()
        for path in self.directory.glob("*.r*.json"):
            match = re.fullmatch(r"([0-9a-fA-F-]{36})\.r\d+\.json", path.name)
            if match is None:
                continue
            try:
                capsule_ids.add(UUID(match.group(1)))
            except ValueError:
                continue

        summaries: list[dict[str, Any]] = []
        for capsule_id in capsule_ids:
            try:
                envelope = self.load(capsule_id)
                payload = envelope["capsule"]
                current_incident = str(payload.get("incident_id") or "")
                if parsed_incident is not None and current_incident != str(parsed_incident):
                    continue
                integrity = envelope.get("integrity") or {}
                summaries.append({
                    "capsule_id": str(capsule_id),
                    "incident_id": current_incident or None,
                    "run_id": payload.get("run_id"),
                    "revision": int(payload.get("revision") or 0),
                    "created_at": payload.get("created_at"),
                    "artifact_count": len(payload.get("artifacts") or ()),
                    "communication_count": len(payload.get("communications") or ()),
                    "policy_fingerprint": payload.get("policy_fingerprint"),
                    "authority_policy_generation": payload.get("authority_policy_generation"),
                    "content_sha256": integrity.get("content_sha256"),
                    "signature_state": integrity.get("signature_state") or "UNSIGNED",
                    "integrity_status": "VERIFIED",
                    "incident_state": _summary_state(payload.get("incident_state")),
                })
            except Exception as exc:
                summaries.append({
                    "capsule_id": str(capsule_id),
                    "incident_id": None,
                    "revision": None,
                    "created_at": None,
                    "artifact_count": None,
                    "communication_count": None,
                    "integrity_status": "INVALID",
                    "integrity_error": f"{type(exc).__name__}: {exc}",
                })
        summaries.sort(
            key=lambda item: (
                str(item.get("created_at") or ""),
                str(item.get("capsule_id") or ""),
            ),
            reverse=True,
        )
        return summaries[: max(1, int(limit))]

    def load_artifact(self, artifact_id: UUID | str) -> dict[str, Any]:
        """Load and verify a side artifact referenced by a capsule."""

        parsed = UUID(str(artifact_id))
        path = self.artifact_directory / f"{parsed}.json"
        envelope = json.loads(path.read_text(encoding="utf-8"))
        artifact = envelope.get("artifact")
        integrity = envelope.get("integrity")
        if not isinstance(artifact, Mapping) or not isinstance(integrity, Mapping):
            raise IncidentCapsuleIntegrityError("artifact envelope is missing artifact/integrity objects")
        expected = str(integrity.get("content_sha256") or "")
        if not expected or content_hash(artifact) != expected:
            raise IncidentCapsuleIntegrityError(f"artifact content hash is invalid at {path}")
        if str(artifact.get("artifact_id")) != str(parsed):
            raise IncidentCapsuleIntegrityError(f"artifact identity is invalid at {path}")
        capsule_id = UUID(str(artifact.get("capsule_id")))
        capsule = self.load(capsule_id)
        references = capsule["capsule"].get("artifacts") or ()
        reference = next(
            (
                item
                for item in references
                if isinstance(item, Mapping) and str(item.get("artifact_id")) == str(parsed)
            ),
            None,
        )
        if not isinstance(reference, Mapping) or reference.get("content_sha256") != expected:
            raise IncidentCapsuleIntegrityError("artifact is not referenced by the verified capsule revision")
        return envelope

    def attach_artifact(
        self,
        incident_id: UUID | str,
        *,
        kind: str,
        content: Any,
        source: str,
        operator_identity: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        policy: IncidentCapsulePolicy | None = None,
        run_id: UUID | str | None = None,
        incident_state: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        active_policy = policy or self.policy
        validate_incident_capsule_policy(active_policy)
        if not active_policy.enabled:
            raise IncidentCapsuleError("Incident Capsule capture is disabled by policy")
        if operator_identity and not active_policy.allow_operator_artifacts:
            raise IncidentCapsuleError("Operator side artifacts are disabled by capsule policy")
        with self._lock:
            latest = self.latest_for_incident(incident_id)
            if latest is None:
                latest = self.create_placeholder(
                    incident_id,
                    run_id=run_id,
                    incident_state=incident_state,
                    policy=active_policy,
                )
            payload = dict(latest["capsule"])
            references = list(payload.get("artifacts") or ())
            if len(references) >= active_policy.maximum_artifacts:
                raise IncidentCapsuleError("Incident Capsule artifact limit has been reached")
            artifact_id = uuid4()
            captured = _bounded_artifact_content(content, active_policy)
            artifact_payload = {
                "schema_version": ARTIFACT_SCHEMA_VERSION,
                "artifact_id": str(artifact_id),
                "capsule_id": str(payload["capsule_id"]),
                "incident_id": str(payload["incident_id"]),
                "created_at": _utcnow().isoformat(),
                "kind": str(kind),
                "source": str(source),
                "operator_identity": operator_identity,
                "metadata": bounded_safe_data(dict(metadata or {}), policy=active_policy),
                "content": captured,
            }
            digest = content_hash(artifact_payload)
            artifact_envelope = {
                "artifact": artifact_payload,
                "integrity": {"content_sha256": digest},
            }
            artifact_path = self.artifact_directory / f"{artifact_id}.json"
            self._write_exclusive(
                artifact_path,
                artifact_envelope,
                maximum_bytes=active_policy.maximum_artifact_bytes,
            )
            references.append({
                "artifact_id": str(artifact_id),
                "kind": str(kind),
                "created_at": artifact_payload["created_at"],
                "content_sha256": digest,
                "relative_path": str(artifact_path.relative_to(self.directory)),
                "source": str(source),
                "operator_identity": operator_identity,
                "metadata": artifact_payload["metadata"],
            })
            result = self._append_revision(
                latest,
                artifacts=tuple(references),
                communications=tuple(payload.get("communications") or ()),
                policy=active_policy,
            )
            return {"capsule": result, "artifact": artifact_envelope, "artifact_path": str(artifact_path)}

    def record_communication(
        self,
        incident_id: UUID | str,
        *,
        direction: str,
        channel: str,
        status: str,
        audience_profile_id: str | None = None,
        content_sha256: str | None = None,
        source: str = "unknown",
        metadata: Mapping[str, Any] | None = None,
        policy: IncidentCapsulePolicy | None = None,
        run_id: UUID | str | None = None,
    ) -> dict[str, Any]:
        active_policy = policy or self.policy
        validate_incident_capsule_policy(active_policy)
        if not active_policy.enabled:
            raise IncidentCapsuleError("Incident Capsule capture is disabled by policy")
        with self._lock:
            latest = self.latest_for_incident(incident_id)
            if latest is None:
                latest = self.create_placeholder(incident_id, run_id=run_id, policy=active_policy)
            payload = dict(latest["capsule"])
            communications = list(payload.get("communications") or ())
            if len(communications) >= active_policy.maximum_communications:
                raise IncidentCapsuleError("Incident Capsule communication limit has been reached")
            communications.append({
                "communication_id": str(uuid4()),
                "recorded_at": _utcnow().isoformat(),
                "direction": str(direction),
                "channel": str(channel),
                "audience_profile_id": audience_profile_id,
                "status": str(status),
                "content_sha256": content_sha256,
                "source": str(source),
                "metadata": bounded_safe_data(dict(metadata or {}), policy=active_policy),
            })
            return self._append_revision(
                latest,
                artifacts=tuple(payload.get("artifacts") or ()),
                communications=tuple(communications),
                policy=active_policy,
            )

    def verify(self, envelope: Mapping[str, Any]) -> tuple[bool, str | None]:
        try:
            self._verify_envelope(envelope)
        except IncidentCapsuleIntegrityError as exc:
            return False, str(exc)
        return True, None

    def _append_revision(
        self,
        previous: Mapping[str, Any],
        *,
        artifacts: tuple[Mapping[str, Any], ...],
        communications: tuple[Mapping[str, Any], ...],
        policy: IncidentCapsulePolicy,
    ) -> dict[str, Any]:
        if len(artifacts) > policy.maximum_artifacts:
            raise IncidentCapsuleError("Incident Capsule artifact limit has been reached")
        if len(communications) > policy.maximum_communications:
            raise IncidentCapsuleError("Incident Capsule communication limit has been reached")
        old_payload = dict(previous["capsule"])
        return self._create_revision(
            capsule_id=UUID(str(old_payload["capsule_id"])),
            incident_id=UUID(str(old_payload["incident_id"])),
            run_id=UUID(str(old_payload["run_id"])) if old_payload.get("run_id") else None,
            revision=int(old_payload["revision"]) + 1,
            previous_revision_sha256=str(previous["integrity"]["content_sha256"]),
            policy_fingerprint=old_payload.get("policy_fingerprint"),
            authority_policy_generation=old_payload.get("authority_policy_generation"),
            authority_policy_fingerprint=old_payload.get("authority_policy_fingerprint"),
            incident_state=old_payload.get("incident_state") or {},
            artifacts=artifacts,
            communications=communications,
            policy=policy,
        )

    def _create_revision(
        self,
        *,
        capsule_id: UUID,
        incident_id: UUID,
        run_id: UUID | None,
        revision: int,
        previous_revision_sha256: str | None,
        policy_fingerprint: str | None,
        authority_policy_generation: int | None,
        authority_policy_fingerprint: str | None,
        incident_state: Mapping[str, Any],
        artifacts: tuple[Mapping[str, Any], ...],
        communications: tuple[Mapping[str, Any], ...],
        policy: IncidentCapsulePolicy,
    ) -> dict[str, Any]:
        payload = {
            "schema_version": CAPSULE_SCHEMA_VERSION,
            "capsule_id": str(capsule_id),
            "incident_id": str(incident_id),
            "run_id": str(run_id) if run_id else None,
            "revision": revision,
            "created_at": _utcnow().isoformat(),
            "previous_revision_sha256": previous_revision_sha256,
            "policy_fingerprint": policy_fingerprint,
            "authority_policy_generation": authority_policy_generation,
            "authority_policy_fingerprint": authority_policy_fingerprint,
            "incident_state": bounded_safe_data(incident_state, policy=policy),
            "artifacts": _bounded_artifact_references(artifacts, policy),
            "communications": _bounded_communication_records(communications, policy),
        }
        digest = content_hash(payload)
        signature: Any | None = None
        if self.artifact_signer is not None:
            signature = self.artifact_signer.sign_artifact(
                artifact_kind="incident-capsule",
                content_hash=digest,
                context={
                    "capsule_id": str(capsule_id),
                    "incident_id": str(incident_id),
                    "revision": revision,
                },
            )
        envelope = {
            "capsule": payload,
            "integrity": {
                "content_sha256": digest,
                "signature_state": signature.signer_mode.name if signature else "UNSIGNED",
                "signer_fingerprint": signature.public_key_fingerprint if signature else None,
                "artifact_signature": _serialize_signed_artifact(signature) if signature else None,
            },
        }
        path = self.directory / f"{capsule_id}.r{revision}.json"
        with self._lock:
            self._write_exclusive(
                path,
                envelope,
                maximum_bytes=policy.maximum_capsule_bytes,
            )
        return envelope

    def _write_exclusive(
        self,
        path: Path,
        value: Mapping[str, Any],
        *,
        maximum_bytes: int,
    ) -> None:
        encoded = canonical_json_bytes(value)
        if len(encoded) > maximum_bytes:
            raise IncidentCapsuleError(
                f"Incident Capsule data exceeds maximum size {maximum_bytes} bytes"
            )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    @staticmethod
    def _verify_envelope(envelope: Mapping[str, Any], *, path: Path | None = None) -> None:
        payload = envelope.get("capsule")
        integrity = envelope.get("integrity")
        if not isinstance(payload, Mapping) or not isinstance(integrity, Mapping):
            raise IncidentCapsuleIntegrityError("capsule envelope is missing capsule/integrity objects")
        expected = str(integrity.get("content_sha256") or "")
        if not expected or content_hash(payload) != expected:
            suffix = f" at {path}" if path else ""
            raise IncidentCapsuleIntegrityError(f"capsule content hash is invalid{suffix}")
        signed = integrity.get("artifact_signature")
        if signed is not None:
            try:
                artifact = _deserialize_signed_artifact(signed)
            except Exception as exc:
                raise IncidentCapsuleIntegrityError(
                    f"capsule artifact signature is malformed: {type(exc).__name__}: {exc}"
                ) from exc
            if artifact.artifact_kind != "incident-capsule" or artifact.content_hash != expected:
                raise IncidentCapsuleIntegrityError("capsule signature does not bind the capsule content")


def _incident_state(incident: Any, policy: IncidentCapsulePolicy) -> Mapping[str, Any]:
    raw = bounded_safe_data(incident, policy=policy)
    if not isinstance(raw, Mapping):
        return {"value": raw}
    level = policy.level
    if level is IncidentCapsuleLevel.MINIMAL:
        allowed = {
            "incident_id",
            "run_id",
            "occurred_at",
            "trigger",
            "target",
            "failure",
            "policy_snapshot_id",
            "policy_fingerprint",
            "authority_policy_generation",
            "authority_policy_fingerprint",
            "fingerprint",
        }
        return {key: raw[key] for key in allowed if key in raw}
    if level is IncidentCapsuleLevel.STANDARD:
        allowed = set(raw) - {"metadata"}
        return {key: raw[key] for key in allowed}
    return dict(raw)


def _summary_state(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        return {"value": value}
    keys = (
        "trigger",
        "target",
        "failure",
        "fingerprint",
        "capture_reason",
    )
    return {key: value[key] for key in keys if key in value}


def _bounded_artifact_references(
    values: tuple[Mapping[str, Any], ...],
    policy: IncidentCapsulePolicy,
) -> list[Any]:
    fields = (
        "artifact_id",
        "kind",
        "created_at",
        "content_sha256",
        "relative_path",
        "source",
        "operator_identity",
        "metadata",
    )
    result = []
    for value in values:
        if not isinstance(value, Mapping):
            result.append(bounded_safe_data(value, policy=policy))
            continue
        result.append({
            key: bounded_safe_data(value[key], policy=policy, name=key)
            for key in fields
            if key in value
        })
    return result


def _bounded_communication_records(
    values: tuple[Mapping[str, Any], ...],
    policy: IncidentCapsulePolicy,
) -> list[Any]:
    fields = (
        "communication_id",
        "recorded_at",
        "direction",
        "channel",
        "audience_profile_id",
        "status",
        "content_sha256",
        "source",
        "metadata",
    )
    result = []
    for value in values:
        if not isinstance(value, Mapping):
            result.append(bounded_safe_data(value, policy=policy))
            continue
        result.append({
            key: bounded_safe_data(value[key], policy=policy, name=key)
            for key in fields
            if key in value
        })
    return result


def _bounded_artifact_content(value: Any, policy: IncidentCapsulePolicy) -> Any:
    if isinstance(value, str):
        return _redact_text(value, policy)
    return bounded_safe_data(value, policy=policy)


def _redact_text(value: str, policy: IncidentCapsulePolicy) -> str:
    text = _bounded_text(value, policy.maximum_text_characters)
    names = r"password|passwd|token|secret|authorization|api[_-]?key|apikey"
    text = re.sub(
        rf"(?i)({names})\s*[:=]\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}={policy_redaction_replacement(policy)}",
        text,
    )
    text = re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*",
        f"Bearer {policy_redaction_replacement(policy)}",
        text,
    )
    return text


def policy_redaction_replacement(_policy: IncidentCapsulePolicy) -> str:
    return "<redacted>"


def _sensitive_name(name: str | None) -> bool:
    if not name:
        return False
    return any(token in name.lower() for token in ("password", "passwd", "token", "secret", "authorization", "api_key", "apikey"))


def _integrity_text_name(name: str | None) -> bool:
    if not name:
        return False
    normalized = name.casefold().replace("-", "_")
    return normalized.endswith(("_sha256", "_fingerprint")) or normalized in {
        "sha256",
        "fingerprint",
    }


def _bounded_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + "…"


def _bounded_repr(value: Any, limit: int) -> str:
    try:
        return _bounded_text(repr(value), limit)
    except Exception as exc:
        return f"<repr failed: {type(exc).__name__}>"


def _type_name(value: Any) -> str:
    return f"{type(value).__module__}.{type(value).__qualname__}"


def _revision_number(path: Path) -> int:
    match = re.search(r"\.r(\d+)\.json$", path.name)
    if match is None:
        raise ValueError(f"invalid Incident Capsule revision path: {path}")
    return int(match.group(1))


def _uuid_value(value: Any, field_name: str) -> UUID | None:
    raw = value.get(field_name) if isinstance(value, Mapping) else getattr(value, field_name, None)
    if raw is None:
        return None
    return raw if isinstance(raw, UUID) else UUID(str(raw))


def _string_value(value: Any, field_name: str) -> str | None:
    raw = value.get(field_name) if isinstance(value, Mapping) else getattr(value, field_name, None)
    return str(raw) if raw is not None else None


def _int_value(value: Any, field_name: str) -> int | None:
    raw = value.get(field_name) if isinstance(value, Mapping) else getattr(value, field_name, None)
    return int(raw) if raw is not None else None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_signed_artifact(value: Any) -> Mapping[str, Any]:
    from .logging.signing import serialize_signed_artifact

    return serialize_signed_artifact(value)


def _deserialize_signed_artifact(value: Any) -> Any:
    from .logging.signing import deserialize_signed_artifact

    return deserialize_signed_artifact(value)
