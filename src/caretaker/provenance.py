"""Small, non-authorizing provenance projections shared by artifact families.

The envelope is intentionally a projection rather than a replacement wire
format.  Family-specific records remain responsible for their own validation,
signatures, and serialized bytes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


PROVENANCE_SCHEMA_VERSION = 1
_MAX_TEXT_LENGTH = 256


def _bounded_text(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string or None")
    if len(value) > _MAX_TEXT_LENGTH:
        raise ValueError(f"{name} exceeds the {_MAX_TEXT_LENGTH}-character limit")
    return value


def _generation(value: str | int | None) -> str | int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("authority_policy_generation must be a string, integer, or None")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("authority_policy_generation must be non-negative")
        return value
    if isinstance(value, str):
        if not value.strip():
            raise ValueError("authority_policy_generation must be non-empty when provided")
        if len(value) > _MAX_TEXT_LENGTH:
            raise ValueError(
                "authority_policy_generation exceeds the "
                f"{_MAX_TEXT_LENGTH}-character limit"
            )
        return value
    raise ValueError("authority_policy_generation must be a string, integer, or None")


@dataclass(frozen=True, slots=True)
class ProvenanceEnvelope:
    """Bounded common provenance for cross-family inspection.

    This value is evidence about an artifact or operation.  It is never an
    authority packet and its fingerprint must not be used to grant approval.
    Unknown family-specific fields are deliberately not represented here.
    """

    target_id: str | None = None
    generation_id: str | None = None
    code_hash: str | None = None
    policy_fingerprint: str | None = None
    authority_policy_generation: str | int | None = None
    authority_policy_fingerprint: str | None = None
    evidence_identity: str | None = None
    evidence_fingerprint: str | None = None
    schema_version: int = PROVENANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PROVENANCE_SCHEMA_VERSION
        ):
            raise ValueError(
                f"unsupported provenance schema_version: {self.schema_version!r}"
            )
        for name in (
            "target_id",
            "generation_id",
            "code_hash",
            "policy_fingerprint",
            "authority_policy_fingerprint",
            "evidence_identity",
            "evidence_fingerprint",
        ):
            _bounded_text(name, getattr(self, name))
        _generation(self.authority_policy_generation)

    def as_dict(self) -> dict[str, Any]:
        """Return the canonical projection, including its schema version."""

        return {
            "authority_policy_fingerprint": self.authority_policy_fingerprint,
            "authority_policy_generation": self.authority_policy_generation,
            "code_hash": self.code_hash,
            "evidence_fingerprint": self.evidence_fingerprint,
            "evidence_identity": self.evidence_identity,
            "generation_id": self.generation_id,
            "policy_fingerprint": self.policy_fingerprint,
            "schema_version": self.schema_version,
            "target_id": self.target_id,
        }

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> "ProvenanceEnvelope":
        """Project common fields from a legacy or family-specific mapping.

        Extra keys are ignored so readers can inspect newer family records
        without treating their additional fields as shared provenance.
        """

        if not isinstance(mapping, Mapping):
            raise TypeError("provenance source must be a mapping")
        schema_version = mapping.get(
            "schema_version", mapping.get("provenance_schema_version", PROVENANCE_SCHEMA_VERSION)
        )
        return cls(
            target_id=mapping.get("target_id"),
            generation_id=mapping.get("generation_id"),
            code_hash=mapping.get("code_hash"),
            policy_fingerprint=mapping.get("policy_fingerprint"),
            authority_policy_generation=mapping.get("authority_policy_generation"),
            authority_policy_fingerprint=mapping.get("authority_policy_fingerprint"),
            evidence_identity=mapping.get("evidence_identity"),
            evidence_fingerprint=mapping.get("evidence_fingerprint"),
            schema_version=schema_version,
        )

    @property
    def fingerprint(self) -> str:
        """Hash the projection for comparison; this does not authorize anything."""

        return hashlib.sha256(
            json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


__all__ = ["PROVENANCE_SCHEMA_VERSION", "ProvenanceEnvelope"]
