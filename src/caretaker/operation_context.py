"""Immutable identity for one policy- and authority-bound operation.

An operation context is a record of the inputs resolved at admission.  It is
deliberately a value object: orchestrators may carry it through a repair or
rollout, but they cannot update it when policy or authority changes.  A live
context must be checked again at explicit boundaries before it can authorize a
state-changing action.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID


class OperationContextStaleError(RuntimeError):
    """Raised when an operation no longer matches its admission context."""


@dataclass(frozen=True, slots=True)
class OperationContext:
    """The immutable context admitted for one repair or rollout operation."""

    operation_id: UUID
    target_id: str
    policy_snapshot_id: UUID | None
    policy_fingerprint: str
    authority_policy_generation: int
    authority_policy_fingerprint: str
    evidence_identity: str
    evidence_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, UUID):
            raise TypeError("operation_id must be a UUID")
        if not isinstance(self.policy_snapshot_id, (UUID, type(None))):
            raise TypeError("policy_snapshot_id must be a UUID or None")
        for name in (
            "target_id",
            "policy_fingerprint",
            "authority_policy_fingerprint",
            "evidence_identity",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if (
            isinstance(self.authority_policy_generation, bool)
            or not isinstance(self.authority_policy_generation, int)
            or self.authority_policy_generation < 0
        ):
            raise ValueError("authority_policy_generation must be a non-negative integer")
        if self.evidence_fingerprint is not None:
            if not isinstance(self.evidence_fingerprint, str) or not self.evidence_fingerprint.strip():
                raise ValueError("evidence_fingerprint must be a non-empty string or None")

    def as_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-compatible audit representation."""

        return {
            "operation_id": str(self.operation_id),
            "target_id": self.target_id,
            "policy_snapshot_id": (
                str(self.policy_snapshot_id) if self.policy_snapshot_id is not None else None
            ),
            "policy_fingerprint": self.policy_fingerprint,
            "authority_policy_generation": self.authority_policy_generation,
            "authority_policy_fingerprint": self.authority_policy_fingerprint,
            "evidence_identity": self.evidence_identity,
            "evidence_fingerprint": self.evidence_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        """Hash of the exact context used for audit equality checks."""

        return hashlib.sha256(
            json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def assert_current(
        self,
        *,
        target_id: str,
        policy_fingerprint: str,
        authority_policy_generation: int,
        authority_policy_fingerprint: str,
    ) -> None:
        """Fail closed unless live inputs still match this admitted context."""

        checks = (
            ("target_id", self.target_id, str(target_id)),
            ("policy_fingerprint", self.policy_fingerprint, str(policy_fingerprint)),
            (
                "authority_policy_generation",
                self.authority_policy_generation,
                authority_policy_generation,
            ),
            (
                "authority_policy_fingerprint",
                self.authority_policy_fingerprint,
                str(authority_policy_fingerprint),
            ),
        )
        for name, expected, observed in checks:
            if expected != observed:
                raise OperationContextStaleError(
                    f"operation context is stale: {name} does not match admission"
                )


__all__ = ["OperationContext", "OperationContextStaleError"]
