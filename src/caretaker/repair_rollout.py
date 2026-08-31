"""Policy-bound lifecycle records for runtime Repair rollouts.

This module records rollout authority; it does not route application traffic or
activate a FunctionSlot.  Those responsibilities remain with the application
and future rollout adapters.  A record therefore cannot grant execution
authority by itself.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

from .contracts import Comparator
from .domain import RepairEvent
from .execution import EffectObservation, FunctionExecutionContract
from .shadow import ShadowExecutionAdapter, ShadowExecutionResult, shadow_execute

if TYPE_CHECKING:
    from .observation import ObservationManager
    from .policy import ObservationPolicy


class RepairRolloutError(RuntimeError):
    """Raised when a rollout transition violates its lifecycle contract."""


class RepairRolloutExecutionError(RepairRolloutError):
    """Raised when a rollout record cannot be bound to a function slot."""


class RepairRolloutStage(str, Enum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    SHADOW = "shadow"
    CANARY = "canary"
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class RepairRolloutAuthority(str, Enum):
    ADVISORY = "advisory"
    OPERATOR = "operator"
    DEPLOYMENT = "deployment"
    ADAPTIVE = "adaptive"


class RepairReleaseKind(str, Enum):
    FIELD = "field-repair"
    PERMANENT = "permanent-deployment"


class RepairAuthoritativeImplementation(str, Enum):
    DEPLOYED = "deployed"
    CANDIDATE = "candidate"


@dataclass(frozen=True, slots=True)
class RolloutRoutingPolicy:
    """Policy inputs for deterministic, process-local rollout selection.

    Percentages describe the population identified by the caller's routing
    scope and key.  They do not imply an exact fleet-wide percentage: that
    requires a supervisor-owned coordinator, which is not part of this helper.
    """

    shadow_sample_percentage: int = 100
    canary_percentage: int = 0
    active_candidate_percentage: int = 100
    bucket_count: int = 10_000

    def __post_init__(self) -> None:
        for name in (
            "shadow_sample_percentage",
            "canary_percentage",
            "active_candidate_percentage",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
                raise ValueError(f"rollout.routing.{name} must be an integer from 0 through 100")
        if (
            isinstance(self.bucket_count, bool)
            or not isinstance(self.bucket_count, int)
            or not 100 <= self.bucket_count <= 1_000_000
        ):
            raise ValueError(
                "rollout.routing.bucket_count must be an integer from 100 through 1000000"
            )


@dataclass(frozen=True, slots=True)
class RepairRolloutPolicy:
    """Controls the ledger's authority and lifecycle boundaries.

    The feature is opt-in and records no application mutation.  Existing Repair
    behavior is therefore unchanged until an embedding application creates a
    ledger with an enabled policy.
    """

    enabled: bool = False
    require_validation_for_activation: bool = True
    allow_shadow_stage: bool = True
    allow_canary_stage: bool = True
    allow_direct_field_activation: bool = True
    allow_adaptive_stage_progression: bool = False
    require_deployment_authority_for_permanent: bool = True
    require_incident_for_active_revocation: bool = True
    routing: RolloutRoutingPolicy = field(default_factory=RolloutRoutingPolicy)

    def __post_init__(self) -> None:
        for name in (
            "enabled",
            "require_validation_for_activation",
            "allow_shadow_stage",
            "allow_canary_stage",
            "allow_direct_field_activation",
            "allow_adaptive_stage_progression",
            "require_deployment_authority_for_permanent",
            "require_incident_for_active_revocation",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"rollout.{name} must be a boolean")
        if not isinstance(self.routing, RolloutRoutingPolicy):
            raise ValueError("rollout.routing must be a RolloutRoutingPolicy")


@dataclass(frozen=True, slots=True)
class RepairRolloutRecord:
    rollout_id: UUID
    target_id: str
    incident_id: UUID
    candidate_id: UUID
    candidate_source_hash: str
    base_source_hash: str | None
    stage: RepairRolloutStage
    release_kind: RepairReleaseKind
    authoritative_implementation: RepairAuthoritativeImplementation
    policy_fingerprint: str
    authority_fingerprint: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    validation_evidence_hash: str | None = None
    deployment_artifact_hash: str | None = None
    last_transition_id: UUID | None = None
    transition_count: int = 0

    @property
    def authority_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= _utcnow()


@dataclass(frozen=True, slots=True)
class RepairRolloutTransition:
    transition_id: UUID
    rollout_id: UUID
    target_id: str
    from_stage: RepairRolloutStage | None
    to_stage: RepairRolloutStage
    action: str
    authority_type: RepairRolloutAuthority
    authority_id: str
    incident_id: UUID | None
    policy_fingerprint: str
    authority_fingerprint: str
    reason: str
    content_hash: str
    transition_hash: str
    previous_transition_hash: str | None
    signature: Mapping[str, Any] | None
    signature_status: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class RolloutRoutingDecision:
    """Evidence-only result of one deterministic rollout selection."""

    rollout_id: UUID
    target_id: str
    stage: RepairRolloutStage
    routing_scope: str
    routing_key_digest: str
    bucket: int
    bucket_count: int
    configured_percentage: int
    candidate_selected: bool
    candidate_authoritative: bool
    authoritative_implementation: RepairAuthoritativeImplementation
    strategy: str
    policy_fingerprint: str
    decision_hash: str
    reason: str


@dataclass(frozen=True, slots=True)
class RolloutExecutionResult:
    """Result of one invocation selected by a rollout decision."""

    result: Any
    decision: RolloutRoutingDecision
    candidate_executed: bool
    candidate_authoritative: bool
    shadow_result: ShadowExecutionResult | None = None


class RepairRolloutStore(Protocol):
    def record_rollout(self, record: RepairRolloutRecord) -> None: ...
    def all_rollouts(self) -> tuple[Any, ...]: ...
    def record_rollout_transition(self, record: RepairRolloutTransition) -> None: ...
    def all_rollout_transitions(self) -> tuple[Any, ...]: ...


class RolloutArtifactSigner(Protocol):
    def sign_artifact(self, **kwargs: Any) -> Any: ...


class RepairRolloutLedger:
    """In-process rollout state backed by optional durable Repair storage."""

    def __init__(
        self,
        *,
        policy: RepairRolloutPolicy,
        store: RepairRolloutStore | None = None,
        signer: RolloutArtifactSigner | None = None,
        audit_event: Callable[..., Any] | None = None,
        clock: Any | None = None,
    ) -> None:
        self.policy = policy
        self.store = store
        self.signer = signer
        self.audit_event = audit_event
        self._clock = clock or _utcnow
        self._records: dict[UUID, RepairRolloutRecord] = {}
        self._transitions: dict[UUID, RepairRolloutTransition] = {}
        self._restore()

    def create(
        self,
        *,
        target_id: str,
        incident_id: UUID,
        candidate_id: UUID,
        candidate_source_hash: str,
        base_source_hash: str | None,
        policy_fingerprint: str,
        authority_fingerprint: str,
        proposed_by: str,
        authority_type: RepairRolloutAuthority = RepairRolloutAuthority.ADVISORY,
        expires_at: datetime | None = None,
        validation_evidence_hash: str | None = None,
        reason: str = "repair rollout proposed",
    ) -> RepairRolloutRecord:
        self._require_enabled()
        if not target_id.strip():
            raise RepairRolloutError("rollout target_id is required")
        if not candidate_source_hash.strip():
            raise RepairRolloutError("rollout candidate_source_hash is required")
        if not proposed_by.strip():
            raise RepairRolloutError("rollout proposer identity is required")
        if authority_type is RepairRolloutAuthority.ADVISORY:
            # Advisory actors may propose evidence, but the proposal remains
            # non-authoritative until a permitted actor advances it.
            pass
        now = self._clock()
        record = RepairRolloutRecord(
            rollout_id=uuid4(),
            target_id=target_id,
            incident_id=incident_id,
            candidate_id=candidate_id,
            candidate_source_hash=candidate_source_hash,
            base_source_hash=base_source_hash,
            stage=RepairRolloutStage.PROPOSED,
            release_kind=RepairReleaseKind.FIELD,
            authoritative_implementation=RepairAuthoritativeImplementation.DEPLOYED,
            policy_fingerprint=policy_fingerprint,
            authority_fingerprint=authority_fingerprint,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            validation_evidence_hash=validation_evidence_hash,
        )
        self._records[record.rollout_id] = record
        self._persist_record(record)
        self._record_transition(
            record,
            from_stage=None,
            to_stage=RepairRolloutStage.PROPOSED,
            action="propose",
            authority_type=authority_type,
            authority_id=proposed_by,
            incident_id=incident_id,
            reason=reason,
        )
        return self._records[record.rollout_id]

    def advance(
        self,
        rollout_id: UUID,
        *,
        to_stage: RepairRolloutStage,
        authority_type: RepairRolloutAuthority,
        authority_id: str,
        reason: str,
        policy_fingerprint: str,
        authority_fingerprint: str,
        validation_evidence_hash: str | None = None,
        incident_id: UUID | None = None,
    ) -> RepairRolloutRecord:
        self._require_enabled()
        record = self._get(rollout_id)
        self._check_context(record, policy_fingerprint, authority_fingerprint)
        self._require_actor(authority_type, authority_id)
        try:
            to_stage = RepairRolloutStage(to_stage)
        except (TypeError, ValueError) as exc:
            raise RepairRolloutError("unknown rollout stage") from exc
        if record.stage in {RepairRolloutStage.RETIRED, RepairRolloutStage.REVOKED}:
            raise RepairRolloutError(f"rollout is terminal in stage {record.stage.value}")
        if self._authority_expired(record) and to_stage not in {
            RepairRolloutStage.RETIRED,
            RepairRolloutStage.REVOKED,
        }:
            raise RepairRolloutError("rollout authority has expired")
        if (
            to_stage is RepairRolloutStage.VALIDATED
            and self.policy.require_validation_for_activation
            and not validation_evidence_hash
            and not record.validation_evidence_hash
        ):
            raise RepairRolloutError(
                "validation evidence is required before entering the validated stage"
            )
        self._check_transition(record, to_stage, authority_type)
        if to_stage is RepairRolloutStage.REVOKED and (
            record.stage is RepairRolloutStage.ACTIVE
            and self.policy.require_incident_for_active_revocation
            and incident_id is None
        ):
            raise RepairRolloutError(
                "revoking an active rollout requires a new incident"
            )
        now = self._clock()
        updated = replace(
            record,
            stage=to_stage,
            updated_at=now,
            authoritative_implementation=(
                RepairAuthoritativeImplementation.CANDIDATE
                if to_stage is RepairRolloutStage.ACTIVE
                else record.authoritative_implementation
            ),
            validation_evidence_hash=validation_evidence_hash or record.validation_evidence_hash,
        )
        self._records[rollout_id] = updated
        self._persist_record(updated)
        self._record_transition(
            updated,
            from_stage=record.stage,
            to_stage=to_stage,
            action="advance",
            authority_type=authority_type,
            authority_id=authority_id,
            incident_id=incident_id,
            reason=reason,
        )
        return self._records[rollout_id]

    def promote_permanent(
        self,
        rollout_id: UUID,
        *,
        authority_id: str,
        authority_type: RepairRolloutAuthority = RepairRolloutAuthority.DEPLOYMENT,
        policy_fingerprint: str,
        authority_fingerprint: str,
        deployment_artifact_hash: str,
        reason: str,
        incident_id: UUID | None = None,
    ) -> RepairRolloutRecord:
        self._require_enabled()
        record = self._get(rollout_id)
        self._check_context(record, policy_fingerprint, authority_fingerprint)
        if self.policy.require_deployment_authority_for_permanent:
            if authority_type is not RepairRolloutAuthority.DEPLOYMENT:
                raise RepairRolloutError("permanent promotion requires deployment authority")
            self._require_actor(authority_type, authority_id)
        if record.stage is not RepairRolloutStage.ACTIVE:
            raise RepairRolloutError("only an active field repair can become permanent")
        if self._authority_expired(record):
            raise RepairRolloutError("rollout authority has expired")
        if record.release_kind is RepairReleaseKind.PERMANENT:
            return record
        if not deployment_artifact_hash.strip():
            raise RepairRolloutError("deployment_artifact_hash is required")
        now = self._clock()
        updated = replace(
            record,
            release_kind=RepairReleaseKind.PERMANENT,
            authoritative_implementation=RepairAuthoritativeImplementation.DEPLOYED,
            deployment_artifact_hash=deployment_artifact_hash,
            updated_at=now,
        )
        self._records[rollout_id] = updated
        self._persist_record(updated)
        self._record_transition(
            updated,
            from_stage=record.stage,
            to_stage=record.stage,
            action="promote-permanent",
            authority_type=authority_type,
            authority_id=authority_id,
            incident_id=incident_id,
            reason=reason,
        )
        return self._records[rollout_id]

    def get(self, rollout_id: UUID) -> RepairRolloutRecord:
        return self._get(rollout_id)

    def all(self) -> tuple[RepairRolloutRecord, ...]:
        return tuple(sorted(self._records.values(), key=lambda item: item.created_at))

    def transitions(self, rollout_id: UUID | None = None) -> tuple[RepairRolloutTransition, ...]:
        values = self._transitions.values()
        if rollout_id is not None:
            values = (item for item in values if item.rollout_id == rollout_id)
        return tuple(sorted(values, key=lambda item: item.created_at))

    def _check_transition(
        self,
        record: RepairRolloutRecord,
        to_stage: RepairRolloutStage,
        authority_type: RepairRolloutAuthority,
    ) -> None:
        allowed: dict[RepairRolloutStage, set[RepairRolloutStage]] = {
            RepairRolloutStage.PROPOSED: {RepairRolloutStage.VALIDATED, RepairRolloutStage.REVOKED},
            RepairRolloutStage.VALIDATED: {RepairRolloutStage.SHADOW, RepairRolloutStage.CANARY, RepairRolloutStage.ACTIVE, RepairRolloutStage.REVOKED},
            RepairRolloutStage.SHADOW: {RepairRolloutStage.CANARY, RepairRolloutStage.REVOKED},
            RepairRolloutStage.CANARY: {RepairRolloutStage.ACTIVE, RepairRolloutStage.REVOKED},
            RepairRolloutStage.ACTIVE: {RepairRolloutStage.RETIRED, RepairRolloutStage.REVOKED},
        }
        if to_stage not in allowed.get(record.stage, set()):
            raise RepairRolloutError(
                f"invalid rollout transition {record.stage.value} -> {to_stage.value}"
            )
        if to_stage is RepairRolloutStage.SHADOW and not self.policy.allow_shadow_stage:
            raise RepairRolloutError("shadow stage is disabled by rollout policy")
        if to_stage is RepairRolloutStage.CANARY and not self.policy.allow_canary_stage:
            raise RepairRolloutError("canary stage is disabled by rollout policy")
        if to_stage is RepairRolloutStage.ACTIVE:
            if self.policy.require_validation_for_activation and record.stage is RepairRolloutStage.PROPOSED:
                raise RepairRolloutError("activation requires a validated rollout")
            if record.stage is RepairRolloutStage.VALIDATED:
                if not self.policy.allow_direct_field_activation:
                    raise RepairRolloutError("direct field activation is disabled by rollout policy")
                if authority_type is not RepairRolloutAuthority.OPERATOR:
                    raise RepairRolloutError("direct field activation requires operator authority")
        if authority_type is RepairRolloutAuthority.ADAPTIVE and not self.policy.allow_adaptive_stage_progression:
            raise RepairRolloutError("adaptive authority cannot advance rollout stages under this policy")
        if authority_type is RepairRolloutAuthority.ADVISORY:
            raise RepairRolloutError("advisory authority cannot advance a rollout")

    def _check_context(
        self,
        record: RepairRolloutRecord,
        policy_fingerprint: str,
        authority_fingerprint: str,
    ) -> None:
        if record.policy_fingerprint != policy_fingerprint:
            raise RepairRolloutError("rollout policy fingerprint is stale")
        if record.authority_fingerprint != authority_fingerprint:
            raise RepairRolloutError("rollout authority fingerprint is stale")

    @staticmethod
    def _require_actor(authority_type: RepairRolloutAuthority, authority_id: str) -> None:
        if authority_type is RepairRolloutAuthority.ADVISORY:
            raise RepairRolloutError("advisory authority cannot perform rollout work")
        if not authority_id.strip():
            raise RepairRolloutError("rollout authority identity is required")

    def _get(self, rollout_id: UUID) -> RepairRolloutRecord:
        try:
            return self._records[rollout_id]
        except KeyError as exc:
            raise RepairRolloutError(f"unknown rollout {rollout_id}") from exc

    def _require_enabled(self) -> None:
        if not self.policy.enabled:
            raise RepairRolloutError("repair rollout is disabled by policy")

    def _authority_expired(self, record: RepairRolloutRecord) -> bool:
        return record.expires_at is not None and record.expires_at <= self._clock()

    def _persist_record(self, record: RepairRolloutRecord) -> None:
        if self.store is not None:
            self.store.record_rollout(record)

    def _record_transition(
        self,
        record: RepairRolloutRecord,
        *,
        from_stage: RepairRolloutStage | None,
        to_stage: RepairRolloutStage,
        action: str,
        authority_type: RepairRolloutAuthority,
        authority_id: str,
        incident_id: UUID | None,
        reason: str,
    ) -> RepairRolloutTransition:
        previous = self.transitions(record.rollout_id)
        previous_hash = previous[-1].transition_hash if previous else None
        content = {
            "rollout_id": str(record.rollout_id),
            "target_id": record.target_id,
            "from_stage": from_stage.value if from_stage else None,
            "to_stage": to_stage.value,
            "action": action,
            "authority_type": authority_type.value,
            "authority_id": authority_id,
            "incident_id": str(incident_id) if incident_id else None,
            "policy_fingerprint": record.policy_fingerprint,
            "authority_fingerprint": record.authority_fingerprint,
            "reason": reason,
            "created_at": self._clock().isoformat(),
            "previous_transition_hash": previous_hash,
        }
        content_hash = _digest(content)
        signature, signature_status = _sign(
            self.signer,
            content_hash=content_hash,
            previous_hash=previous_hash,
            context=content,
        )
        transition_hash = _digest({**content, "content_hash": content_hash, "signature": signature})
        transition = RepairRolloutTransition(
            transition_id=uuid4(),
            rollout_id=record.rollout_id,
            target_id=record.target_id,
            from_stage=from_stage,
            to_stage=to_stage,
            action=action,
            authority_type=authority_type,
            authority_id=authority_id,
            incident_id=incident_id,
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
            reason=reason,
            content_hash=content_hash,
            transition_hash=transition_hash,
            previous_transition_hash=previous_hash,
            signature=signature,
            signature_status=signature_status,
            created_at=self._clock(),
        )
        updated = replace(
            record,
            last_transition_id=transition.transition_id,
            transition_count=record.transition_count + 1,
        )
        self._records[record.rollout_id] = updated
        self._persist_record(updated)
        self._transitions[transition.transition_id] = transition
        if self.store is not None:
            self.store.record_rollout_transition(transition)
            append_event = getattr(self.store, "append_event", None)
            if append_event is not None:
                append_event(
                    RepairEvent.create(
                        "repair.rollout.transition",
                        record.target_id,
                        incident_id=incident_id or record.incident_id,
                        candidate_id=record.candidate_id,
                        details={
                            "rollout_id": str(record.rollout_id),
                            "transition_id": str(transition.transition_id),
                            "from_stage": from_stage.value if from_stage else None,
                            "to_stage": to_stage.value,
                            "action": action,
                            "authority_type": authority_type.value,
                            "authority_id": authority_id,
                            "policy_fingerprint": record.policy_fingerprint,
                            "authority_fingerprint": record.authority_fingerprint,
                            "content_hash": content_hash,
                            "transition_hash": transition_hash,
                            "signature_status": signature_status,
                        },
                    )
                )
        if self.audit_event is not None:
            self.audit_event(
                "REPAIR_ROLLOUT_TRANSITION",
                actor={
                    "type": authority_type.value,
                    "id": authority_id,
                },
                scope={
                    "target_id": record.target_id,
                    "incident_id": str(incident_id or record.incident_id),
                    "rollout_id": str(record.rollout_id),
                    "transition_id": str(transition.transition_id),
                },
                policy={
                    "fingerprint": record.policy_fingerprint,
                    "authority_fingerprint": record.authority_fingerprint,
                },
                outcome={
                    "state": to_stage.value,
                    "from_state": from_stage.value if from_stage else None,
                    "action": action,
                },
                details={
                    "candidate_id": str(record.candidate_id),
                    "content_hash": content_hash,
                    "transition_hash": transition_hash,
                    "signature_status": signature_status,
                    "reason": reason,
                },
            )
        return transition

    def _restore(self) -> None:
        if self.store is None:
            return
        for raw in self.store.all_rollouts():
            record = _coerce_record(raw)
            self._records[record.rollout_id] = record
        for raw in self.store.all_rollout_transitions():
            transition = _coerce_transition(raw)
            self._transitions[transition.transition_id] = transition


def decide_rollout_routing(
    record: RepairRolloutRecord,
    *,
    policy: RepairRolloutPolicy,
    policy_fingerprint: str,
    routing_scope: str,
    routing_key: str,
    audit_event: Callable[..., Any] | None = None,
) -> RolloutRoutingDecision:
    """Select a rollout implementation for one scoped invocation.

    The result is deterministic for the same rollout, scope, and key.  It is
    only a routing decision: callers remain responsible for invoking the
    selected implementation under the normal Repair, Integrity, Guard, and
    authority checks.  Shadow selection never makes the candidate authoritative.
    """

    if not policy.enabled:
        raise RepairRolloutError("rollout routing is disabled by policy")
    if not policy_fingerprint.strip():
        raise RepairRolloutError("current rollout policy fingerprint is required")
    if record.policy_fingerprint != policy_fingerprint:
        raise RepairRolloutError("rollout policy fingerprint is stale")
    scope = routing_scope.strip()
    if not scope:
        raise RepairRolloutError("rollout routing scope is required")
    if not isinstance(routing_key, str) or not routing_key:
        raise RepairRolloutError("rollout routing key is required")
    if record.authority_expired:
        raise RepairRolloutError("rollout authority has expired")
    if record.stage in {RepairRolloutStage.RETIRED, RepairRolloutStage.REVOKED}:
        raise RepairRolloutError(f"rollout is terminal in stage {record.stage.value}")

    routing = policy.routing
    key_digest = hashlib.sha256(
        b"caretaker.rollout.routing.key\0"
        + scope.encode("utf-8")
        + b"\0"
        + routing_key.encode("utf-8")
    ).hexdigest()
    bucket = int.from_bytes(
        hashlib.sha256(
            b"caretaker.rollout.routing.bucket\0"
            + str(record.rollout_id).encode("ascii")
            + b"\0"
            + scope.encode("utf-8")
            + b"\0"
            + routing_key.encode("utf-8")
        ).digest()[:8],
        "big",
    ) % routing.bucket_count

    percentage = 0
    candidate_selected = False
    candidate_authoritative = False
    strategy = "deployed"
    reason = "rollout stage keeps the deployed implementation authoritative"
    if record.stage is RepairRolloutStage.SHADOW:
        if not policy.allow_shadow_stage:
            raise RepairRolloutError("shadow stage is disabled by rollout policy")
        percentage = routing.shadow_sample_percentage
        candidate_selected = _bucket_selected(bucket, routing.bucket_count, percentage)
        strategy = "shadow" if candidate_selected else "deployed"
        reason = (
            "candidate selected for non-authoritative shadow execution"
            if candidate_selected
            else "candidate not selected by shadow sampling percentage"
        )
    elif record.stage is RepairRolloutStage.CANARY:
        if not policy.allow_canary_stage:
            raise RepairRolloutError("canary stage is disabled by rollout policy")
        percentage = routing.canary_percentage
        candidate_selected = _bucket_selected(bucket, routing.bucket_count, percentage)
        candidate_authoritative = candidate_selected
        strategy = "canary" if candidate_selected else "deployed"
        reason = (
            "candidate selected as authoritative canary implementation"
            if candidate_selected
            else "deployed implementation retained by canary percentage"
        )
    elif record.stage is RepairRolloutStage.ACTIVE:
        if record.authoritative_implementation is RepairAuthoritativeImplementation.CANDIDATE:
            percentage = routing.active_candidate_percentage
            candidate_selected = _bucket_selected(bucket, routing.bucket_count, percentage)
            candidate_authoritative = candidate_selected
            strategy = "active-candidate" if candidate_selected else "deployed"
            reason = (
                "active field-repair candidate selected as authoritative implementation"
                if candidate_selected
                else "deployed implementation retained by active candidate percentage"
            )
        else:
            reason = "permanent deployment record is already authoritative as deployed"

    implementation = (
        RepairAuthoritativeImplementation.CANDIDATE
        if candidate_authoritative
        else RepairAuthoritativeImplementation.DEPLOYED
    )
    evidence = {
        "rollout_id": str(record.rollout_id),
        "target_id": record.target_id,
        "stage": record.stage.value,
        "routing_scope": scope,
        "routing_key_digest": key_digest,
        "bucket": bucket,
        "bucket_count": routing.bucket_count,
        "configured_percentage": percentage,
        "candidate_selected": candidate_selected,
        "candidate_authoritative": candidate_authoritative,
        "authoritative_implementation": implementation.value,
        "strategy": strategy,
        "policy_fingerprint": policy_fingerprint,
        "reason": reason,
    }
    decision = RolloutRoutingDecision(
        rollout_id=record.rollout_id,
        target_id=record.target_id,
        stage=record.stage,
        routing_scope=scope,
        routing_key_digest=key_digest,
        bucket=bucket,
        bucket_count=routing.bucket_count,
        configured_percentage=percentage,
        candidate_selected=candidate_selected,
        candidate_authoritative=candidate_authoritative,
        authoritative_implementation=implementation,
        strategy=strategy,
        policy_fingerprint=policy_fingerprint,
        decision_hash=_digest(evidence),
        reason=reason,
    )
    if audit_event is not None:
        audit_event(
            "REPAIR_ROLLOUT_ROUTING_DECISION",
            actor={"type": "caretaker", "id": "rollout-router"},
            scope={
                "target_id": record.target_id,
                "rollout_id": str(record.rollout_id),
                "routing_scope": scope,
                "routing_key_digest": key_digest,
            },
            policy={"fingerprint": policy_fingerprint},
            outcome={
                "state": "SELECTED",
                "stage": record.stage.value,
                "strategy": strategy,
                "candidate_selected": candidate_selected,
                "candidate_authoritative": candidate_authoritative,
                "authoritative_implementation": implementation.value,
            },
            details={
                "bucket": bucket,
                "bucket_count": routing.bucket_count,
                "configured_percentage": percentage,
                "decision_hash": decision.decision_hash,
            },
        )
    return decision


def execute_rollout(
    record: RepairRolloutRecord,
    *,
    policy: RepairRolloutPolicy,
    policy_fingerprint: str,
    routing_scope: str,
    routing_key: str,
    deployed: Callable[..., Any],
    candidate: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: FunctionExecutionContract,
    effect_observation: EffectObservation | None = None,
    isolation_adapter: ShadowExecutionAdapter | None = None,
    comparator: Comparator | None = None,
    audit_event: Callable[..., Any] | None = None,
) -> RolloutExecutionResult:
    """Invoke an already-authorized rollout path.

    This adapter consumes, but does not create, rollout authority.  A sampled
    shadow candidate is executed through the original-authoritative shadow
    primitive.  A canary or active candidate is invoked only when the routing
    decision explicitly makes it authoritative; all other calls use ``deployed``.
    The caller remains responsible for selecting functions that passed its
    normal Repair, Integrity, Guard, and authority checks.
    """

    decision = decide_rollout_routing(
        record,
        policy=policy,
        policy_fingerprint=policy_fingerprint,
        routing_scope=routing_scope,
        routing_key=routing_key,
        audit_event=audit_event,
    )
    return _execute_rollout_decision(
        decision,
        deployed=deployed,
        candidate=candidate,
        args=args,
        kwargs=kwargs,
        contract=contract,
        effect_observation=effect_observation,
        isolation_adapter=isolation_adapter,
        comparator=comparator,
        audit_event=audit_event,
    )


def execute_slot_rollout(
    slot: "FunctionSlot",
    record: RepairRolloutRecord,
    *,
    policy: RepairRolloutPolicy,
    policy_fingerprint: str,
    routing_scope: str,
    routing_key: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    effect_observation: EffectObservation | None = None,
    isolation_adapter: ShadowExecutionAdapter | None = None,
    comparator: Comparator | None = None,
    audit_event: Callable[..., Any] | None = None,
    observation_manager: "ObservationManager | None" = None,
    observation_policy: "ObservationPolicy | None" = None,
    call_id: UUID | None = None,
) -> RolloutExecutionResult:
    """Execute a rollout bound to one slot's current candidate.

    The slot binding is intentionally strict.  A field repair must use the
    candidate currently installed in the slot and the immediately preceding
    version as its deployed counterpart.  A permanent record treats the
    current slot version as deployed code and cannot re-route it as a field
    candidate.  Observation accounting is opt-in. When an
    ``ObservationManager``, its policy, and a call ID are supplied, only
    authoritative candidate calls are counted. Candidate failures are passed
    to the manager's existing policy-driven rollback logic and then re-raised;
    there is no silent fallback. Shadow executions are never counted as
    acceptance observations.
    """

    if record.stage not in {
        RepairRolloutStage.SHADOW,
        RepairRolloutStage.CANARY,
        RepairRolloutStage.ACTIVE,
    }:
        raise RepairRolloutExecutionError(
            f"rollout stage {record.stage.value} is not executable"
        )
    if observation_manager is None:
        if observation_policy is not None or call_id is not None:
            raise RepairRolloutExecutionError(
                "observation policy and call ID require an observation manager"
            )
    elif observation_policy is None or call_id is None:
        raise RepairRolloutExecutionError(
            "observation manager requires an observation policy and call ID"
        )
    if record.target_id != slot.target_id:
        raise RepairRolloutExecutionError("rollout target does not match function slot")

    current = slot.load()
    if current.candidate_id != record.candidate_id:
        raise RepairRolloutExecutionError(
            "rollout candidate does not match the function slot candidate"
        )
    if current.source_hash != record.candidate_source_hash:
        raise RepairRolloutExecutionError(
            "rollout candidate source does not match the function slot candidate"
        )

    if record.release_kind is RepairReleaseKind.PERMANENT:
        deployed = current.implementation
        candidate = current.implementation
    else:
        previous = slot.previous()
        if previous is None:
            raise RepairRolloutExecutionError(
                "field rollout requires a preceding deployed function version"
            )
        if (
            record.base_source_hash is not None
            and previous.source_hash != record.base_source_hash
        ):
            raise RepairRolloutExecutionError(
                "rollout deployed source does not match the function slot history"
            )
        deployed = previous.implementation
        candidate = current.implementation

    decision = decide_rollout_routing(
        record,
        policy=policy,
        policy_fingerprint=policy_fingerprint,
        routing_scope=routing_scope,
        routing_key=routing_key,
        audit_event=audit_event,
    )
    try:
        result = _execute_rollout_decision(
            decision,
            deployed=deployed,
            candidate=candidate,
            args=args,
            kwargs=kwargs,
            contract=slot.execution_contract,
            effect_observation=effect_observation,
            isolation_adapter=isolation_adapter,
            comparator=comparator,
            audit_event=audit_event,
        )
    except BaseException as exc:
        if decision.candidate_authoritative and observation_manager is not None:
            try:
                observation_manager.record_failure(
                    slot=slot,
                    call_id=call_id,
                    exception=exc,
                    policy=observation_policy,
                    mode=decision.strategy,
                    rollout_id=record.rollout_id,
                    routing_decision_hash=decision.decision_hash,
                )
            except BaseException as accounting_error:
                raise exc from accounting_error
        raise
    if decision.candidate_authoritative and observation_manager is not None:
        observation_manager.record_success(
            slot=slot,
            call_id=call_id,
            policy=observation_policy,
            output=result.result,
            mode=decision.strategy,
            rollout_id=record.rollout_id,
            routing_decision_hash=decision.decision_hash,
        )
    return result


def _execute_rollout_decision(
    decision: RolloutRoutingDecision,
    *,
    deployed: Callable[..., Any],
    candidate: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: FunctionExecutionContract,
    effect_observation: EffectObservation | None,
    isolation_adapter: ShadowExecutionAdapter | None,
    comparator: Comparator | None,
    audit_event: Callable[..., Any] | None,
) -> RolloutExecutionResult:
    if decision.strategy == "shadow":
        shadow = shadow_execute(
            original=deployed,
            candidate=candidate,
            args=args,
            kwargs=kwargs,
            contract=contract,
            effect_observation=effect_observation,
            isolation_adapter=isolation_adapter,
            comparator=comparator,
            audit_event=audit_event,
        )
        return RolloutExecutionResult(
            result=shadow.result,
            decision=decision,
            candidate_executed=True,
            candidate_authoritative=False,
            shadow_result=shadow,
        )
    if decision.candidate_authoritative:
        return RolloutExecutionResult(
            result=candidate(*args, **kwargs),
            decision=decision,
            candidate_executed=True,
            candidate_authoritative=True,
        )
    return RolloutExecutionResult(
        result=deployed(*args, **kwargs),
        decision=decision,
        candidate_executed=False,
        candidate_authoritative=False,
    )


def _bucket_selected(bucket: int, bucket_count: int, percentage: int) -> bool:
    return bucket < (bucket_count * percentage // 100)


def _sign(
    signer: RolloutArtifactSigner | None,
    *,
    content_hash: str,
    previous_hash: str | None,
    context: Mapping[str, Any],
) -> tuple[Mapping[str, Any] | None, str]:
    if signer is None:
        return None, "UNSIGNED"
    signed = signer.sign_artifact(
        artifact_kind="repair-rollout-transition",
        content_hash=content_hash,
        previous_artifact_hash=previous_hash,
        context=context,
    )
    if signed is None:
        return None, "HASHED_AND_CHAINED"
    from .logging.signing import serialize_signed_artifact

    return serialize_signed_artifact(signed), signed.signer_mode.name


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_record(raw: Any) -> RepairRolloutRecord:
    if isinstance(raw, RepairRolloutRecord):
        return raw
    return RepairRolloutRecord(
        rollout_id=UUID(str(raw["rollout_id"])),
        target_id=str(raw["target_id"]),
        incident_id=UUID(str(raw["incident_id"])),
        candidate_id=UUID(str(raw["candidate_id"])),
        candidate_source_hash=str(raw["candidate_source_hash"]),
        base_source_hash=raw.get("base_source_hash"),
        stage=_coerce_enum(RepairRolloutStage, raw["stage"]),
        release_kind=_coerce_enum(RepairReleaseKind, raw["release_kind"]),
        authoritative_implementation=_coerce_enum(
            RepairAuthoritativeImplementation, raw["authoritative_implementation"]
        ),
        policy_fingerprint=str(raw["policy_fingerprint"]),
        authority_fingerprint=str(raw["authority_fingerprint"]),
        created_at=datetime.fromisoformat(str(raw["created_at"])),
        updated_at=datetime.fromisoformat(str(raw["updated_at"])),
        expires_at=(
            datetime.fromisoformat(str(raw["expires_at"]))
            if raw.get("expires_at")
            else None
        ),
        validation_evidence_hash=raw.get("validation_evidence_hash"),
        deployment_artifact_hash=raw.get("deployment_artifact_hash"),
        last_transition_id=(
            UUID(str(raw["last_transition_id"]))
            if raw.get("last_transition_id")
            else None
        ),
        transition_count=int(raw.get("transition_count") or 0),
    )


def _coerce_transition(raw: Any) -> RepairRolloutTransition:
    if isinstance(raw, RepairRolloutTransition):
        return raw
    return RepairRolloutTransition(
        transition_id=UUID(str(raw["transition_id"])),
        rollout_id=UUID(str(raw["rollout_id"])),
        target_id=str(raw["target_id"]),
        from_stage=(
            _coerce_enum(RepairRolloutStage, raw["from_stage"])
            if raw.get("from_stage")
            else None
        ),
        to_stage=_coerce_enum(RepairRolloutStage, raw["to_stage"]),
        action=str(raw["action"]),
        authority_type=_coerce_enum(RepairRolloutAuthority, raw["authority_type"]),
        authority_id=str(raw["authority_id"]),
        incident_id=(UUID(str(raw["incident_id"])) if raw.get("incident_id") else None),
        policy_fingerprint=str(raw["policy_fingerprint"]),
        authority_fingerprint=str(raw["authority_fingerprint"]),
        reason=str(raw["reason"]),
        content_hash=str(raw["content_hash"]),
        transition_hash=str(raw["transition_hash"]),
        previous_transition_hash=raw.get("previous_transition_hash"),
        signature=raw.get("signature"),
        signature_status=str(raw["signature_status"]),
        created_at=datetime.fromisoformat(str(raw["created_at"])),
    )


def _coerce_enum(enum_type: type[Enum], value: Any) -> Any:
    if isinstance(value, enum_type):
        return value
    text = str(value)
    try:
        return enum_type[text]
    except KeyError:
        return enum_type(text)
