"""Policy-bound lifecycle records for runtime Repair rollouts.

This module records rollout authority; it does not route application traffic or
activate a FunctionSlot.  Those responsibilities remain with the application
and future rollout adapters.  A record therefore cannot grant execution
authority by itself.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import threading
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
    candidate_id: UUID
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
    execution_observation: "RolloutExecutionObservation | None" = None


@dataclass(frozen=True, slots=True)
class RolloutExecutionObservation:
    """Bounded evidence for one rollout invocation.

    This record intentionally contains no return values or exception messages.
    It is an observation ledger, not a source of rollout authority.
    """

    observation_id: UUID
    rollout_id: UUID
    target_id: str
    candidate_id: UUID
    stage: RepairRolloutStage
    strategy: str
    authoritative_implementation: RepairAuthoritativeImplementation
    candidate_executed: bool
    candidate_authoritative: bool
    original_succeeded: bool | None
    candidate_succeeded: bool | None
    equivalent: bool | None
    execution_state: str
    exception_type: str | None
    decision_hash: str
    policy_fingerprint: str
    created_at: datetime
    content_hash: str


@dataclass(frozen=True, slots=True)
class RolloutExecutionSummary:
    """Read-only aggregate of integrity-checked rollout observations."""

    rollout_id: UUID
    target_id: str
    candidate_id: UUID
    policy_fingerprint: str
    observation_count: int
    completed_count: int
    failed_count: int
    candidate_execution_count: int
    candidate_authoritative_count: int
    candidate_success_count: int
    candidate_failure_count: int
    shadow_count: int
    shadow_equivalent_count: int
    shadow_mismatch_count: int
    shadow_inconclusive_count: int
    invalid_observation_count: int
    stage_counts: Mapping[str, int]
    evidence_hash: str


@dataclass(frozen=True, slots=True)
class RolloutWorkerAcknowledgement:
    """Durable evidence that one worker observed the current rollout context.

    This is a supervisor coordination record, not an authority grant. A
    worker must still pass the supervisor's process and authority checks before
    this record is accepted by an application control plane.
    """

    acknowledgement_id: UUID
    rollout_id: UUID
    target_id: str
    candidate_id: UUID
    worker_id: str
    worker_process_id: int
    stage: RepairRolloutStage
    policy_fingerprint: str
    authority_fingerprint: str
    acknowledged_at: datetime
    content_hash: str


def _execution_observation_payload(
    observation: RolloutExecutionObservation,
) -> dict[str, Any]:
    return {
        "observation_id": str(observation.observation_id),
        "rollout_id": str(observation.rollout_id),
        "target_id": observation.target_id,
        "candidate_id": str(observation.candidate_id),
        "stage": observation.stage.value,
        "strategy": observation.strategy,
        "authoritative_implementation": observation.authoritative_implementation.value,
        "candidate_executed": observation.candidate_executed,
        "candidate_authoritative": observation.candidate_authoritative,
        "original_succeeded": observation.original_succeeded,
        "candidate_succeeded": observation.candidate_succeeded,
        "equivalent": observation.equivalent,
        "execution_state": observation.execution_state,
        "exception_type": observation.exception_type,
        "decision_hash": observation.decision_hash,
        "policy_fingerprint": observation.policy_fingerprint,
    }


def _worker_acknowledgement_payload(
    acknowledgement: RolloutWorkerAcknowledgement,
) -> dict[str, Any]:
    return {
        "acknowledgement_id": str(acknowledgement.acknowledgement_id),
        "rollout_id": str(acknowledgement.rollout_id),
        "target_id": acknowledgement.target_id,
        "candidate_id": str(acknowledgement.candidate_id),
        "worker_id": acknowledgement.worker_id,
        "worker_process_id": acknowledgement.worker_process_id,
        "stage": acknowledgement.stage.value,
        "policy_fingerprint": acknowledgement.policy_fingerprint,
        "authority_fingerprint": acknowledgement.authority_fingerprint,
        "acknowledged_at": acknowledgement.acknowledged_at.isoformat(),
    }


class RepairRolloutStore(Protocol):
    def record_rollout(self, record: RepairRolloutRecord) -> None: ...
    def all_rollouts(self) -> tuple[Any, ...]: ...
    def record_rollout_transition(self, record: RepairRolloutTransition) -> None: ...
    def all_rollout_transitions(self) -> tuple[Any, ...]: ...
    def record_rollout_execution(self, record: RolloutExecutionObservation) -> None: ...
    def all_rollout_executions(self) -> tuple[Any, ...]: ...
    def record_rollout_worker_acknowledgement(
        self, record: RolloutWorkerAcknowledgement
    ) -> None: ...
    def all_rollout_worker_acknowledgements(self) -> tuple[Any, ...]: ...


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

    def execution_summary(
        self,
        rollout_id: UUID,
        *,
        policy_fingerprint: str,
    ) -> RolloutExecutionSummary:
        """Summarize persisted execution evidence without changing rollout state."""

        record = self._get(rollout_id)
        self._check_context(record, policy_fingerprint, record.authority_fingerprint)
        if self.store is None:
            observations: tuple[Any, ...] = ()
        else:
            reader = getattr(self.store, "all_rollout_executions", None)
            if not callable(reader):
                raise RepairRolloutError(
                    "rollout store does not support execution observations"
                )
            observations = tuple(reader())
        return summarize_rollout_executions(
            record,
            observations,
            policy_fingerprint=policy_fingerprint,
        )

    def operator_projection(
        self,
        *,
        policy_fingerprint: str,
        rollout_id: UUID | None = None,
        limit: int = 100,
        transition_limit: int = 200,
    ) -> dict[str, Any]:
        """Return a bounded, read-only projection for operator review.

        The projection deliberately reports stale or unavailable execution
        evidence alongside the rollout record. It never advances a stage,
        changes routing, or grants authority.
        """

        if limit < 1 or transition_limit < 1:
            raise ValueError("rollout projection limits must be positive")
        records = self.all()
        if rollout_id is not None:
            records = tuple(item for item in records if item.rollout_id == rollout_id)
        records = records[:limit]
        record_payloads: list[dict[str, Any]] = []
        for record in records:
            item = _json_safe(record)
            try:
                item["execution_summary"] = _json_safe(
                    self.execution_summary(
                        record.rollout_id,
                        policy_fingerprint=policy_fingerprint,
                    )
                )
                item["execution_summary_status"] = "AVAILABLE"
            except RepairRolloutError as exc:
                item["execution_summary"] = None
                item["execution_summary_status"] = "STALE_OR_UNAVAILABLE"
                item["execution_summary_reason"] = str(exc)
            record_payloads.append(item)

        return {
            "read_only": True,
            "authority_granted": False,
            "policy_fingerprint": policy_fingerprint,
            "records": record_payloads,
            "transitions": [
                _json_safe(item)
                for item in self.transitions(rollout_id)[:transition_limit]
            ],
        }

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

    # These private persistence operations are implemented once below on the
    # coordinator's shared internal helper surface.  Keeping the forwarding
    # methods here makes the ledger's own contract explicit and avoids
    # attaching methods to the class after module definition.
    def _require_enabled(self) -> None:
        return RepairRolloutCoordinator._ledger_require_enabled(self)

    def _authority_expired(self, record: RepairRolloutRecord) -> bool:
        return RepairRolloutCoordinator._ledger_authority_expired(self, record)

    def _persist_record(self, record: RepairRolloutRecord) -> None:
        return RepairRolloutCoordinator._ledger_persist_record(self, record)

    def _record_transition(
        self,
        record: RepairRolloutRecord,
        **kwargs: Any,
    ) -> RepairRolloutTransition:
        return RepairRolloutCoordinator._ledger_record_transition(self, record, **kwargs)

    def _restore(self) -> None:
        return RepairRolloutCoordinator._ledger_restore(self)


class RepairRolloutCoordinator:
    """Supervisor-owned context gate for application-wide rollout routing.

    Workers do ordinary invocation work. This coordinator only verifies that
    a worker has acknowledged the exact current rollout context before it may
    request a routing decision. It does not advance lifecycle stages or grant
    execution authority.
    """

    def __init__(
        self,
        ledger: RepairRolloutLedger,
        *,
        policy_fingerprint: str,
        authority_fingerprint: str,
        store: RepairRolloutStore | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not policy_fingerprint.strip() or not authority_fingerprint.strip():
            raise ValueError("rollout coordinator context fingerprints are required")
        self.ledger = ledger
        self.policy_fingerprint = policy_fingerprint
        self.authority_fingerprint = authority_fingerprint
        self.store = store if store is not None else ledger.store
        self._clock = clock or _utcnow
        self._acknowledgements: dict[UUID, RolloutWorkerAcknowledgement] = {}
        self._lock = threading.RLock()
        self._restore_acknowledgements()

    def acknowledge_worker(
        self,
        *,
        rollout_id: UUID,
        worker_id: str,
        worker_process_id: int,
        stage: RepairRolloutStage | str | None = None,
        acknowledgement_id: UUID | None = None,
    ) -> RolloutWorkerAcknowledgement:
        """Record a worker's acknowledgement of the current rollout state."""

        normalized_worker_id = str(worker_id).strip()
        if not normalized_worker_id or len(normalized_worker_id) > 256:
            raise ValueError("worker_id must contain 1..256 non-whitespace characters")
        if isinstance(worker_process_id, bool) or worker_process_id <= 0:
            raise ValueError("worker_process_id must be positive")
        record = self.ledger.get(rollout_id)
        if record.stage in {RepairRolloutStage.RETIRED, RepairRolloutStage.REVOKED}:
            raise RepairRolloutError(
                f"cannot acknowledge terminal rollout stage {record.stage.value}"
            )
        self._check_context(record)
        acknowledged_stage = (
            record.stage
            if stage is None
            else _coerce_rollout_enum(stage, RepairRolloutStage)
        )
        if acknowledged_stage is not record.stage:
            raise RepairRolloutError("worker acknowledgement stage is stale")
        now = self._clock()
        acknowledgement = RolloutWorkerAcknowledgement(
            acknowledgement_id=acknowledgement_id or uuid4(),
            rollout_id=record.rollout_id,
            target_id=record.target_id,
            candidate_id=record.candidate_id,
            worker_id=normalized_worker_id,
            worker_process_id=int(worker_process_id),
            stage=record.stage,
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
            acknowledged_at=now,
            content_hash="",
        )
        acknowledgement = replace(
            acknowledgement,
            content_hash=_digest(_worker_acknowledgement_payload(acknowledgement)),
        )
        if self.store is not None:
            recorder = getattr(self.store, "record_rollout_worker_acknowledgement", None)
            if not callable(recorder):
                raise RepairRolloutError(
                    "rollout store does not support worker acknowledgements"
                )
            recorder(acknowledgement)
        with self._lock:
            existing = self._acknowledgements.get(acknowledgement.acknowledgement_id)
            if existing is not None and existing != acknowledgement:
                raise RepairRolloutError(
                    "worker acknowledgement ID was already recorded with different evidence"
                )
            self._acknowledgements[acknowledgement.acknowledgement_id] = acknowledgement
        return acknowledgement

    def route(
        self,
        *,
        rollout_id: UUID,
        worker_id: str,
        worker_process_id: int,
        routing_scope: str,
        routing_key: str,
        audit_event: Callable[..., Any] | None = None,
    ) -> RolloutRoutingDecision:
        """Return a route only for a worker bound to the current context."""

        record = self.ledger.get(rollout_id)
        self._check_context(record)
        normalized_worker_id = str(worker_id).strip()
        if not normalized_worker_id:
            raise ValueError("worker_id is required")
        if self._current_acknowledgement(
            record,
            worker_id=normalized_worker_id,
            worker_process_id=worker_process_id,
        ) is None:
            raise PermissionError(
                "worker has not acknowledged the current rollout context"
            )
        return decide_rollout_routing(
            record,
            policy=self.ledger.policy,
            policy_fingerprint=self.policy_fingerprint,
            routing_scope=routing_scope,
            routing_key=routing_key,
            audit_event=audit_event,
        )

    def status(self, rollout_id: UUID | None = None) -> dict[str, Any]:
        """Return bounded worker-context status for supervisor/operator review."""

        records = self.ledger.all()
        if rollout_id is not None:
            records = tuple(item for item in records if item.rollout_id == rollout_id)
        output: list[dict[str, Any]] = []
        for record in records:
            acknowledgements = self._acknowledgements_for(record.rollout_id)
            current: list[RolloutWorkerAcknowledgement] = []
            stale = 0
            invalid = 0
            for acknowledgement in acknowledgements:
                if not _valid_worker_acknowledgement(acknowledgement):
                    invalid += 1
                    continue
                if self._ack_matches_record(acknowledgement, record):
                    current.append(acknowledgement)
                else:
                    stale += 1
            output.append({
                "rollout_id": str(record.rollout_id),
                "target_id": record.target_id,
                "candidate_id": str(record.candidate_id),
                "stage": record.stage.value,
                "acknowledgement_count": len(acknowledgements),
                "current_worker_count": len({item.worker_id for item in current}),
                "stale_acknowledgement_count": stale,
                "invalid_acknowledgement_count": invalid,
                "workers": [
                    {
                        "worker_id": item.worker_id,
                        "worker_process_id": item.worker_process_id,
                        "stage": item.stage.value,
                        "acknowledged_at": item.acknowledged_at.isoformat(),
                    }
                    for item in sorted(current, key=lambda item: item.acknowledged_at)
                ],
            })
        return {
            "read_only": True,
            "authority_granted": False,
            "policy_fingerprint": self.policy_fingerprint,
            "rollouts": output,
        }

    def _check_context(self, record: RepairRolloutRecord) -> None:
        if record.policy_fingerprint != self.policy_fingerprint:
            raise RepairRolloutError("rollout coordinator policy fingerprint is stale")
        if record.authority_fingerprint != self.authority_fingerprint:
            raise RepairRolloutError("rollout coordinator authority fingerprint is stale")

    def _acknowledgements_for(
        self, rollout_id: UUID
    ) -> tuple[RolloutWorkerAcknowledgement, ...]:
        values: dict[UUID, RolloutWorkerAcknowledgement] = {}
        if self.store is not None:
            reader = getattr(self.store, "all_rollout_worker_acknowledgements", None)
            if callable(reader):
                for raw in reader():
                    acknowledgement = _coerce_worker_acknowledgement(raw)
                    if acknowledgement is not None:
                        values[acknowledgement.acknowledgement_id] = acknowledgement
        with self._lock:
            values.update(self._acknowledgements)
        return tuple(
            item for item in values.values() if item.rollout_id == rollout_id
        )

    def _current_acknowledgement(
        self,
        record: RepairRolloutRecord,
        *,
        worker_id: str,
        worker_process_id: int,
    ) -> RolloutWorkerAcknowledgement | None:
        if isinstance(worker_process_id, bool) or worker_process_id <= 0:
            return None
        candidates = [
            item
            for item in self._acknowledgements_for(record.rollout_id)
            if item.worker_id == worker_id
            and item.worker_process_id == worker_process_id
            and _valid_worker_acknowledgement(item)
            and self._ack_matches_record(item, record)
        ]
        return max(candidates, key=lambda item: item.acknowledged_at, default=None)

    def _ack_matches_record(
        self,
        acknowledgement: RolloutWorkerAcknowledgement,
        record: RepairRolloutRecord,
    ) -> bool:
        return (
            acknowledgement.rollout_id == record.rollout_id
            and acknowledgement.target_id == record.target_id
            and acknowledgement.candidate_id == record.candidate_id
            and acknowledgement.stage is record.stage
            and acknowledgement.policy_fingerprint == self.policy_fingerprint
            and acknowledgement.authority_fingerprint == self.authority_fingerprint
        )

    def _restore_acknowledgements(self) -> None:
        if self.store is None:
            return
        reader = getattr(self.store, "all_rollout_worker_acknowledgements", None)
        if not callable(reader):
            return
        for raw in reader():
            acknowledgement = _coerce_worker_acknowledgement(raw)
            if acknowledgement is None or not _valid_worker_acknowledgement(acknowledgement):
                continue
            self._acknowledgements[acknowledgement.acknowledgement_id] = acknowledgement

    def _ledger_require_enabled(self) -> None:
        if not self.policy.enabled:
            raise RepairRolloutError("repair rollout is disabled by policy")

    def _ledger_authority_expired(self, record: RepairRolloutRecord) -> bool:
        return record.expires_at is not None and record.expires_at <= self._clock()

    def _ledger_persist_record(self, record: RepairRolloutRecord) -> None:
        if self.store is not None:
            self.store.record_rollout(record)

    def _ledger_record_transition(
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

    def _ledger_restore(self) -> None:
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
        "candidate_id": str(record.candidate_id),
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
        candidate_id=record.candidate_id,
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
    behavior_capture: Mapping[str, Any] | None = None,
    behavior_capture_complete: bool = False,
    isolation_adapter: ShadowExecutionAdapter | None = None,
    comparator: Comparator | None = None,
    audit_event: Callable[..., Any] | None = None,
    execution_store: RepairRolloutStore | None = None,
    execution_id: UUID | None = None,
) -> RolloutExecutionResult:
    """Invoke an already-authorized rollout path.

    This adapter consumes, but does not create, rollout authority.  A sampled
    shadow candidate is executed through the original-authoritative shadow
    primitive.  A canary or active candidate is invoked only when the routing
    decision explicitly makes it authoritative; all other calls use ``deployed``.
    The caller remains responsible for selecting functions that passed its
    normal Repair, Integrity, Guard, and authority checks.
    """

    effect_observation = _resolve_effect_observation(
        effect_observation,
        behavior_capture=behavior_capture,
        behavior_capture_complete=behavior_capture_complete,
    )

    decision = decide_rollout_routing(
        record,
        policy=policy,
        policy_fingerprint=policy_fingerprint,
        routing_scope=routing_scope,
        routing_key=routing_key,
        audit_event=audit_event,
    )
    return _execute_and_record(
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
        execution_store=execution_store,
        execution_id=execution_id,
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
    behavior_capture: Mapping[str, Any] | None = None,
    behavior_capture_complete: bool = False,
    isolation_adapter: ShadowExecutionAdapter | None = None,
    comparator: Comparator | None = None,
    audit_event: Callable[..., Any] | None = None,
    observation_manager: "ObservationManager | None" = None,
    observation_policy: "ObservationPolicy | None" = None,
    call_id: UUID | None = None,
    execution_store: RepairRolloutStore | None = None,
    execution_id: UUID | None = None,
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

    effect_observation = _resolve_effect_observation(
        effect_observation,
        behavior_capture=behavior_capture,
        behavior_capture_complete=behavior_capture_complete,
    )

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
        result = _execute_and_record(
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
            execution_store=execution_store,
            execution_id=execution_id,
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
                    audit_event=audit_event,
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
            audit_event=audit_event,
        )
    return result


def _resolve_effect_observation(
    effect_observation: EffectObservation | None,
    *,
    behavior_capture: Mapping[str, Any] | None,
    behavior_capture_complete: bool,
) -> EffectObservation | None:
    if effect_observation is not None and behavior_capture is not None:
        raise RepairRolloutExecutionError(
            "provide either effect observation or behavior capture, not both"
        )
    if behavior_capture is None:
        return effect_observation
    try:
        return EffectObservation.from_behavior_capture(
            behavior_capture,
            complete=behavior_capture_complete,
        )
    except (TypeError, ValueError) as exc:
        raise RepairRolloutExecutionError(
            f"invalid behavior capture for effect assessment: {exc}"
        ) from exc


def _execute_and_record(
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
    execution_store: RepairRolloutStore | None,
    execution_id: UUID | None,
) -> RolloutExecutionResult:
    try:
        result = _execute_rollout_decision(
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
    except BaseException as exc:
        observation = _build_execution_observation(
            decision,
            execution_id=execution_id,
            error=exc,
        )
        _persist_execution_observation(execution_store, observation)
        raise
    observation = _build_execution_observation(
        decision,
        execution_id=execution_id,
        result=result,
    )
    _persist_execution_observation(execution_store, observation)
    return replace(result, execution_observation=observation)


def _build_execution_observation(
    decision: RolloutRoutingDecision,
    *,
    execution_id: UUID | None,
    result: RolloutExecutionResult | None = None,
    error: BaseException | None = None,
) -> RolloutExecutionObservation:
    shadow = result.shadow_result if result is not None else None
    candidate_executed = (
        result.candidate_executed
        if result is not None
        else decision.strategy == "shadow" or decision.candidate_authoritative
    )
    candidate_succeeded = (
        shadow.candidate_succeeded
        if shadow is not None
        else (
            True
            if result is not None and decision.candidate_authoritative
            else False
            if error is not None and decision.candidate_authoritative
            else None
        )
    )
    original_succeeded = shadow.original_succeeded if shadow is not None else None
    equivalent = shadow.equivalent if shadow is not None else None
    execution_state = "COMPLETED" if result is not None else "FAILED"
    content = {
        "observation_id": str(execution_id or uuid4()),
        "rollout_id": str(decision.rollout_id),
        "target_id": decision.target_id,
        "candidate_id": str(decision.candidate_id),
        "stage": decision.stage.value,
        "strategy": decision.strategy,
        "authoritative_implementation": decision.authoritative_implementation.value,
        "candidate_executed": candidate_executed,
        "candidate_authoritative": decision.candidate_authoritative,
        "original_succeeded": original_succeeded,
        "candidate_succeeded": candidate_succeeded,
        "equivalent": equivalent,
        "execution_state": execution_state,
        "exception_type": type(error).__name__ if error is not None else None,
        "decision_hash": decision.decision_hash,
        "policy_fingerprint": decision.policy_fingerprint,
    }
    observation_id = execution_id or uuid4()
    content["observation_id"] = str(observation_id)
    return RolloutExecutionObservation(
        observation_id=observation_id,
        rollout_id=decision.rollout_id,
        target_id=decision.target_id,
        candidate_id=decision.candidate_id,
        stage=decision.stage,
        strategy=decision.strategy,
        authoritative_implementation=decision.authoritative_implementation,
        candidate_executed=bool(candidate_executed),
        candidate_authoritative=decision.candidate_authoritative,
        original_succeeded=original_succeeded,
        candidate_succeeded=candidate_succeeded,
        equivalent=equivalent,
        execution_state=execution_state,
        exception_type=type(error).__name__ if error is not None else None,
        decision_hash=decision.decision_hash,
        policy_fingerprint=decision.policy_fingerprint,
        created_at=_utcnow(),
        content_hash=_digest(content),
    )


def _persist_execution_observation(
    store: RepairRolloutStore | None,
    observation: RolloutExecutionObservation,
) -> None:
    if store is None:
        return
    recorder = getattr(store, "record_rollout_execution", None)
    if not callable(recorder):
        raise RepairRolloutExecutionError(
            "rollout execution store does not support execution observations"
        )
    recorder(observation)


def summarize_rollout_executions(
    record: RepairRolloutRecord,
    observations: Iterable[RolloutExecutionObservation | Mapping[str, Any]],
    *,
    policy_fingerprint: str,
) -> RolloutExecutionSummary:
    """Build an integrity-checked, read-only summary for staged review.

    Observations from another rollout, candidate, target, policy, or a
    tampered content hash are retained only in ``invalid_observation_count``.
    No observation can change the supplied rollout record.
    """

    stage_counts: Counter[str] = Counter()
    observation_count = 0
    completed_count = 0
    failed_count = 0
    candidate_execution_count = 0
    candidate_authoritative_count = 0
    candidate_success_count = 0
    candidate_failure_count = 0
    shadow_count = 0
    shadow_equivalent_count = 0
    shadow_mismatch_count = 0
    shadow_inconclusive_count = 0
    invalid_count = 0
    for raw in observations:
        observation = _coerce_execution_observation(raw)
        if observation is None or not _valid_execution_observation(observation):
            invalid_count += 1
            continue
        if (
            observation.rollout_id != record.rollout_id
            or observation.target_id != record.target_id
            or observation.candidate_id != record.candidate_id
            or observation.policy_fingerprint != policy_fingerprint
            or observation.policy_fingerprint != record.policy_fingerprint
            or observation.content_hash != _digest(_execution_observation_payload(observation))
        ):
            invalid_count += 1
            continue
        observation_count += 1
        stage_counts[observation.stage.value] += 1
        if observation.execution_state == "COMPLETED":
            completed_count += 1
        else:
            failed_count += 1
        if observation.candidate_executed:
            candidate_execution_count += 1
        if observation.candidate_authoritative:
            candidate_authoritative_count += 1
        if observation.candidate_succeeded is True:
            candidate_success_count += 1
        elif observation.candidate_succeeded is False:
            candidate_failure_count += 1
        if observation.strategy == "shadow":
            shadow_count += 1
            if observation.equivalent is True:
                shadow_equivalent_count += 1
            elif observation.equivalent is False:
                shadow_mismatch_count += 1
            else:
                shadow_inconclusive_count += 1
    summary_payload = {
        "rollout_id": str(record.rollout_id),
        "target_id": record.target_id,
        "candidate_id": str(record.candidate_id),
        "policy_fingerprint": policy_fingerprint,
        "observation_count": observation_count,
        "completed_count": completed_count,
        "failed_count": failed_count,
        "candidate_execution_count": candidate_execution_count,
        "candidate_authoritative_count": candidate_authoritative_count,
        "candidate_success_count": candidate_success_count,
        "candidate_failure_count": candidate_failure_count,
        "shadow_count": shadow_count,
        "shadow_equivalent_count": shadow_equivalent_count,
        "shadow_mismatch_count": shadow_mismatch_count,
        "shadow_inconclusive_count": shadow_inconclusive_count,
        "invalid_observation_count": invalid_count,
        "stage_counts": dict(sorted(stage_counts.items())),
    }
    return RolloutExecutionSummary(
        rollout_id=record.rollout_id,
        target_id=record.target_id,
        candidate_id=record.candidate_id,
        policy_fingerprint=policy_fingerprint,
        observation_count=observation_count,
        completed_count=completed_count,
        failed_count=failed_count,
        candidate_execution_count=candidate_execution_count,
        candidate_authoritative_count=candidate_authoritative_count,
        candidate_success_count=candidate_success_count,
        candidate_failure_count=candidate_failure_count,
        shadow_count=shadow_count,
        shadow_equivalent_count=shadow_equivalent_count,
        shadow_mismatch_count=shadow_mismatch_count,
        shadow_inconclusive_count=shadow_inconclusive_count,
        invalid_observation_count=invalid_count,
        stage_counts=dict(sorted(stage_counts.items())),
        evidence_hash=_digest(summary_payload),
    )


def _valid_execution_observation(observation: RolloutExecutionObservation) -> bool:
    return (
        observation.execution_state in {"COMPLETED", "FAILED"}
        and (observation.exception_type is None or observation.exception_type.strip() != "")
        and observation.strategy.strip() != ""
    )


def _coerce_execution_observation(
    raw: RolloutExecutionObservation | Mapping[str, Any],
) -> RolloutExecutionObservation | None:
    if isinstance(raw, RolloutExecutionObservation):
        return raw
    if not isinstance(raw, Mapping):
        return None
    try:
        return RolloutExecutionObservation(
            observation_id=UUID(str(raw["observation_id"])),
            rollout_id=UUID(str(raw["rollout_id"])),
            target_id=str(raw["target_id"]),
            candidate_id=UUID(str(raw["candidate_id"])),
            stage=_coerce_rollout_enum(raw["stage"], RepairRolloutStage),
            strategy=str(raw["strategy"]),
            authoritative_implementation=_coerce_rollout_enum(
                raw["authoritative_implementation"],
                RepairAuthoritativeImplementation,
            ),
            candidate_executed=bool(raw["candidate_executed"]),
            candidate_authoritative=bool(raw["candidate_authoritative"]),
            original_succeeded=_optional_bool(raw.get("original_succeeded")),
            candidate_succeeded=_optional_bool(raw.get("candidate_succeeded")),
            equivalent=_optional_bool(raw.get("equivalent")),
            execution_state=str(raw["execution_state"]),
            exception_type=(
                str(raw["exception_type"])
                if raw.get("exception_type") is not None
                else None
            ),
            decision_hash=str(raw["decision_hash"]),
            policy_fingerprint=str(raw["policy_fingerprint"]),
            created_at=datetime.fromisoformat(str(raw["created_at"])),
            content_hash=str(raw["content_hash"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _coerce_worker_acknowledgement(
    raw: Any,
) -> RolloutWorkerAcknowledgement | None:
    if isinstance(raw, RolloutWorkerAcknowledgement):
        return raw
    if not isinstance(raw, Mapping):
        return None
    try:
        return RolloutWorkerAcknowledgement(
            acknowledgement_id=UUID(str(raw["acknowledgement_id"])),
            rollout_id=UUID(str(raw["rollout_id"])),
            target_id=str(raw["target_id"]),
            candidate_id=UUID(str(raw["candidate_id"])),
            worker_id=str(raw["worker_id"]),
            worker_process_id=int(raw["worker_process_id"]),
            stage=_coerce_rollout_enum(raw["stage"], RepairRolloutStage),
            policy_fingerprint=str(raw["policy_fingerprint"]),
            authority_fingerprint=str(raw["authority_fingerprint"]),
            acknowledged_at=datetime.fromisoformat(str(raw["acknowledged_at"])),
            content_hash=str(raw["content_hash"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _valid_worker_acknowledgement(
    acknowledgement: RolloutWorkerAcknowledgement,
) -> bool:
    return (
        bool(acknowledgement.worker_id.strip())
        and len(acknowledgement.worker_id) <= 256
        and acknowledgement.worker_process_id > 0
        and bool(acknowledgement.policy_fingerprint.strip())
        and bool(acknowledgement.authority_fingerprint.strip())
        and acknowledgement.content_hash
        == _digest(_worker_acknowledgement_payload(acknowledgement))
    )


def _coerce_rollout_enum(value: Any, enum_type: type[Enum]) -> Any:
    text = str(value)
    try:
        return enum_type(text)
    except ValueError:
        return enum_type[text.upper()]


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ValueError("expected a boolean or null")


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
        if audit_event is not None:
            audit_event(
                "REPAIR_ROLLOUT_EXECUTION_OUTCOME",
                actor={"type": "caretaker", "id": "rollout-executor"},
                scope={
                    "target_id": decision.target_id,
                    "rollout_id": str(decision.rollout_id),
                    "routing_scope": decision.routing_scope,
                    "routing_key_digest": decision.routing_key_digest,
                },
                policy={"fingerprint": decision.policy_fingerprint},
                outcome={
                    "state": "COMPLETED" if shadow.original_succeeded else "FAILED",
                    "implementation": "deployed",
                    "candidate_executed": True,
                    "candidate_authoritative": False,
                },
                details={
                    "decision_hash": decision.decision_hash,
                    "original_succeeded": shadow.original_succeeded,
                    "candidate_succeeded": shadow.candidate_succeeded,
                },
            )
        return RolloutExecutionResult(
            result=shadow.result,
            decision=decision,
            candidate_executed=True,
            candidate_authoritative=False,
            shadow_result=shadow,
        )
    if decision.candidate_authoritative:
        return _invoke_rollout_implementation(
            decision,
            implementation=candidate,
            args=args,
            kwargs=kwargs,
            candidate_executed=True,
            audit_event=audit_event,
        )
    return _invoke_rollout_implementation(
        decision,
        implementation=deployed,
        args=args,
        kwargs=kwargs,
        candidate_executed=False,
        audit_event=audit_event,
    )


def _invoke_rollout_implementation(
    decision: RolloutRoutingDecision,
    *,
    implementation: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    candidate_executed: bool,
    audit_event: Callable[..., Any] | None,
) -> RolloutExecutionResult:
    candidate_authoritative = decision.candidate_authoritative
    try:
        result = implementation(*args, **kwargs)
    except BaseException as exc:
        if audit_event is not None:
            _emit_rollout_execution_outcome(
                decision,
                state="FAILED",
                candidate_executed=candidate_executed,
                exception=exc,
                audit_event=audit_event,
            )
        raise
    if audit_event is not None:
        _emit_rollout_execution_outcome(
            decision,
            state="COMPLETED",
            candidate_executed=candidate_executed,
            audit_event=audit_event,
        )
    return RolloutExecutionResult(
        result=result,
        decision=decision,
        candidate_executed=candidate_executed,
        candidate_authoritative=candidate_authoritative,
    )


def _emit_rollout_execution_outcome(
    decision: RolloutRoutingDecision,
    *,
    state: str,
    candidate_executed: bool,
    audit_event: Callable[..., Any],
    exception: BaseException | None = None,
) -> None:
    details: dict[str, Any] = {"decision_hash": decision.decision_hash}
    if exception is not None:
        details["exception_type"] = type(exception).__name__[:128]
    audit_event(
        "REPAIR_ROLLOUT_EXECUTION_OUTCOME",
        actor={"type": "caretaker", "id": "rollout-executor"},
        scope={
            "target_id": decision.target_id,
            "rollout_id": str(decision.rollout_id),
            "routing_scope": decision.routing_scope,
            "routing_key_digest": decision.routing_key_digest,
        },
        policy={"fingerprint": decision.policy_fingerprint},
        outcome={
            "state": state,
            "implementation": decision.authoritative_implementation.value,
            "candidate_executed": candidate_executed,
            "candidate_authoritative": decision.candidate_authoritative,
        },
        details=details,
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


def _json_safe(value: Any) -> Any:
    """Convert rollout dataclasses to stable JSON-compatible values."""

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (UUID, datetime)):
        return str(value)
    if dataclasses.is_dataclass(value):
        return _json_safe(dataclasses.asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


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
