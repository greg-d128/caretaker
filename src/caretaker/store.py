from __future__ import annotations

from .adaptive import lightweight_dependency
import dataclasses
import gzip
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import UUID

from .integrity.models import IntegrityIncident, IntegrityVerification

from .domain import (
    CandidateGeneration,
    Incident,
    InternalIncident,
    ObservationRecord,
    PolicySnapshot,
    RepairAttempt,
    RepairCandidate,
    RepairEpisode,
    RepairEvent,
)
from .repair_recovery import (
    ComparisonWorkerAssignment,
    ComparisonWorkerComparisonReport,
    ComparisonWorkerReconciliationReport,
    ComparisonWorkerResult,
    RepairRecoveryLifecycleMark,
    RepairRecoveryRecord,
    WorkerEvidenceJoinReport,
    WorkerFailureRecord,
    WorkerFailureRecoveryRecord,
    WorkerPostmortemConflictReport,
)
from .repair_rollout import (
    RepairRolloutRecord,
    RepairRolloutTransition,
    RolloutApplicationRouteAssignment,
    RolloutExecutionObservation,
    RolloutWorkerAcknowledgement,
)


REPAIR_STORE_SCHEMA_VERSION = 9
REPAIR_RETENTION_PLAN_SCHEMA_VERSION = 1
REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION = 1

_RETENTION_PROTECTED_TABLES = frozenset({
    "incidents",
    "internal_incidents",
    "integrity_verifications",
    "integrity_incidents",
    "events",
})


class RepairStore(Protocol):
    def record_policy(self, record: PolicySnapshot) -> None: ...
    def record_incident(self, record: Incident) -> None: ...
    def record_episode(self, record: RepairEpisode) -> None: ...
    def record_generation(self, record: CandidateGeneration) -> None: ...
    def record_candidate(self, record: RepairCandidate) -> None: ...
    def record_attempt(self, record: RepairAttempt) -> None: ...
    def append_event(self, record: RepairEvent) -> None: ...
    def record_observation(self, record: ObservationRecord) -> None: ...
    def all_observations(self) -> tuple[Any, ...]: ...
    def record_internal_incident(self, record: InternalIncident) -> None: ...
    def record_integrity_verification(self, record: IntegrityVerification) -> None: ...
    def record_integrity_incident(self, record: IntegrityIncident) -> None: ...
    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]: ...
    def attempts_for_target(self, target_id: str) -> tuple[Any, ...]: ...
    def all_attempts(self) -> tuple[Any, ...]: ...
    def all_policies(self) -> tuple[Any, ...]: ...
    def all_episodes(self) -> tuple[Any, ...]: ...
    def all_generations(self) -> tuple[Any, ...]: ...
    def all_candidates(self) -> tuple[Any, ...]: ...
    def record_rollout(self, record: RepairRolloutRecord) -> None: ...
    def all_rollouts(self) -> tuple[Any, ...]: ...
    def record_rollout_transition(self, record: RepairRolloutTransition) -> None: ...
    def commit_rollout_transition(
        self,
        record: RepairRolloutRecord,
        transition: RepairRolloutTransition,
        event: RepairEvent | None,
    ) -> None: ...
    def all_rollout_transitions(self) -> tuple[Any, ...]: ...
    def record_rollout_worker_acknowledgement(
        self, record: RolloutWorkerAcknowledgement
    ) -> None: ...
    def all_rollout_worker_acknowledgements(self) -> tuple[Any, ...]: ...
    def record_recovery(self, record: RepairRecoveryRecord) -> None: ...
    def all_recoveries(self) -> tuple[Any, ...]: ...
    def record_recovery_lifecycle_mark(self, record: RepairRecoveryLifecycleMark) -> None: ...
    def all_recovery_lifecycle_marks(self) -> tuple[Any, ...]: ...
    def record_worker_failure(self, record: WorkerFailureRecord) -> None: ...
    def all_worker_failures(self) -> tuple[Any, ...]: ...
    def record_worker_failure_recovery(self, record: WorkerFailureRecoveryRecord) -> None: ...
    def all_worker_failure_recoveries(self) -> tuple[Any, ...]: ...
    def record_worker_postmortem_conflict(self, record: WorkerPostmortemConflictReport) -> None: ...
    def all_worker_postmortem_conflicts(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_assignment(self, record: ComparisonWorkerAssignment) -> None: ...
    def all_comparison_worker_assignments(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_result(self, record: ComparisonWorkerResult) -> None: ...
    def all_comparison_worker_results(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_comparison(self, record: ComparisonWorkerComparisonReport) -> None: ...
    def all_comparison_worker_comparisons(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_reconciliation(
        self, record: ComparisonWorkerReconciliationReport
    ) -> None: ...
    def all_comparison_worker_reconciliations(self) -> tuple[Any, ...]: ...
    def record_worker_evidence_join(self, record: WorkerEvidenceJoinReport) -> None: ...
    def all_worker_evidence_joins(self) -> tuple[Any, ...]: ...


class RepairLifecycleStore(Protocol):
    """Capability required to persist and inspect repair lifecycle records."""

    def record_policy(self, record: PolicySnapshot) -> None: ...
    def record_incident(self, record: Incident) -> None: ...
    def record_episode(self, record: RepairEpisode) -> None: ...
    def record_generation(self, record: CandidateGeneration) -> None: ...
    def record_candidate(self, record: RepairCandidate) -> None: ...
    def record_attempt(self, record: RepairAttempt) -> None: ...
    def append_event(self, record: RepairEvent) -> None: ...
    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]: ...
    def attempts_for_target(self, target_id: str) -> tuple[Any, ...]: ...
    def all_attempts(self) -> tuple[Any, ...]: ...
    def all_policies(self) -> tuple[Any, ...]: ...
    def all_episodes(self) -> tuple[Any, ...]: ...
    def all_generations(self) -> tuple[Any, ...]: ...
    def all_candidates(self) -> tuple[Any, ...]: ...
    def record_rollout(self, record: RepairRolloutRecord) -> None: ...
    def all_rollouts(self) -> tuple[Any, ...]: ...
    def record_rollout_transition(self, record: RepairRolloutTransition) -> None: ...
    def commit_rollout_transition(
        self,
        record: RepairRolloutRecord,
        transition: RepairRolloutTransition,
        event: RepairEvent | None,
    ) -> None: ...
    def all_rollout_transitions(self) -> tuple[Any, ...]: ...


class RepairEvidenceStore(Protocol):
    """Capability required by components that write observation evidence."""

    def record_observation(self, record: ObservationRecord) -> None: ...
    def all_observations(self) -> tuple[Any, ...]: ...


class RepairWorkerRecoveryStore(Protocol):
    """Capability required by worker and repair-recovery consumers."""

    def attempts_for_target(self, target_id: str) -> tuple[Any, ...]: ...
    def all_attempts(self) -> tuple[Any, ...]: ...
    def all_observations(self) -> tuple[Any, ...]: ...
    def record_recovery(self, record: RepairRecoveryRecord) -> None: ...
    def all_recoveries(self) -> tuple[Any, ...]: ...
    def record_recovery_lifecycle_mark(self, record: RepairRecoveryLifecycleMark) -> None: ...
    def all_recovery_lifecycle_marks(self) -> tuple[Any, ...]: ...
    def record_worker_failure(self, record: WorkerFailureRecord) -> None: ...
    def all_worker_failures(self) -> tuple[Any, ...]: ...
    def record_worker_failure_recovery(self, record: WorkerFailureRecoveryRecord) -> None: ...
    def all_worker_failure_recoveries(self) -> tuple[Any, ...]: ...
    def record_worker_postmortem_conflict(self, record: WorkerPostmortemConflictReport) -> None: ...
    def all_worker_postmortem_conflicts(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_assignment(self, record: ComparisonWorkerAssignment) -> None: ...
    def all_comparison_worker_assignments(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_result(self, record: ComparisonWorkerResult) -> None: ...
    def all_comparison_worker_results(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_comparison(self, record: ComparisonWorkerComparisonReport) -> None: ...
    def all_comparison_worker_comparisons(self) -> tuple[Any, ...]: ...
    def record_comparison_worker_reconciliation(
        self, record: ComparisonWorkerReconciliationReport
    ) -> None: ...
    def all_comparison_worker_reconciliations(self) -> tuple[Any, ...]: ...
    def record_worker_evidence_join(self, record: WorkerEvidenceJoinReport) -> None: ...
    def all_worker_evidence_joins(self) -> tuple[Any, ...]: ...


class RepairIntegrityStore(Protocol):
    """Capability required to persist integrity verification records."""

    def record_integrity_verification(self, record: IntegrityVerification) -> None: ...
    def record_integrity_incident(self, record: IntegrityIncident) -> None: ...


class RepairPostmortemStore(Protocol):
    """Capability required to persist internal post-mortem evidence."""

    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]: ...
    def record_internal_incident(self, record: InternalIncident) -> None: ...


class _CapabilityStoreView:
    """Read/write capability projection over one physical store.

    The wrapped store is intentionally private. This is an ownership and
    dependency seam, not a second authorization boundary; callers should type
    against the corresponding capability protocol and cannot accidentally use
    unrelated record families through the view.
    """

    __slots__ = ("_store", "_allowed")

    def __init__(self, store: RepairStore, allowed: frozenset[str]) -> None:
        self._store = store
        self._allowed = allowed

    def __getattr__(self, name: str) -> Any:
        if name not in self._allowed:
            raise AttributeError(name)
        return getattr(self._store, name)


_LIFECYCLE_METHODS = frozenset({
    "record_policy", "record_incident", "record_episode", "record_generation",
    "record_candidate", "record_attempt", "append_event", "recent_events",
    "attempts_for_target", "all_attempts", "all_policies", "all_episodes",
    "all_generations", "all_candidates", "record_rollout", "all_rollouts",
    "record_rollout_transition", "commit_rollout_transition", "all_rollout_transitions",
})
_EVIDENCE_METHODS = frozenset({"record_observation", "all_observations"})
_WORKER_RECOVERY_METHODS = frozenset({
    "attempts_for_target", "all_attempts", "all_observations", "record_recovery",
    "all_recoveries", "record_recovery_lifecycle_mark", "all_recovery_lifecycle_marks",
    "record_worker_failure", "all_worker_failures", "record_worker_failure_recovery",
    "all_worker_failure_recoveries", "record_worker_postmortem_conflict",
    "all_worker_postmortem_conflicts", "record_comparison_worker_assignment",
    "all_comparison_worker_assignments", "record_comparison_worker_result",
    "all_comparison_worker_results", "record_comparison_worker_comparison",
    "all_comparison_worker_comparisons", "record_comparison_worker_reconciliation",
    "all_comparison_worker_reconciliations", "record_worker_evidence_join",
    "all_worker_evidence_joins",
})
_INTEGRITY_METHODS = frozenset({"record_integrity_verification", "record_integrity_incident"})
_POSTMORTEM_METHODS = frozenset({"recent_events", "record_internal_incident"})


def lifecycle_store_view(store: RepairStore) -> RepairLifecycleStore:
    """Return the lifecycle capability over an existing physical store."""

    return _CapabilityStoreView(store, _LIFECYCLE_METHODS)  # type: ignore[return-value]


def evidence_store_view(store: RepairStore) -> RepairEvidenceStore:
    """Return the observation-evidence capability over an existing store."""

    return _CapabilityStoreView(store, _EVIDENCE_METHODS)  # type: ignore[return-value]


def worker_recovery_store_view(store: RepairStore) -> RepairWorkerRecoveryStore:
    """Return the worker/recovery capability over an existing store."""

    return _CapabilityStoreView(store, _WORKER_RECOVERY_METHODS)  # type: ignore[return-value]


def integrity_store_view(store: RepairStore) -> RepairIntegrityStore:
    """Return the integrity-record capability over an existing store."""

    return _CapabilityStoreView(store, _INTEGRITY_METHODS)  # type: ignore[return-value]


def postmortem_store_view(store: RepairStore) -> RepairPostmortemStore:
    """Return the internal post-mortem capability over an existing store."""

    return _CapabilityStoreView(store, _POSTMORTEM_METHODS)  # type: ignore[return-value]


class InMemoryRepairStore:
    def __init__(self, event_limit: int = 10_000) -> None:
        self.policies: dict[UUID, PolicySnapshot] = {}
        self.incidents: dict[UUID, Incident] = {}
        self.episodes: dict[UUID, RepairEpisode] = {}
        self.generations: dict[UUID, CandidateGeneration] = {}
        self.candidates: dict[UUID, RepairCandidate] = {}
        self.attempts: dict[UUID, RepairAttempt] = {}
        self.recoveries: dict[str, RepairRecoveryRecord] = {}
        self.recovery_lifecycle_marks: dict[UUID, RepairRecoveryLifecycleMark] = {}
        self.worker_failures: dict[UUID, WorkerFailureRecord] = {}
        self.worker_failure_recoveries: dict[UUID, WorkerFailureRecoveryRecord] = {}
        self.worker_postmortem_conflicts: dict[UUID, WorkerPostmortemConflictReport] = {}
        self.comparison_worker_assignments: dict[UUID, ComparisonWorkerAssignment] = {}
        self.comparison_worker_results: dict[UUID, ComparisonWorkerResult] = {}
        self.comparison_worker_comparisons: dict[UUID, ComparisonWorkerComparisonReport] = {}
        self.comparison_worker_reconciliations: dict[UUID, ComparisonWorkerReconciliationReport] = {}
        self.worker_evidence_joins: dict[UUID, WorkerEvidenceJoinReport] = {}
        self.rollouts: dict[UUID, RepairRolloutRecord] = {}
        self.rollout_transitions: dict[UUID, RepairRolloutTransition] = {}
        self.rollout_executions: dict[UUID, RolloutExecutionObservation] = {}
        self.rollout_worker_acknowledgements: dict[UUID, RolloutWorkerAcknowledgement] = {}
        self.rollout_application_routes: dict[UUID, RolloutApplicationRouteAssignment] = {}
        self.observations: dict[UUID, ObservationRecord] = {}
        self.internal_incidents: dict[UUID, InternalIncident] = {}
        self.integrity_verifications: dict[UUID, IntegrityVerification] = {}
        self.integrity_incidents: dict[UUID, IntegrityIncident] = {}
        self.events: deque[RepairEvent] = deque(maxlen=event_limit)
        self._lock = RLock()

    def record_policy(self, record: PolicySnapshot) -> None:
        with self._lock:
            self.policies[record.policy_snapshot_id] = record

    def record_incident(self, record: Incident) -> None:
        with self._lock:
            self.incidents[record.incident_id] = record

    def record_episode(self, record: RepairEpisode) -> None:
        with self._lock:
            self.episodes[record.episode_id] = record

    def record_generation(self, record: CandidateGeneration) -> None:
        with self._lock:
            self.generations[record.generation_id] = record

    def record_candidate(self, record: RepairCandidate) -> None:
        with self._lock:
            self.candidates[record.candidate_id] = record

    def record_attempt(self, record: RepairAttempt) -> None:
        with self._lock:
            self.attempts[record.attempt_id] = record

    def append_event(self, record: RepairEvent) -> None:
        with self._lock:
            self.events.append(record)

    def record_observation(self, record: ObservationRecord) -> None:
        with self._lock:
            existing = self.observations.get(record.observation_id)
            if existing is not None:
                if existing != record:
                    raise ValueError(
                        "observation_id was already recorded with different evidence"
                    )
                return
            self.observations[record.observation_id] = record

    def all_observations(self) -> tuple[ObservationRecord, ...]:
        with self._lock:
            return tuple(sorted(self.observations.values(), key=lambda record: record.occurred_at))

    def record_internal_incident(self, record: InternalIncident) -> None:
        with self._lock:
            self.internal_incidents[record.internal_incident_id] = record

    def record_integrity_verification(self, record: IntegrityVerification) -> None:
        with self._lock:
            self.integrity_verifications[record.verification_id] = record

    def record_integrity_incident(self, record: IntegrityIncident) -> None:
        with self._lock:
            self.integrity_incidents[record.incident_id] = record

    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]:
        with self._lock:
            events = [
                event for event in self.events
                if target_id is None or event.target_id == target_id
            ]
            return tuple(events[-limit:])

    def attempts_for_target(self, target_id: str) -> tuple[RepairAttempt, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (attempt for attempt in self.attempts.values() if attempt.target_id == target_id),
                    key=lambda attempt: attempt.created_at,
                )
            )

    def all_attempts(self) -> tuple[RepairAttempt, ...]:
        with self._lock:
            return tuple(sorted(self.attempts.values(), key=lambda attempt: attempt.created_at))

    def all_policies(self) -> tuple[PolicySnapshot, ...]:
        with self._lock:
            return tuple(sorted(self.policies.values(), key=lambda policy: policy.created_at))

    def all_episodes(self) -> tuple[RepairEpisode, ...]:
        with self._lock:
            return tuple(sorted(self.episodes.values(), key=lambda episode: episode.created_at))

    def all_generations(self) -> tuple[CandidateGeneration, ...]:
        with self._lock:
            return tuple(sorted(self.generations.values(), key=lambda generation: generation.started_at))

    def all_candidates(self) -> tuple[RepairCandidate, ...]:
        with self._lock:
            return tuple(sorted(self.candidates.values(), key=lambda candidate: candidate.created_at))

    def record_rollout(self, record: RepairRolloutRecord) -> None:
        with self._lock:
            self.rollouts[record.rollout_id] = record

    def all_rollouts(self) -> tuple[RepairRolloutRecord, ...]:
        with self._lock:
            return tuple(sorted(self.rollouts.values(), key=lambda record: record.created_at))

    def record_rollout_transition(self, record: RepairRolloutTransition) -> None:
        with self._lock:
            existing = self.rollout_transitions.get(record.transition_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "rollout transition ID was already recorded with different evidence"
                )
            self.rollout_transitions[record.transition_id] = record

    def commit_rollout_transition(
        self,
        record: RepairRolloutRecord,
        transition: RepairRolloutTransition,
        event: RepairEvent | None,
    ) -> None:
        """Atomically persist one rollout milestone in the in-memory seam.

        The transition ID is the idempotency key. Validate every existing
        record before mutating any collection so a conflicting retry cannot
        leave a partially updated lifecycle.
        """
        with self._lock:
            existing_transition = self.rollout_transitions.get(transition.transition_id)
            if existing_transition is not None and existing_transition != transition:
                raise ValueError(
                    "rollout transition ID was already recorded with different evidence"
                )
            if event is not None:
                existing_event = next(
                    (item for item in self.events if item.event_id == event.event_id),
                    None,
                )
                if existing_event is not None and existing_event != event:
                    raise ValueError("rollout milestone event ID was already recorded with different evidence")
            self.rollouts[record.rollout_id] = record
            self.rollout_transitions[transition.transition_id] = transition
            if event is not None and existing_transition is None:
                self.events.append(event)

    def all_rollout_transitions(self) -> tuple[RepairRolloutTransition, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.rollout_transitions.values(),
                    key=lambda record: record.created_at,
                )
            )

    def record_rollout_execution(self, record: RolloutExecutionObservation) -> None:
        with self._lock:
            existing = self.rollout_executions.get(record.observation_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "rollout execution observation ID was already recorded with different evidence"
                )
            self.rollout_executions[record.observation_id] = record

    def all_rollout_executions(self) -> tuple[RolloutExecutionObservation, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.rollout_executions.values(),
                    key=lambda record: record.created_at,
                )
            )

    def record_rollout_worker_acknowledgement(
        self, record: RolloutWorkerAcknowledgement
    ) -> None:
        with self._lock:
            existing = self.rollout_worker_acknowledgements.get(record.acknowledgement_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "worker acknowledgement ID was already recorded with different evidence"
                )
            self.rollout_worker_acknowledgements[record.acknowledgement_id] = record

    def all_rollout_worker_acknowledgements(
        self,
    ) -> tuple[RolloutWorkerAcknowledgement, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.rollout_worker_acknowledgements.values(),
                    key=lambda record: record.acknowledged_at,
                )
            )

    def record_rollout_application_route(
        self, record: RolloutApplicationRouteAssignment
    ) -> None:
        with self._lock:
            existing = self.rollout_application_routes.get(record.assignment_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "application route assignment ID was already recorded with different evidence"
                )
            self.rollout_application_routes[record.assignment_id] = record

    def all_rollout_application_routes(
        self,
    ) -> tuple[RolloutApplicationRouteAssignment, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.rollout_application_routes.values(),
                    key=lambda record: record.sequence,
                )
            )

    def record_recovery(self, record: RepairRecoveryRecord) -> None:
        with self._lock:
            self.recoveries.setdefault(record.attempt_id, record)

    def all_recoveries(self) -> tuple[RepairRecoveryRecord, ...]:
        with self._lock:
            return tuple(sorted(self.recoveries.values(), key=lambda record: record.observed_at))

    def record_recovery_lifecycle_mark(self, record: RepairRecoveryLifecycleMark) -> None:
        with self._lock:
            existing = self.recovery_lifecycle_marks.get(record.marker_id)
            if existing is not None:
                if (
                    existing.attempt_id != record.attempt_id
                    or existing.record_type != record.record_type
                    or existing.record_id != record.record_id
                    or existing.state != record.state
                    or existing.last_milestone != record.last_milestone
                    or existing.reason != record.reason
                    or existing.source_sha256 != record.source_sha256
                ):
                    raise ValueError(
                        "recovery lifecycle marker was already recorded with different evidence"
                    )
                return
            self.recovery_lifecycle_marks[record.marker_id] = record

    def all_recovery_lifecycle_marks(
        self,
    ) -> tuple[RepairRecoveryLifecycleMark, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.recovery_lifecycle_marks.values(),
                    key=lambda record: record.observed_at,
                )
            )

    def record_worker_failure(self, record: WorkerFailureRecord) -> None:
        with self._lock:
            self.worker_failures[record.failure_id] = record

    def all_worker_failures(self) -> tuple[WorkerFailureRecord, ...]:
        with self._lock:
            return tuple(sorted(self.worker_failures.values(), key=lambda record: record.observed_at))

    def record_worker_failure_recovery(self, record: WorkerFailureRecoveryRecord) -> None:
        with self._lock:
            self.worker_failure_recoveries[record.recovery_id] = record

    def all_worker_failure_recoveries(self) -> tuple[WorkerFailureRecoveryRecord, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.worker_failure_recoveries.values(),
                    key=lambda record: record.observed_at,
                )
            )

    def record_worker_postmortem_conflict(self, record: WorkerPostmortemConflictReport) -> None:
        with self._lock:
            self.worker_postmortem_conflicts[record.report_id] = record

    def all_worker_postmortem_conflicts(self) -> tuple[WorkerPostmortemConflictReport, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.worker_postmortem_conflicts.values(),
                    key=lambda record: record.observed_at,
                )
            )

    def record_comparison_worker_assignment(
        self, record: ComparisonWorkerAssignment
    ) -> None:
        with self._lock:
            existing = self.comparison_worker_assignments.get(record.assignment_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "comparison assignment ID was already recorded with different evidence"
                )
            self.comparison_worker_assignments[record.assignment_id] = record

    def all_comparison_worker_assignments(
        self,
    ) -> tuple[ComparisonWorkerAssignment, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.comparison_worker_assignments.values(),
                    key=lambda record: record.issued_at,
                )
            )

    def record_comparison_worker_result(self, record: ComparisonWorkerResult) -> None:
        with self._lock:
            existing = self.comparison_worker_results.get(record.result_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "comparison result ID was already recorded with different evidence"
                )
            self.comparison_worker_results[record.result_id] = record

    def all_comparison_worker_results(self) -> tuple[ComparisonWorkerResult, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.comparison_worker_results.values(),
                    key=lambda record: record.observed_at,
                )
            )

    def record_comparison_worker_comparison(
        self, record: ComparisonWorkerComparisonReport
    ) -> None:
        with self._lock:
            existing = self.comparison_worker_comparisons.get(record.comparison_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "comparison report ID was already recorded with different evidence"
                )
            self.comparison_worker_comparisons[record.comparison_id] = record

    def all_comparison_worker_comparisons(
        self,
    ) -> tuple[ComparisonWorkerComparisonReport, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.comparison_worker_comparisons.values(),
                    key=lambda record: record.compared_at,
                )
            )

    def record_comparison_worker_reconciliation(
        self, record: ComparisonWorkerReconciliationReport
    ) -> None:
        with self._lock:
            existing = self.comparison_worker_reconciliations.get(record.reconciliation_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "comparison reconciliation ID was already recorded with different evidence"
                )
            self.comparison_worker_reconciliations[record.reconciliation_id] = record

    def all_comparison_worker_reconciliations(
        self,
    ) -> tuple[ComparisonWorkerReconciliationReport, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.comparison_worker_reconciliations.values(),
                    key=lambda record: record.reconciled_at,
                )
            )

    def record_worker_evidence_join(self, record: WorkerEvidenceJoinReport) -> None:
        with self._lock:
            existing = self.worker_evidence_joins.get(record.join_id)
            if existing is not None and existing != record:
                raise ValueError(
                    "worker evidence join ID was already recorded with different evidence"
                )
            self.worker_evidence_joins[record.join_id] = record

    def all_worker_evidence_joins(self) -> tuple[WorkerEvidenceJoinReport, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self.worker_evidence_joins.values(),
                    key=lambda record: record.joined_at,
                )
            )


class SQLiteRepairStore:
    """Small JSON-backed event store with one logical stream per table."""

    _TABLES = {
        "policy_snapshots": "policy_snapshot_id",
        "incidents": "incident_id",
        "episodes": "episode_id",
        "generations": "generation_id",
        "candidates": "candidate_id",
        "repair_rollouts": "rollout_id",
        "repair_rollout_transitions": "transition_id",
        "repair_rollout_executions": "observation_id",
        "repair_rollout_worker_acknowledgements": "acknowledgement_id",
        "repair_rollout_application_routes": "assignment_id",
        "attempts": "attempt_id",
        "recovery_records": "recovery_id",
        "recovery_lifecycle_marks": "marker_id",
        "worker_failure_records": "failure_id",
        "worker_failure_recoveries": "recovery_id",
        "worker_postmortem_conflicts": "report_id",
        "comparison_worker_assignments": "assignment_id",
        "comparison_worker_results": "result_id",
        "comparison_worker_comparisons": "comparison_id",
        "comparison_worker_reconciliations": "reconciliation_id",
        "worker_evidence_joins": "join_id",
        "events": "event_id",
        "observations": "observation_id",
        "internal_incidents": "internal_incident_id",
        "integrity_verifications": "verification_id",
        "integrity_incidents": "incident_id",
    }

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    @lightweight_dependency(target_id="caretaker.dependency.sqlite.repair-store")
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS caretaker_store_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO caretaker_store_metadata(key, value) "
                "VALUES ('schema_version', ?)",
                (str(REPAIR_STORE_SCHEMA_VERSION),),
            )
            row = connection.execute(
                "SELECT value FROM caretaker_store_metadata WHERE key='schema_version'"
            ).fetchone()
            try:
                stored_version = int(row[0]) if row is not None else 0
            except (TypeError, ValueError) as exc:
                raise ValueError("Caretaker repair store schema version is invalid") from exc
            if stored_version != REPAIR_STORE_SCHEMA_VERSION:
                raise ValueError(
                    "Unsupported Caretaker repair store schema version "
                    f"{stored_version}; expected {REPAIR_STORE_SCHEMA_VERSION}"
                )
            for table in self._TABLES:
                connection.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {table} (
                        record_id TEXT PRIMARY KEY,
                        target_id TEXT,
                        created_at TEXT NOT NULL,
                        payload TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    f"CREATE INDEX IF NOT EXISTS {table}_target_idx ON {table}(target_id, created_at)"
                )
            connection.commit()

    def _write(self, table: str, record: object, *, target_id: str | None, append: bool = False) -> None:
        id_field = self._TABLES[table]
        record_id = str(getattr(record, id_field))
        created_at = _record_time(record).isoformat()
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        statement = "INSERT" if append else "INSERT OR REPLACE"
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                f"{statement} INTO {table}(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (record_id, target_id, created_at, payload),
            )
            connection.commit()

    def record_policy(self, record: PolicySnapshot) -> None:
        self._write("policy_snapshots", record, target_id=None)

    def record_incident(self, record: Incident) -> None:
        self._write("incidents", record, target_id=record.target.target_id)

    def record_episode(self, record: RepairEpisode) -> None:
        self._write("episodes", record, target_id=record.target_id)

    def record_generation(self, record: CandidateGeneration) -> None:
        self._write("generations", record, target_id=record.target_id)

    def record_candidate(self, record: RepairCandidate) -> None:
        self._write("candidates", record, target_id=record.target_id)

    def record_attempt(self, record: RepairAttempt) -> None:
        self._write("attempts", record, target_id=record.target_id)

    def append_event(self, record: RepairEvent) -> None:
        self._write("events", record, target_id=record.target_id, append=True)

    def record_observation(self, record: ObservationRecord) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                "SELECT payload FROM observations WHERE record_id = ?",
                (str(record.observation_id),),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload:
                    raise ValueError(
                        "observation_id was already recorded with different evidence"
                    )
                return
            connection.execute(
                "INSERT INTO observations(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    str(record.observation_id),
                    record.target_id,
                    record.occurred_at.isoformat(),
                    payload,
                ),
            )
            connection.commit()

    def all_observations(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("observations", limit=10000))

    def record_internal_incident(self, record: InternalIncident) -> None:
        self._write("internal_incidents", record, target_id=record.active_target_id)

    def record_integrity_verification(self, record: IntegrityVerification) -> None:
        self._write("integrity_verifications", record, target_id=None)

    def record_integrity_incident(self, record: IntegrityIncident) -> None:
        self._write("integrity_incidents", record, target_id=None)

    def recent_events(self, target_id: str | None, limit: int = 50) -> tuple[RepairEvent, ...]:
        rows = self.query_records("events", target_id=target_id, limit=limit)
        events: list[RepairEvent] = []
        for payload in rows:
            events.append(
                RepairEvent(
                    event_id=UUID(payload["event_id"]),
                    timestamp=datetime.fromisoformat(payload["timestamp"]),
                    event_type=payload["event_type"],
                    target_id=payload["target_id"],
                    incident_id=UUID(payload["incident_id"]) if payload.get("incident_id") else None,
                    episode_id=UUID(payload["episode_id"]) if payload.get("episode_id") else None,
                    attempt_id=UUID(payload["attempt_id"]) if payload.get("attempt_id") else None,
                    candidate_id=UUID(payload["candidate_id"]) if payload.get("candidate_id") else None,
                    details=payload.get("details", {}),
                )
            )
        return tuple(events)

    def attempts_for_target(self, target_id: str) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("attempts", target_id=target_id, limit=10000))

    def all_attempts(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("attempts", limit=10000))

    def all_policies(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("policy_snapshots", limit=10000))

    def all_episodes(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("episodes", limit=10000))

    def all_generations(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("generations", limit=10000))

    def all_candidates(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("candidates", limit=10000))

    def record_rollout(self, record: RepairRolloutRecord) -> None:
        self._write("repair_rollouts", record, target_id=record.target_id)

    def all_rollouts(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("repair_rollouts", limit=10000))

    def record_rollout_transition(self, record: RepairRolloutTransition) -> None:
        self._write(
            "repair_rollout_transitions",
            record,
            target_id=record.target_id,
            append=True,
        )

    def commit_rollout_transition(
        self,
        record: RepairRolloutRecord,
        transition: RepairRolloutTransition,
        event: RepairEvent | None,
    ) -> None:
        """Commit aggregate, transition, and local event in one SQLite transaction.

        ``transition_id`` is the idempotency key and the store metadata schema
        version is included in the milestone event details by the coordinator.
        Existing matching records make retries no-ops; conflicting evidence
        fails before any write is committed.
        """
        rollout_payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        transition_payload = json.dumps(
            _jsonable(transition), sort_keys=True, separators=(",", ":")
        )
        event_payload = (
            json.dumps(_jsonable(event), sort_keys=True, separators=(",", ":"))
            if event is not None
            else None
        )
        with self._lock, closing(self._connect()) as connection:
            existing_rollout = connection.execute(
                "SELECT payload FROM repair_rollouts WHERE record_id = ?",
                (str(record.rollout_id),),
            ).fetchone()
            existing_transition = connection.execute(
                "SELECT payload FROM repair_rollout_transitions WHERE record_id = ?",
                (str(transition.transition_id),),
            ).fetchone()
            if existing_transition is not None:
                if existing_transition[0] != transition_payload:
                    raise ValueError(
                        "rollout transition ID was already recorded with different evidence"
                    )
                # A matching transition means this idempotency key completed.
                connection.commit()
                return
            if event is not None:
                existing_event = connection.execute(
                    "SELECT payload FROM events WHERE record_id = ?",
                    (str(event.event_id),),
                ).fetchone()
                if existing_event is not None and existing_event[0] != event_payload:
                    raise ValueError(
                        "rollout milestone event ID was already recorded with different evidence"
                    )
            if existing_rollout is None:
                connection.execute(
                    "INSERT INTO repair_rollouts(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                    (
                        str(record.rollout_id),
                        record.target_id,
                        _record_time(record).isoformat(),
                        rollout_payload,
                    ),
                )
            else:
                connection.execute(
                    "UPDATE repair_rollouts SET target_id = ?, created_at = ?, payload = ? WHERE record_id = ?",
                    (record.target_id, _record_time(record).isoformat(), rollout_payload, str(record.rollout_id)),
                )
            connection.execute(
                "INSERT INTO repair_rollout_transitions(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    str(transition.transition_id),
                    transition.target_id,
                    _record_time(transition).isoformat(),
                    transition_payload,
                ),
            )
            if event is not None and existing_event is None:
                connection.execute(
                    "INSERT INTO events(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                    (
                        str(event.event_id),
                        event.target_id,
                        _record_time(event).isoformat(),
                        event_payload,
                    ),
                )
            connection.commit()

    def all_rollout_transitions(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("repair_rollout_transitions", limit=10000))

    def record_rollout_execution(self, record: RolloutExecutionObservation) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                "SELECT payload FROM repair_rollout_executions WHERE record_id = ?",
                (str(record.observation_id),),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload:
                    raise ValueError(
                        "rollout execution observation ID was already recorded with different evidence"
                    )
                return
            connection.execute(
                "INSERT INTO repair_rollout_executions(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    str(record.observation_id),
                    record.target_id,
                    record.created_at.isoformat(),
                    payload,
                ),
            )
            connection.commit()

    def all_rollout_executions(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("repair_rollout_executions", limit=10000))

    def record_rollout_worker_acknowledgement(
        self, record: RolloutWorkerAcknowledgement
    ) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                "SELECT payload FROM repair_rollout_worker_acknowledgements WHERE record_id = ?",
                (str(record.acknowledgement_id),),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload:
                    raise ValueError(
                        "worker acknowledgement ID was already recorded with different evidence"
                    )
                return
            connection.execute(
                "INSERT INTO repair_rollout_worker_acknowledgements(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    str(record.acknowledgement_id),
                    record.target_id,
                    record.acknowledged_at.isoformat(),
                    payload,
                ),
            )
            connection.commit()

    def all_rollout_worker_acknowledgements(
        self,
    ) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            self.query_records("repair_rollout_worker_acknowledgements", limit=10000)
        )

    def record_rollout_application_route(
        self, record: RolloutApplicationRouteAssignment
    ) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                "SELECT payload FROM repair_rollout_application_routes WHERE record_id = ?",
                (str(record.assignment_id),),
            ).fetchone()
            if existing is not None:
                if existing[0] != payload:
                    raise ValueError(
                        "application route assignment ID was already recorded with different evidence"
                    )
                return
            connection.execute(
                "INSERT INTO repair_rollout_application_routes(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    str(record.assignment_id),
                    record.target_id,
                    record.created_at.isoformat(),
                    payload,
                ),
            )
            connection.commit()

    def all_rollout_application_routes(
        self,
    ) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            self.query_records("repair_rollout_application_routes", limit=10000)
        )

    def record_recovery(self, record: RepairRecoveryRecord) -> None:
        self._write("recovery_records", record, target_id=record.target_id)

    def all_recoveries(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("recovery_records", limit=10000))

    def record_recovery_lifecycle_mark(self, record: RepairRecoveryLifecycleMark) -> None:
        payload = json.dumps(_jsonable(record), sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            existing = connection.execute(
                "SELECT payload FROM recovery_lifecycle_marks WHERE record_id = ?",
                (str(record.marker_id),),
            ).fetchone()
            if existing is not None:
                current = json.loads(existing[0])
                stable_fields = (
                    "attempt_id",
                    "record_type",
                    "record_id",
                    "state",
                    "last_milestone",
                    "reason",
                    "source_sha256",
                    "schema_version",
                )
                if any(current.get(field) != json.loads(payload).get(field) for field in stable_fields):
                    raise ValueError(
                        "recovery lifecycle marker was already recorded with different evidence"
                    )
                return
            connection.execute(
                "INSERT INTO recovery_lifecycle_marks(record_id, target_id, created_at, payload) VALUES (?, ?, ?, ?)",
                (
                    str(record.marker_id),
                    None,
                    record.observed_at.isoformat(),
                    payload,
                ),
            )
            connection.commit()

    def all_recovery_lifecycle_marks(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("recovery_lifecycle_marks", limit=10000))

    def record_worker_failure(self, record: WorkerFailureRecord) -> None:
        self._write("worker_failure_records", record, target_id=None)

    def all_worker_failures(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("worker_failure_records", limit=10000))

    def record_worker_failure_recovery(self, record: WorkerFailureRecoveryRecord) -> None:
        self._write("worker_failure_recoveries", record, target_id=record.scope)

    def all_worker_failure_recoveries(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("worker_failure_recoveries", limit=10000))

    def record_worker_postmortem_conflict(self, record: WorkerPostmortemConflictReport) -> None:
        self._write("worker_postmortem_conflicts", record, target_id=record.scope)

    def all_worker_postmortem_conflicts(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("worker_postmortem_conflicts", limit=10000))

    def record_comparison_worker_assignment(
        self, record: ComparisonWorkerAssignment
    ) -> None:
        self._write(
            "comparison_worker_assignments",
            record,
            target_id=record.target_id,
        )

    def all_comparison_worker_assignments(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            self.query_records("comparison_worker_assignments", limit=10000)
        )

    def record_comparison_worker_result(self, record: ComparisonWorkerResult) -> None:
        self._write(
            "comparison_worker_results",
            record,
            target_id=None,
        )

    def all_comparison_worker_results(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("comparison_worker_results", limit=10000))

    def record_comparison_worker_comparison(
        self, record: ComparisonWorkerComparisonReport
    ) -> None:
        self._write(
            "comparison_worker_comparisons",
            record,
            target_id=record.scope,
        )

    def all_comparison_worker_comparisons(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            self.query_records("comparison_worker_comparisons", limit=10000)
        )

    def record_comparison_worker_reconciliation(
        self, record: ComparisonWorkerReconciliationReport
    ) -> None:
        self._write(
            "comparison_worker_reconciliations",
            record,
            target_id=record.scope,
        )

    def all_comparison_worker_reconciliations(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            self.query_records("comparison_worker_reconciliations", limit=10000)
        )

    def record_worker_evidence_join(self, record: WorkerEvidenceJoinReport) -> None:
        self._write("worker_evidence_joins", record, target_id=record.scope)

    def all_worker_evidence_joins(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.query_records("worker_evidence_joins", limit=10000))

    def retention_dry_run(
        self,
        *,
        older_than: datetime,
        families: Sequence[str] | None = None,
        maximum_records: int = 1000,
    ) -> Mapping[str, Any]:
        """Return bounded retention candidates without changing the store.

        Incident-linked, signed, and audit families are returned as explicit
        preservation exceptions. This method is intentionally a planner only;
        callers must apply any archive or deletion policy through a separate,
        family-owned operation.
        """

        if older_than.tzinfo is None or older_than.utcoffset() is None:
            raise ValueError("older_than must be timezone-aware")
        if (
            isinstance(maximum_records, bool)
            or not isinstance(maximum_records, int)
            or maximum_records <= 0
        ):
            raise ValueError("maximum_records must be a positive integer")
        selected = tuple(families) if families is not None else tuple(self._TABLES)
        unknown = [table for table in selected if table not in self._TABLES]
        if unknown:
            raise ValueError(f"Unknown Caretaker store table: {unknown[0]}")

        candidates: list[dict[str, Any]] = []
        preserved: list[dict[str, Any]] = []
        examined = 0
        truncated = False
        remaining = maximum_records
        with self._lock, closing(self._connect()) as connection:
            for table in selected:
                if remaining <= 0:
                    truncated = True
                    break
                page_limit = remaining
                rows = connection.execute(
                    f"SELECT record_id, target_id, created_at, payload FROM {table} "
                    "ORDER BY created_at ASC LIMIT ?",
                    (page_limit + 1,),
                ).fetchall()
                page_truncated = len(rows) > page_limit
                for row in rows[:page_limit]:
                    examined += 1
                    remaining -= 1
                    try:
                        created_at = datetime.fromisoformat(row[2])
                    except (TypeError, ValueError):
                        preserved.append({
                            "family": table,
                            "record_id": row[0],
                            "reason": "invalid_created_at",
                        })
                        continue
                    if created_at.tzinfo is None:
                        preserved.append({
                            "family": table,
                            "record_id": row[0],
                            "reason": "naive_created_at",
                        })
                        continue
                    if created_at >= older_than:
                        continue
                    try:
                        payload = json.loads(row[3])
                    except (TypeError, ValueError):
                        payload = None
                    reason = _retention_preservation_reason(table, payload)
                    item = {
                        "family": table,
                        "record_id": row[0],
                        "target_id": row[1],
                        "created_at": row[2],
                    }
                    if reason is not None:
                        item["reason"] = reason
                        preserved.append(item)
                    else:
                        candidates.append(item)
                    if remaining <= 0:
                        truncated = True
                        break
                if page_truncated:
                    # A full page may hide additional records; the caller
                    # receives an explicit bounded-result marker.
                    truncated = True
                    break
        return {
            "schema_version": REPAIR_RETENTION_PLAN_SCHEMA_VERSION,
            "store_schema_version": REPAIR_STORE_SCHEMA_VERSION,
            "older_than": older_than.isoformat(),
            "families": list(selected),
            "maximum_records": maximum_records,
            "examined_records": examined,
            "truncated": truncated,
            "candidate_records": candidates,
            "preserved_records": preserved,
        }

    def retention_archive(
        self,
        plan: Mapping[str, Any],
        *,
        archive_path: str | Path,
        maximum_records: int = 1000,
    ) -> Mapping[str, Any]:
        """Copy a complete dry-run plan into a resumable compressed archive.

        The source store is never changed.  A plan must be complete and is
        rechecked against the current rows before each record is copied.  The
        uncompressed ``.partial.jsonl`` sidecar is deliberately retained while
        work is incomplete, so an interrupted call can resume without
        duplicating records.  A final archive is created with an atomic rename.
        Deletion and compaction are separate, policy-owned operations.
        """

        if not isinstance(plan, Mapping):
            raise TypeError("retention plan must be a mapping")
        if plan.get("schema_version") != REPAIR_RETENTION_PLAN_SCHEMA_VERSION:
            raise ValueError("unsupported Caretaker retention plan schema version")
        if plan.get("store_schema_version") != REPAIR_STORE_SCHEMA_VERSION:
            raise ValueError("retention plan targets an unsupported store schema version")
        if plan.get("truncated"):
            raise ValueError("a truncated retention plan cannot be archived")
        if (
            isinstance(maximum_records, bool)
            or not isinstance(maximum_records, int)
            or maximum_records <= 0
        ):
            raise ValueError("maximum_records must be a positive integer")
        try:
            cutoff = datetime.fromisoformat(str(plan["older_than"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("retention plan cutoff is invalid") from exc
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise ValueError("retention plan cutoff must be timezone-aware")
        candidates = plan.get("candidate_records")
        if isinstance(candidates, (str, bytes)) or not isinstance(candidates, Sequence):
            raise ValueError("retention plan candidates must be a sequence")
        normalized_candidates: list[dict[str, Any]] = []
        candidate_keys: set[tuple[str, str]] = set()
        for item in candidates:
            if not isinstance(item, Mapping):
                raise ValueError("retention plan candidate is not a mapping")
            family = item.get("family")
            record_id = item.get("record_id")
            if not isinstance(family, str) or family not in self._TABLES:
                raise ValueError("retention plan contains an unknown family")
            if not isinstance(record_id, str) or not record_id:
                raise ValueError("retention plan contains an invalid record ID")
            plan_families = plan.get("families", ())
            if (
                isinstance(plan_families, (str, bytes))
                or not isinstance(plan_families, Sequence)
                or family not in plan_families
            ):
                raise ValueError("retention plan candidate is outside its family scope")
            key = (family, record_id)
            if key in candidate_keys:
                raise ValueError("retention plan contains a duplicate record")
            candidate_keys.add(key)
            normalized_candidates.append({
                "family": family,
                "record_id": record_id,
                "target_id": item.get("target_id"),
                "created_at": item.get("created_at"),
            })

        destination = Path(archive_path)
        if destination.resolve() == self.path.resolve():
            raise ValueError("retention archive cannot overwrite the repair store")
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(destination.name + ".partial.jsonl")
        plan_sha256 = hashlib.sha256(
            _canonical_json_bytes({
                "schema_version": plan["schema_version"],
                "store_schema_version": plan["store_schema_version"],
                "older_than": plan["older_than"],
                "families": plan.get("families", []),
                "candidate_records": normalized_candidates,
            })
        ).hexdigest()

        if destination.exists():
            summary = _read_retention_archive(destination)
            if summary["plan_sha256"] != plan_sha256:
                raise ValueError("existing retention archive belongs to a different plan")
            if summary["record_keys"] != candidate_keys:
                raise ValueError("existing retention archive does not match the retention plan")
            return {
                "schema_version": REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION,
                "archive_path": str(destination),
                "partial": False,
                "complete": True,
                "plan_sha256": plan_sha256,
                "archived_records": summary["record_count"],
                "remaining_records": 0,
                "resumed_records": summary["record_count"],
            }

        header = {
            "kind": "retention_archive_header",
            "schema_version": REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION,
            "store_schema_version": REPAIR_STORE_SCHEMA_VERSION,
            "format": "caretaker-repair-retention-jsonl-v1",
            "plan_sha256": plan_sha256,
        }
        existing: dict[tuple[str, str], dict[str, Any]] = {}
        if partial.exists():
            existing_header, existing = _read_retention_partial(partial)
            if existing_header != header:
                raise ValueError("existing retention partial belongs to a different plan")
            if not set(existing).issubset(candidate_keys):
                raise ValueError("existing retention partial contains an unplanned record")
        else:
            partial.touch(mode=0o600)
            partial.chmod(0o600)
            with partial.open("ab") as stream:
                stream.write(_canonical_json_bytes(header) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())

        pending = [
            item for item in normalized_candidates
            if (item["family"], item["record_id"]) not in existing
        ]
        if len(pending) > maximum_records:
            to_archive = pending[:maximum_records]
        else:
            to_archive = pending
        new_records: list[dict[str, Any]] = []
        with self._lock, closing(self._connect()) as connection:
            for item in to_archive:
                row = connection.execute(
                    f"SELECT target_id, created_at, payload FROM {item['family']} WHERE record_id = ?",
                    (item["record_id"],),
                ).fetchone()
                if row is None or row[0] != item["target_id"] or row[1] != item["created_at"]:
                    raise ValueError(
                        "retention plan is stale for "
                        f"{item['family']}/{item['record_id']}"
                    )
                try:
                    created_at = datetime.fromisoformat(row[1])
                    payload = json.loads(row[2])
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError("retention plan row is no longer valid JSON") from exc
                if (
                    created_at.tzinfo is None
                    or created_at.utcoffset() is None
                    or created_at >= cutoff
                    or _retention_preservation_reason(item["family"], payload) is not None
                ):
                    raise ValueError(
                        "retention plan row is no longer eligible for archival: "
                        f"{item['family']}/{item['record_id']}"
                    )
                record = {
                    "kind": "retention_archive_record",
                    "family": item["family"],
                    "record_id": item["record_id"],
                    "target_id": row[0],
                    "created_at": row[1],
                    "payload": payload,
                }
                record["record_sha256"] = hashlib.sha256(
                    _canonical_json_bytes(record)
                ).hexdigest()
                new_records.append(record)

        if new_records:
            with partial.open("ab") as stream:
                for record in new_records:
                    stream.write(_canonical_json_bytes(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            existing.update({
                (record["family"], record["record_id"]): record
                for record in new_records
            })

        remaining = len(normalized_candidates) - len(existing)
        if remaining:
            return {
                "schema_version": REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION,
                "archive_path": str(destination),
                "partial_path": str(partial),
                "partial": True,
                "complete": False,
                "plan_sha256": plan_sha256,
                "archived_records": len(existing),
                "remaining_records": remaining,
                "resumed_records": len(existing) - len(new_records),
            }

        records_digest = hashlib.sha256()
        with partial.open("rb") as stream:
            lines = stream.readlines()
        for line in lines[1:]:
            record = json.loads(line)
            if record.get("kind") == "retention_archive_record":
                records_digest.update(line)
        footer = {
            "kind": "retention_archive_footer",
            "schema_version": REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION,
            "record_count": len(existing),
            "records_sha256": records_digest.hexdigest(),
        }
        with partial.open("ab") as stream:
            stream.write(_canonical_json_bytes(footer) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary = destination.with_name(destination.name + ".tmp")
        with partial.open("rb") as source, gzip.open(temporary, "wb") as compressed:
            while chunk := source.read(1024 * 1024):
                compressed.write(chunk)
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        partial.unlink()
        return {
            "schema_version": REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION,
            "archive_path": str(destination),
            "partial": False,
            "complete": True,
            "plan_sha256": plan_sha256,
            "archived_records": len(existing),
            "remaining_records": 0,
            "resumed_records": len(existing) - len(new_records),
        }

    def retention_archive_status(
        self,
        archive_path: str | Path,
    ) -> Mapping[str, Any]:
        """Verify and summarize a completed Repair retention archive."""

        destination = Path(archive_path)
        summary = _read_retention_archive(destination)
        return {
            "schema_version": REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION,
            "archive_path": str(destination),
            "complete": True,
            "plan_sha256": summary["plan_sha256"],
            "record_count": summary["record_count"],
            "record_families": sorted({family for family, _ in summary["record_keys"]}),
        }

    def query_records(
        self,
        table: str,
        *,
        target_id: str | None = None,
        limit: int = 100,
    ) -> tuple[Mapping[str, Any], ...]:
        if table not in self._TABLES:
            raise ValueError(f"Unknown Caretaker store table: {table}")
        sql = f"SELECT payload FROM {table}"
        parameters: list[Any] = []
        if target_id is not None:
            sql += " WHERE target_id = ?"
            parameters.append(target_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(max(0, limit))
        with self._lock, closing(self._connect()) as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return tuple(json.loads(row[0]) for row in reversed(rows))

    @property
    def schema_version(self) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT value FROM caretaker_store_metadata WHERE key='schema_version'"
            ).fetchone()
        return int(row[0]) if row else 0


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _read_retention_partial(
    path: Path,
) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    raw = path.read_bytes()
    if not raw.endswith(b"\n"):
        last_newline = raw.rfind(b"\n")
        if last_newline < 0:
            raise ValueError("retention partial has no complete header")
        raw = raw[: last_newline + 1]
        path.write_bytes(raw)
    try:
        lines = [json.loads(line) for line in raw.splitlines()]
    except json.JSONDecodeError as exc:
        raise ValueError("retention partial contains invalid JSON") from exc
    if not lines or lines[0].get("kind") != "retention_archive_header":
        raise ValueError("retention partial header is missing")
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for item in lines[1:]:
        if item.get("kind") != "retention_archive_record":
            raise ValueError("retention partial contains an unexpected record")
        family = item.get("family")
        record_id = item.get("record_id")
        if not isinstance(family, str) or not isinstance(record_id, str):
            raise ValueError("retention partial record identity is invalid")
        record_sha256 = item.get("record_sha256")
        unsigned = dict(item)
        unsigned.pop("record_sha256", None)
        if record_sha256 != hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest():
            raise ValueError("retention partial record integrity check failed")
        key = (family, record_id)
        if key in records:
            raise ValueError("retention partial contains a duplicate record")
        records[key] = item
    return lines[0], records


def _read_retention_archive(path: Path) -> dict[str, Any]:
    try:
        with gzip.open(path, "rb") as stream:
            raw = stream.read()
    except (OSError, EOFError) as exc:
        raise ValueError("retention archive cannot be read") from exc
    try:
        lines = [json.loads(line) for line in raw.splitlines()]
    except json.JSONDecodeError as exc:
        raise ValueError("retention archive contains invalid JSON") from exc
    if len(lines) < 2 or lines[0].get("kind") != "retention_archive_header":
        raise ValueError("retention archive header is missing")
    if (
        lines[0].get("schema_version") != REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION
        or lines[0].get("store_schema_version") != REPAIR_STORE_SCHEMA_VERSION
        or lines[0].get("format") != "caretaker-repair-retention-jsonl-v1"
    ):
        raise ValueError("retention archive header is unsupported")
    footer = lines[-1]
    if footer.get("kind") != "retention_archive_footer":
        raise ValueError("retention archive footer is missing")
    if footer.get("schema_version") != REPAIR_RETENTION_ARCHIVE_SCHEMA_VERSION:
        raise ValueError("retention archive footer is unsupported")
    digest = hashlib.sha256()
    count = 0
    record_keys: set[tuple[str, str]] = set()
    for item, line in zip(lines[1:-1], raw.splitlines()[1:-1]):
        if item.get("kind") != "retention_archive_record":
            raise ValueError("retention archive contains an unexpected record")
        record_sha256 = item.get("record_sha256")
        unsigned = dict(item)
        unsigned.pop("record_sha256", None)
        if record_sha256 != hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest():
            raise ValueError("retention archive record integrity check failed")
        family = item.get("family")
        record_id = item.get("record_id")
        if (
            not isinstance(family, str)
            or family not in SQLiteRepairStore._TABLES
            or not isinstance(record_id, str)
            or not record_id
        ):
            raise ValueError("retention archive record identity is invalid")
        key = (family, record_id)
        if key in record_keys:
            raise ValueError("retention archive contains a duplicate record")
        record_keys.add(key)
        digest.update(line + b"\n")
        count += 1
    if footer.get("record_count") != count or footer.get("records_sha256") != digest.hexdigest():
        raise ValueError("retention archive footer integrity check failed")
    return {
        "plan_sha256": lines[0].get("plan_sha256"),
        "record_count": count,
        "record_keys": record_keys,
    }


def _record_time(record: object) -> datetime:
    for name in ("timestamp", "occurred_at", "created_at", "calculated_at", "observed_at"):
        value = getattr(record, name, None)
        if isinstance(value, datetime):
            return value
    return datetime.now().astimezone()


def _retention_preservation_reason(table: str, payload: Any) -> str | None:
    if table in _RETENTION_PROTECTED_TABLES:
        return "protected_artifact_family"
    if payload is None:
        return "invalid_payload"
    if _payload_contains_key(payload, {"incident_id", "incident_ids"}):
        return "incident_linked_evidence"
    if _payload_contains_key(
        payload,
        {"signature", "artifact_signature", "signatures", "signature_state"},
    ):
        return "signed_evidence"
    return None


def _payload_contains_key(value: Any, keys: set[str]) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key).lower() in keys or _payload_contains_key(item, keys)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_payload_contains_key(item, keys) for item in value)
    return False


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: _jsonable(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset, deque)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}", "repr": _safe_repr(value)}


def _safe_repr(value: object) -> str:
    try:
        return repr(value)
    except Exception as exc:  # pragma: no cover - defensive path
        return f"<repr failed: {type(exc).__name__}: {exc}>"
