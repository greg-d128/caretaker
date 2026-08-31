from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime
from threading import Condition, RLock
from uuid import UUID, uuid4

from .acceptance import long_term_accepted, short_term_accepted
from .domain import CandidateState, SlotRole, SlotState, utcnow
from .execution import FunctionExecutionContract
from .policy import AcceptanceCriteria


class SlotConflictError(RuntimeError):
    pass


class RepairAlreadyInProgressError(RuntimeError):
    pass


class FlappingCandidateError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class FunctionVersion:
    number: int
    implementation: Callable[..., object]
    source: str | None
    source_hash: str | None
    activated_at: datetime
    repair_attempt_id: UUID | None = None
    candidate_id: UUID | None = None
    candidate_state: CandidateState | None = None


@dataclass(frozen=True, slots=True)
class RepairLease:
    lease_id: UUID
    target_id: str
    base_version: int
    acquired_at: datetime


@dataclass(frozen=True, slots=True)
class ObservationSession:
    candidate_id: UUID
    function_version: int
    started_at: datetime
    successful_executions: int = 0
    failed_executions: int = 0
    state: CandidateState = CandidateState.ACTIVE_PROBATION


class FunctionSlot:
    def __init__(
        self,
        *,
        target_id: str,
        original: Callable[..., object],
        original_source: str | None = None,
        original_source_hash: str | None = None,
        execution_contract: FunctionExecutionContract | None = None,
        role: SlotRole = SlotRole.TARGET_IMPLEMENTATION,
        history_limit: int = 20,
    ) -> None:
        self.target_id = target_id
        self.role = role
        self.execution_contract = execution_contract or FunctionExecutionContract()
        self._lock = RLock()
        self._condition = Condition(self._lock)
        self._current = FunctionVersion(
            number=0,
            implementation=original,
            source=original_source,
            source_hash=original_source_hash,
            activated_at=utcnow(),
        )
        self._original = self._current
        self._history: deque[FunctionVersion] = deque(maxlen=history_limit)
        self._archive: deque[FunctionVersion] = deque(maxlen=max(100, history_limit * 5))
        self._failed_source_hashes: set[str] = set()
        self._transition_hashes: deque[str | None] = deque(maxlen=max(20, history_limit))
        self._transition_hashes.append(original_source_hash)
        self._state = SlotState.HEALTHY
        self._active_lease: RepairLease | None = None
        self._observation: ObservationSession | None = None

    @property
    def state(self) -> SlotState:
        with self._lock:
            return self._state

    @property
    def original(self) -> Callable[..., object]:
        return self._original.implementation

    def load(self) -> FunctionVersion:
        with self._lock:
            return self._current

    def previous(self) -> FunctionVersion | None:
        with self._lock:
            return self._history[-1] if self._history else None

    def observation(self) -> ObservationSession | None:
        with self._lock:
            return self._observation

    def begin_repair(self) -> RepairLease:
        with self._lock:
            if self._state is SlotState.REPAIRING:
                raise RepairAlreadyInProgressError(self.target_id)
            if self._state in {SlotState.QUARANTINED, SlotState.DISABLED}:
                raise RuntimeError(
                    f"Target {self.target_id} cannot be repaired in state {self._state.name}"
                )
            lease = RepairLease(
                lease_id=uuid4(),
                target_id=self.target_id,
                base_version=self._current.number,
                acquired_at=utcnow(),
            )
            self._active_lease = lease
            self._state = SlotState.REPAIRING
            return lease

    def abandon_repair(self, lease: RepairLease) -> None:
        with self._condition:
            self._require_active_lease(lease)
            self._active_lease = None
            self._state = self._state_for_current_version()
            self._condition.notify_all()

    def can_activate_source(
        self,
        source_hash: str,
        *,
        prevent_failed_reactivation: bool,
        detect_oscillation: bool,
        oscillation_window_versions: int,
    ) -> tuple[bool, str | None]:
        with self._lock:
            if source_hash == self._current.source_hash:
                return False, "candidate source is identical to the active implementation"
            if prevent_failed_reactivation and source_hash in self._failed_source_hashes:
                return False, "candidate source was previously rolled back"
            if detect_oscillation:
                recent = list(self._transition_hashes)[-max(2, oscillation_window_versions):]
                if len(recent) >= 2 and source_hash == recent[-2] and source_hash != recent[-1]:
                    return False, "candidate would create an A-B-A version oscillation"
            return True, None

    def activate(
        self,
        *,
        lease: RepairLease,
        implementation: Callable[..., object],
        source: str,
        source_hash: str,
        repair_attempt_id: UUID,
        candidate_id: UUID,
    ) -> FunctionVersion:
        with self._condition:
            self._require_active_lease(lease)
            if self._current.number != lease.base_version:
                raise SlotConflictError(
                    f"Target {self.target_id} changed from version "
                    f"{lease.base_version} to {self._current.number}"
                )
            previous = self._current
            candidate = FunctionVersion(
                number=previous.number + 1,
                implementation=implementation,
                source=source,
                source_hash=source_hash,
                activated_at=utcnow(),
                repair_attempt_id=repair_attempt_id,
                candidate_id=candidate_id,
                candidate_state=CandidateState.ACTIVE_PROBATION,
            )
            self._history.append(previous)
            self._archive.append(previous)
            self._current = candidate
            self._transition_hashes.append(source_hash)
            self._observation = ObservationSession(
                candidate_id=candidate_id,
                function_version=candidate.number,
                started_at=utcnow(),
            )
            self._active_lease = None
            self._state = SlotState.CANDIDATE_ACTIVE
            self._condition.notify_all()
            return candidate

    def record_observation_success(
        self,
        *,
        acceptance: AcceptanceCriteria,
    ) -> ObservationSession | None:
        with self._condition:
            if self._observation is None:
                return None
            observation = replace(
                self._observation,
                successful_executions=self._observation.successful_executions + 1,
            )
            candidate_state = observation.state
            if long_term_accepted(
                successful_executions=observation.successful_executions,
                failed_executions=observation.failed_executions,
                started_at=observation.started_at,
                criteria=acceptance,
            ):
                candidate_state = CandidateState.LONG_TERM_ACCEPTED
                self._state = SlotState.LONG_TERM_ACCEPTED
            elif short_term_accepted(
                successful_executions=observation.successful_executions,
                failed_executions=observation.failed_executions,
                criteria=acceptance,
            ):
                candidate_state = CandidateState.INITIALLY_VALIDATED
                self._state = SlotState.INITIALLY_VALIDATED
            observation = replace(observation, state=candidate_state)
            self._observation = observation
            if self._current.candidate_id == observation.candidate_id:
                self._current = replace(self._current, candidate_state=candidate_state)
            self._condition.notify_all()
            return observation

    def record_observation_failure(self) -> ObservationSession | None:
        with self._condition:
            if self._observation is None:
                return None
            self._observation = replace(
                self._observation,
                failed_executions=self._observation.failed_executions + 1,
                state=CandidateState.DEGRADED,
            )
            if self._current.candidate_id == self._observation.candidate_id:
                self._current = replace(
                    self._current, candidate_state=CandidateState.DEGRADED
                )
            self._state = SlotState.CANDIDATE_ACTIVE
            return self._observation

    def rollback(self, expected_version: int) -> FunctionVersion:
        with self._condition:
            if self._current.number != expected_version:
                raise SlotConflictError(
                    f"Current version is {self._current.number}; expected {expected_version}"
                )
            if not self._history:
                raise RuntimeError(f"No previous version exists for {self.target_id}")
            failed_version = replace(
                self._current,
                candidate_state=CandidateState.ROLLED_BACK,
            )
            if failed_version.source_hash:
                self._failed_source_hashes.add(failed_version.source_hash)
            self._archive.append(failed_version)
            self._current = self._history.pop()
            self._transition_hashes.append(self._current.source_hash)
            self._observation = None
            self._state = self._state_for_current_version()
            self._condition.notify_all()
            return failed_version

    def quarantine(self) -> None:
        with self._condition:
            self._active_lease = None
            self._state = SlotState.QUARANTINED
            self._condition.notify_all()

    def disable(self) -> None:
        with self._condition:
            self._active_lease = None
            self._state = SlotState.DISABLED
            self._condition.notify_all()

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "target_id": self.target_id,
                "role": self.role.name,
                "state": self._state.name,
                "current_version": self._current.number,
                "current_source_hash": self._current.source_hash,
                "execution_contract": {
                    "side_effects": self.execution_contract.side_effects.name,
                    "retry_safety": self.execution_contract.retry_safety.name,
                },
                "candidate_id": str(self._current.candidate_id) if self._current.candidate_id else None,
                "candidate_state": self._current.candidate_state.name if self._current.candidate_state else None,
                "history_versions": [version.number for version in self._history],
                "archived_versions": [version.number for version in self._archive],
                "failed_source_hashes": sorted(self._failed_source_hashes),
                "repair_active": self._active_lease is not None,
                "observation": {
                    "successes": self._observation.successful_executions,
                    "failures": self._observation.failed_executions,
                    "state": self._observation.state.name,
                } if self._observation else None,
            }

    def _state_for_current_version(self) -> SlotState:
        state = self._current.candidate_state
        if state is CandidateState.LONG_TERM_ACCEPTED:
            return SlotState.LONG_TERM_ACCEPTED
        if state is CandidateState.INITIALLY_VALIDATED:
            return SlotState.INITIALLY_VALIDATED
        if state in {CandidateState.ACTIVE_PROBATION, CandidateState.DEGRADED}:
            return SlotState.CANDIDATE_ACTIVE
        return SlotState.HEALTHY

    def _require_active_lease(self, lease: RepairLease) -> None:
        if self._active_lease is None:
            raise SlotConflictError("No repair lease is active")
        if self._active_lease.lease_id != lease.lease_id:
            raise SlotConflictError("Repair lease does not match")
