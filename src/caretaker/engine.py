from __future__ import annotations

import ast
import hashlib
import inspect
import logging
import os
import re
import textwrap
import time
import types
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, TYPE_CHECKING
from uuid import UUID, uuid4

from .auxiliary import AuxiliaryRegistry
from .authority import get_authority_runtime_context
from .capsule import IncidentCapsuleStore
from .contracts import normalize_validation_result
from .domain import (
    ActivationResult,
    ArtifactFile,
    CandidateGeneration,
    CandidateGenerationOutcome,
    CandidateGeneratorKind,
    CandidateLineage,
    CandidateState,
    CheckOutcome,
    DifferentialEvidence,
    GeneratedTest,
    Incident,
    IncidentTargetReference,
    OutputValidationEvidence,
    RepairArtifact,
    RepairArtifactKind,
    RepairAttempt,
    RepairAttemptOutcome,
    RepairAttemptStage,
    RepairCandidate,
    RepairEpisode,
    RepairEpisodeOutcome,
    RepairMode,
    ReplaySafety,
    ValidationResult,
    RepairEvent,
    RetryResult,
    TargetCapability,
    TimeoutEvidence,
    TriggerKind,
    TimeoutMode,
    ValidationCheckKind,
    ValidationCheckResult,
    utcnow,
)
from .logging.handler import get_runtime as get_logging_runtime
from .logging.models import RepairAuthority
from .observation import ObservationManager
from .policy import OutputValidationTrigger, RepairPolicy, TimeoutTrigger
from .postmortem import PostMortemRecorder
from .provider import CandidateBatch, CandidateProposal, RepairProvider, RepairRequest
from .registry import RepairTarget, TargetRegistry, build_target
from .regression import RegressionCorpus, RegressionFixtureStore
from .runtime import current_episode_id, repair_depth, set_runtime_context
from .selection import CandidateScorer, CandidateSelector, EvaluatedCandidate
from .slot import FunctionVersion, RepairAlreadyInProgressError, SlotConflictError
from .state import (
    CallState,
    StateCapture,
    build_call_snapshot,
    exception_evidence,
    value_snapshot,
)
from .store import InMemoryRepairStore, RepairStore
from .telemetry import CorrelatedLogHandler, logger
from .validation import (
    ValidationBackend,
    ValidationBackendRegistry,
    SubprocessValidationBackend,
    sanitized_function_tree,
)


class ResolutionKind:
    NOT_HANDLED = "not_handled"
    REPAIR_FAILED = "repair_failed"
    REPAIRED_NOT_RETRIED = "repaired_not_retried"
    RETRY_SUCCEEDED = "retry_succeeded"
    RETRY_FAILED = "retry_failed"
    AWAITING_APPROVAL = "awaiting_approval"
    STALE_POLICY = "stale_policy"


@dataclass(frozen=True, slots=True)
class RepairResolution:
    kind: str
    incident_id: UUID
    episode_id: UUID | None
    attempt_ids: tuple[UUID, ...]
    active_function_version: int
    retry_output: Any = None
    retry_exception: BaseException | None = None


@dataclass(frozen=True, slots=True)
class PendingRepairApproval:
    episode_id: UUID
    target_id: str
    candidate_id: UUID
    attempt_id: UUID
    source: str
    artifact_hash: str
    expected_function_version: int
    logging_policy_generation: int | None
    authority_policy_generation: int
    authority_policy_fingerprint: str
    reason: str



class RepairEngine:
    def __init__(
        self,
        *,
        provider: RepairProvider | None = None,
        registry: TargetRegistry | None = None,
        store: RepairStore | None = None,
        validation_backend: ValidationBackend | None = None,
        validation_backends: tuple[ValidationBackend, ...] | None = None,
        log_handler: CorrelatedLogHandler | None = None,
        auxiliary_registry: AuxiliaryRegistry | None = None,
        capsule_store: IncidentCapsuleStore | None = None,
        regression_fixture_store: RegressionFixtureStore | None = None,
        guard: "GuardFacade | None" = None,
        run_id: UUID | None = None,
    ) -> None:
        self.provider = provider
        self.registry = registry or TargetRegistry()
        self.store = store or InMemoryRepairStore()
        if validation_backend is not None and validation_backends is not None:
            raise ValueError("specify validation_backend or validation_backends, not both")
        configured_backends = (
            validation_backends
            if validation_backends is not None
            else ((validation_backend,) if validation_backend is not None else (SubprocessValidationBackend(),))
        )
        self.validation_registry = ValidationBackendRegistry(tuple(configured_backends))
        # Backward-compatible default backend attribute. Candidate evaluation uses
        # the registry so minimum-isolation policy can select a stronger backend.
        self.validation_backend = configured_backends[0]
        self.log_handler = log_handler or CorrelatedLogHandler()
        self.auxiliary_registry = auxiliary_registry or AuxiliaryRegistry()
        self.capsule_store = capsule_store
        self._capsule_store_explicit = capsule_store is not None
        self.regression_fixture_store = regression_fixture_store
        if os.environ.get("CARETAKER_SUPERVISED"):
            logging_runtime = get_logging_runtime()
            active_policy = logging_runtime.active_policy if logging_runtime is not None else None
            capsule_policy = getattr(active_policy, "capsules", None)
            if self.capsule_store is None and capsule_policy is not None and capsule_policy.enabled:
                self.capsule_store = IncidentCapsuleStore(
                    active_policy.directory,
                    policy=capsule_policy,
                )
            regression_policy = getattr(active_policy, "regression", None)
            if self.regression_fixture_store is None and regression_policy is not None and regression_policy.enabled:
                self.regression_fixture_store = RegressionFixtureStore(
                    active_policy.directory,
                    policy=regression_policy,
                )
        self.guard = guard
        self.run_id = run_id or uuid4()
        self.state_capture = StateCapture()
        self.scorer = CandidateScorer()
        self.selector = CandidateSelector()
        self.observation = ObservationManager(self.store)
        self.regression = RegressionCorpus(fixture_store=self.regression_fixture_store)
        self._repair_history: dict[tuple[str, str], list[datetime]] = {}
        self._attempt_cache: dict[UUID, RepairAttempt] = {}
        self._pending_guard_deviations: dict[str, tuple[Any, ...]] = {}
        self._pending_approvals: dict[UUID, PendingRepairApproval] = {}
        self._declared_policies: dict[str, RepairPolicy] = {}
        self._activity_lock = threading.RLock()
        self._active_incidents: dict[UUID, dict[str, Any]] = {}
        self._active_validations: dict[UUID, dict[str, Any]] = {}
        self.postmortem = PostMortemRecorder(
            store=self.store,
            registry=self.registry,
            log_handler=self.log_handler,
        )
        if self.guard is not None and hasattr(self.guard, "configure_repair_callbacks"):
            self.guard.configure_repair_callbacks(
                open_repair=self.queue_guard_repair,
                rollback_candidate=self.rollback_candidate,
            )
        from .operator import register_repair_engine
        register_repair_engine(self)

    def register(
        self,
        target: RepairTarget,
        *,
        declared_policy: RepairPolicy | None = None,
    ) -> None:
        declared = declared_policy or target.policy
        self._declared_policies[target.target_id] = declared
        effective_policy = get_authority_runtime_context().apply(
            declared, prefix="repair", target_id=target.target_id
        )
        support_probe = build_target(
            target.slot.original,
            policy=effective_policy,
            target_id=target.target_id,
            registered_cases=target.registered_cases,
            tags=target.tags,
            metadata=target.metadata,
            integrity_class=target.integrity_class,
            mask_function=target.mask_function,
        )
        target = replace(
            target, policy=effective_policy, support=support_probe.support
        )
        self.registry.register(target)
        if self.guard is not None and target.policy.guard.enabled:
            self.guard.register_target(
                target.target_id,
                target.slot.load().implementation,
                target.policy.guard,
                function_resolver=lambda target_id=target.target_id: self.registry.get(target_id).slot.load().implementation,
            )

    def refresh_authority_policy(self) -> None:
        """Recompute every registered target from its declared policy."""
        context = get_authority_runtime_context()
        for current in self.registry.all():
            declared = self._declared_policies.get(current.target_id, current.policy)
            effective_policy = context.apply(
                declared, prefix="repair", target_id=current.target_id
            )
            support_probe = build_target(
                current.slot.original,
                policy=effective_policy,
                target_id=current.target_id,
                registered_cases=current.registered_cases,
                tags=current.tags,
                metadata=current.metadata,
                integrity_class=current.integrity_class,
                mask_function=current.mask_function,
            )
            updated = replace(
                current,
                policy=effective_policy,
                support=support_probe.support,
            )
            self.registry.register(updated)
            if self.guard is not None:
                self.guard.register_target(
                    updated.target_id,
                    updated.slot.load().implementation,
                    updated.policy.guard,
                    function_resolver=lambda target_id=updated.target_id: self.registry.get(target_id).slot.load().implementation,
                )

    def pending_approvals(self) -> tuple[PendingRepairApproval, ...]:
        return tuple(self._pending_approvals.values())

    def runtime_activity(self) -> dict[str, list[dict[str, Any]]]:
        """Return live Repair work for operator inspection."""
        with self._activity_lock:
            return {
                "active_incidents": [dict(item) for item in self._active_incidents.values()],
                "active_validations": [dict(item) for item in self._active_validations.values()],
            }

    def record_candidate_observation_success(
        self,
        *,
        target: RepairTarget,
        call_id: UUID,
        output: Any,
        mode: str = "canary",
    ) -> None:
        before = target.slot.observation()
        self.observation.record_success(
            slot=target.slot,
            call_id=call_id,
            policy=target.policy.observation,
            output=output,
            mode=mode,
        )
        after = target.slot.observation()
        if (
            self.guard is not None
            and target.policy.guard.enabled
            and after is not None
            and (before is None or after.state is not before.state)
        ):
            if after.state is CandidateState.INITIALLY_VALIDATED:
                self.guard.seal_behavior_snapshot(
                    target.target_id, reason="post-repair-behavior-complete"
                )
            elif after.state is CandidateState.LONG_TERM_ACCEPTED:
                self.guard.seal_behavior_snapshot(
                    target.target_id, reason="long-term-acceptance"
                )

    def approve_repair(self, episode_id: UUID):
        pending = self._pending_approvals[episode_id]
        target = self.registry.get(pending.target_id)
        current = target.slot.load()
        logging_runtime = get_logging_runtime()
        current_generation = logging_runtime.effective.generation if logging_runtime is not None else None
        if current.number != pending.expected_function_version:
            raise RuntimeError("Repair approval is stale because the active function version changed")
        if pending.logging_policy_generation != current_generation:
            raise RuntimeError("Repair approval is stale because the effective logging policy changed")
        authority = get_authority_runtime_context().effective
        if (
            pending.authority_policy_generation != authority.generation
            or pending.authority_policy_fingerprint != authority.fingerprint
        ):
            raise RuntimeError(
                "Repair approval is stale because the effective authority policy changed"
            )
        lease = target.slot.begin_repair()
        try:
            implementation = self._compile_for_activation(pending.source, target, current)
            activated = target.slot.activate(
                lease=lease, implementation=implementation, source=pending.source,
                source_hash=pending.artifact_hash, repair_attempt_id=pending.attempt_id,
                candidate_id=pending.candidate_id,
            )
        except Exception:
            try:
                target.slot.abandon_repair(lease)
            except Exception:
                pass
            raise
        if self.guard is not None and target.policy.guard.enabled:
            self.guard.seal_behavior_snapshot(target.target_id, reason="repair-activated")
        self._pending_approvals.pop(episode_id, None)
        self.store.append_event(RepairEvent.create(
            "repair.operator_approved", target.target_id, episode_id=episode_id,
            candidate_id=pending.candidate_id, details={"activated_version": activated.number},
        ))
        return activated

    def reject_repair(self, episode_id: UUID, reason: str) -> None:
        pending = self._pending_approvals.pop(episode_id)
        self.store.append_event(RepairEvent.create(
            "repair.operator_rejected", pending.target_id, episode_id=episode_id,
            candidate_id=pending.candidate_id, details={"reason": reason},
        ))

    def queue_guard_repair(
        self,
        target_id: str,
        deviations: tuple["BehaviorDeviation", ...],
    ) -> None:
        self._pending_guard_deviations[target_id] = tuple(deviations)
        self.store.append_event(
            RepairEvent.create(
                "guard.repair_queued",
                target_id,
                details={
                    "deviation_ids": [str(item.deviation_id) for item in deviations],
                    "explanations": [item.explanation for item in deviations],
                },
            )
        )

    def rollback_candidate(self, candidate_id: UUID, reason: str) -> None:
        for target in self.registry.all():
            current = target.slot.load()
            if current.candidate_id != candidate_id:
                continue
            try:
                target.slot.rollback(current.number)
                self.store.append_event(
                    RepairEvent.create(
                        "guard.candidate_rolled_back",
                        target.target_id,
                        candidate_id=candidate_id,
                        details={"reason": reason},
                    )
                )
            except Exception as exc:
                self.postmortem.capture(
                    exc,
                    component="guard-repair-integration",
                    operation="rollback candidate",
                )
            return

    def handle_pending_guard_signal(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        call_id: UUID,
        started_at: datetime,
    ) -> RepairResolution | None:
        deviations = self._pending_guard_deviations.pop(target.target_id, None)
        if not deviations:
            return None
        explanation = "; ".join(item.explanation for item in deviations)
        failure = OutputValidationEvidence(
            validator_name="caretaker-guard",
            reason=explanation or "Guard detected significant behavior deviation",
            output=value_snapshot(None),
        )
        return self._handle(
            target=target,
            version=version,
            function=function,
            args=args,
            kwargs=kwargs,
            call_state=call_state,
            call_id=call_id,
            started_at=started_at,
            elapsed_seconds=0.0,
            call_attempt=1,
            trigger=TriggerKind.MANUAL,
            failure=failure,
            original_exception=RuntimeError(explanation),
            metadata={
                "guard_deviation_ids": [str(item.deviation_id) for item in deviations],
                "guard_deviations": [item.explanation for item in deviations],
            },
        )

    def resolve_validator(self, validator_id: str) -> Any:
        return self.auxiliary_registry.resolve(validator_id)

    def handle_exception(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        exception: BaseException,
        call_id: UUID,
        started_at: datetime,
        elapsed_seconds: float,
        call_attempt: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> RepairResolution:
        evidence = exception_evidence(
            exception,
            capture_locals=target.policy.state.capture_failure_locals,
        )
        return self._handle(
            target=target,
            version=version,
            function=function,
            args=args,
            kwargs=kwargs,
            call_state=call_state,
            call_id=call_id,
            started_at=started_at,
            elapsed_seconds=elapsed_seconds,
            call_attempt=call_attempt,
            trigger=TriggerKind.EXCEPTION,
            failure=evidence,
            original_exception=exception,
            metadata=metadata or {},
        )

    def handle_invalid_output(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        output: Any,
        validator_name: str,
        reason: str,
        call_id: UUID,
        started_at: datetime,
        elapsed_seconds: float,
    ) -> RepairResolution:
        exception = ValueError(f"Output validation failed: {reason}")
        return self._handle(
            target=target,
            version=version,
            function=function,
            args=args,
            kwargs=kwargs,
            call_state=call_state,
            call_id=call_id,
            started_at=started_at,
            elapsed_seconds=elapsed_seconds,
            call_attempt=1,
            trigger=TriggerKind.INVALID_OUTPUT,
            failure=OutputValidationEvidence(
                validator_name=validator_name,
                reason=reason,
                output=value_snapshot(output),
            ),
            original_exception=exception,
            metadata={"invalid_output_available": True},
        )

    def handle_timeout(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        configured_seconds: float,
        output: Any,
        call_id: UUID,
        started_at: datetime,
        elapsed_seconds: float,
    ) -> RepairResolution:
        exception = TimeoutError(
            f"Function exceeded soft timeout: {elapsed_seconds:.6f}s > {configured_seconds:.6f}s"
        )
        return self._handle(
            target=target,
            version=version,
            function=function,
            args=args,
            kwargs=kwargs,
            call_state=call_state,
            call_id=call_id,
            started_at=started_at,
            elapsed_seconds=elapsed_seconds,
            call_attempt=1,
            trigger=TriggerKind.TIMEOUT,
            failure=TimeoutEvidence(
                configured_seconds=configured_seconds,
                elapsed_seconds=elapsed_seconds,
                mode="soft",
                execution_interrupted=False,
            ),
            original_exception=exception,
            metadata={"successful_slow_output": value_snapshot(output)},
        )

    def handle_differential_failure(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        evidence: DifferentialEvidence,
        call_id: UUID,
        started_at: datetime,
        elapsed_seconds: float,
        fallback_exception: BaseException,
    ) -> RepairResolution:
        previous = target.slot.previous()
        metadata = {
            "differential": True,
            "previous_source": previous.source if previous else None,
            "candidate_source": version.source,
        }
        return self._handle(
            target=target,
            version=version,
            function=function,
            args=args,
            kwargs=kwargs,
            call_state=call_state,
            call_id=call_id,
            started_at=started_at,
            elapsed_seconds=elapsed_seconds,
            call_attempt=1,
            trigger=TriggerKind.DIFFERENTIAL_MISMATCH,
            failure=evidence,
            original_exception=fallback_exception,
            metadata=metadata,
        )

    def _handle(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        call_id: UUID,
        started_at: datetime,
        elapsed_seconds: float,
        call_attempt: int,
        trigger: TriggerKind,
        failure: Any,
        original_exception: BaseException,
        metadata: dict[str, Any],
    ) -> RepairResolution:
        policy = target.policy
        snapshot = policy.snapshot()
        self.store.record_policy(snapshot)
        differences = self.state_capture.differences(
            function,
            args,
            call_state.runtime_snapshot,
            policy.state,
            kwargs,
        ) if policy.state.include_diff_in_incident else ()
        replayable = call_state.runtime_snapshot.replayable or not policy.state.restore_before_retry
        replay_block_reason = None if replayable else "; ".join(call_state.runtime_snapshot.errors)
        authority_policy = get_authority_runtime_context().effective
        metadata = {
            **metadata,
            "authority_policy_generation": authority_policy.generation,
            "authority_policy_fingerprint": authority_policy.fingerprint,
            "authority_assurance": authority_policy.overall_assurance,
        }
        incident = Incident(
            incident_id=uuid4(),
            run_id=self.run_id,
            call_id=call_id,
            occurred_at=utcnow(),
            trigger=trigger,
            target=IncidentTargetReference(
                target_id=target.target_id,
                module_name=target.source.module_name,
                qualified_name=target.source.qualified_name,
                filename=str(target.source.filename) if target.source.filename else None,
                line_number=target.source.first_line_number,
                function_version=version.number,
                source_hash=version.source_hash,
            ),
            call=build_call_snapshot(
                started_at=started_at,
                elapsed_seconds=elapsed_seconds,
                bound_arguments=call_state.bound_arguments,
                call_attempt=call_attempt,
                replayable=replayable,
                replay_block_reason=replay_block_reason,
            ),
            failure=failure,
            policy_snapshot_id=snapshot.policy_snapshot_id,
            policy_fingerprint=snapshot.fingerprint,
            state_differences=differences,
            logs=self.log_handler.recent(
                target_id=target.target_id,
                limit=policy.context.maximum_log_records,
            ),
            repair_depth=repair_depth.get(),
            fingerprint=self._fingerprint(target, version, trigger, failure),
            metadata=metadata,
            authority_policy_generation=authority_policy.generation,
            authority_policy_fingerprint=authority_policy.fingerprint,
        )
        self.store.record_incident(incident)
        capsule_details: dict[str, Any] = {}
        if self.capsule_store is not None:
            logging_runtime = get_logging_runtime()
            active_policy = logging_runtime.active_policy if logging_runtime is not None else None
            capsule_policy = (
                self.capsule_store.policy
                if self._capsule_store_explicit
                else getattr(active_policy, "capsules", self.capsule_store.policy)
            )
            if capsule_policy.enabled:
                try:
                    capsule = self.capsule_store.create_for_incident(
                        incident,
                        policy=capsule_policy,
                        authority_policy_generation=authority_policy.generation,
                        authority_policy_fingerprint=authority_policy.fingerprint,
                    )
                    capsule_payload = capsule.get("capsule") or {}
                    capsule_details = {
                        "capsule_id": capsule_payload.get("capsule_id"),
                        "capsule_revision": capsule_payload.get("revision"),
                        "capsule_content_sha256": (capsule.get("integrity") or {}).get("content_sha256"),
                    }
                except Exception as exc:
                    capsule_details = {
                        "capsule_capture_failed": True,
                        "capsule_capture_error": f"{type(exc).__name__}: {exc}",
                    }
                    logger.warning(
                        "Incident Capsule capture failed for %s: %s",
                        incident.incident_id,
                        capsule_details["capsule_capture_error"],
                    )
        self.store.append_event(
            RepairEvent.create(
                "incident.created",
                target.target_id,
                incident_id=incident.incident_id,
                details={
                    "trigger": trigger.name,
                    "function_version": version.number,
                    "policy": snapshot.human_readable_policy,
                    **capsule_details,
                },
            )
        )

        if (
            not policy.enabled
            or policy.mode is not RepairMode.AUTOMATIC
            or target.support.capability is not TargetCapability.REPAIRABLE
        ):
            return RepairResolution(
                kind=ResolutionKind.NOT_HANDLED,
                incident_id=incident.incident_id,
                episode_id=None,
                attempt_ids=(),
                active_function_version=target.slot.load().number,
            )
        if not self._repair_allowed_by_limits(target, incident):
            self.store.append_event(
                RepairEvent.create(
                    "repair.suppressed_by_limits",
                    target.target_id,
                    incident_id=incident.incident_id,
                    details={
                        "maximum_repairs_per_target": policy.limits.maximum_repairs_per_target,
                        "cooldown_seconds": policy.limits.cooldown_seconds,
                    },
                )
            )
            return RepairResolution(
                kind=ResolutionKind.NOT_HANDLED,
                incident_id=incident.incident_id,
                episode_id=None,
                attempt_ids=(),
                active_function_version=target.slot.load().number,
            )
        if self.provider is None or repair_depth.get() >= policy.limits.maximum_repair_depth:
            return RepairResolution(
                kind=ResolutionKind.NOT_HANDLED,
                incident_id=incident.incident_id,
                episode_id=None,
                attempt_ids=(),
                active_function_version=target.slot.load().number,
            )

        tokens = set_runtime_context(target_id=target.target_id, call_id=call_id, incident_id=incident.incident_id, operation="repair")
        depth_token = repair_depth.set(repair_depth.get() + 1)
        episode_guard = current_episode_id.set(current_episode_id.get())
        with self._activity_lock:
            self._active_incidents[incident.incident_id] = {
                "incident_id": str(incident.incident_id),
                "target_id": target.target_id,
                "trigger": trigger.name,
                "started_at": incident.occurred_at.isoformat(),
                "authority_policy_generation": authority_policy.generation,
                "authority_policy_fingerprint": authority_policy.fingerprint,
            }
        try:
            return self._repair_incident(
                target=target,
                version=version,
                function=function,
                args=args,
                kwargs=kwargs,
                call_state=call_state,
                incident=incident,
                policy_snapshot=snapshot,
                original_exception=original_exception,
            )
        except BaseException as internal_exception:
            record = self.postmortem.capture(
                internal_exception,
                component="repair-engine",
                operation="repair incident",
                original_exception=original_exception,
                original_incident_id=incident.incident_id,
            )
            try:
                original_exception.add_note(
                    "Caretaker failed while processing this exception. "
                    f"Internal incident: {record.internal_incident_id if record else 'unavailable'}"
                )
            except Exception:
                pass
            return RepairResolution(
                kind=ResolutionKind.REPAIR_FAILED,
                incident_id=incident.incident_id,
                episode_id=None,
                attempt_ids=(),
                active_function_version=target.slot.load().number,
            )
        finally:
            with self._activity_lock:
                self._active_incidents.pop(incident.incident_id, None)
            current_episode_id.reset(episode_guard)
            repair_depth.reset(depth_token)
            tokens.reset()

    def _repair_incident(
        self,
        *,
        target: RepairTarget,
        version: FunctionVersion,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        call_state: CallState,
        incident: Incident,
        policy_snapshot: Any,
        original_exception: BaseException,
    ) -> RepairResolution:
        try:
            lease = target.slot.begin_repair()
        except RepairAlreadyInProgressError:
            return RepairResolution(
                kind=ResolutionKind.NOT_HANDLED,
                incident_id=incident.incident_id,
                episode_id=None,
                attempt_ids=(),
                active_function_version=target.slot.load().number,
            )

        logging_runtime = get_logging_runtime()
        logging_policy_generation = logging_runtime.effective.generation if logging_runtime is not None else None
        authority_policy = get_authority_runtime_context().effective
        authority_policy_generation = authority_policy.generation
        authority_policy_fingerprint = authority_policy.fingerprint

        episode = RepairEpisode(
            episode_id=uuid4(),
            incident_id=incident.incident_id,
            target_id=target.target_id,
            created_at=utcnow(),
            completed_at=None,
            policy_snapshot_id=policy_snapshot.policy_snapshot_id,
            outcome=RepairEpisodeOutcome.PENDING,
            authority_policy_generation=authority_policy_generation,
            authority_policy_fingerprint=authority_policy_fingerprint,
        )
        self.store.record_episode(episode)
        set_runtime_context(episode_id=episode.episode_id)
        self.store.append_event(
            RepairEvent.create(
                "repair.episode_started",
                target.target_id,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
            )
        )

        if self.guard is not None and target.policy.guard.enabled:
            self.guard.seal_behavior_snapshot(
                target.target_id, reason="pre-repair-evidence-complete"
            )
        request = self._build_request(target, version, incident, policy_snapshot.human_readable_policy)
        evaluated: list[EvaluatedCandidate] = []
        proposals: dict[UUID, CandidateProposal] = {}
        attempt_ids: list[UUID] = []

        provider_started_at = utcnow()
        try:
            batch = self.provider.generate(request)  # type: ignore[union-attr]
            provider_completed_at = utcnow()
        except Exception as exc:
            provider_completed_at = utcnow()
            failed_generation = CandidateGeneration(
                generation_id=uuid4(),
                episode_id=episode.episode_id,
                incident_id=incident.incident_id,
                target_id=target.target_id,
                generator_kind=CandidateGeneratorKind.LLM,
                generator_name=getattr(self.provider, "name", "provider"),
                provider_name=getattr(self.provider, "name", None),
                model_name=getattr(self.provider, "model_name", None),
                started_at=provider_started_at,
                completed_at=provider_completed_at,
                outcome=CandidateGenerationOutcome.FAILED,
                prompt_version=None,
                prompt_hash=None,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            self.store.record_generation(failed_generation)
            target.slot.abandon_repair(lease)
            episode = replace(
                episode,
                completed_at=utcnow(),
                outcome=RepairEpisodeOutcome.NO_ACCEPTABLE_CANDIDATE,
                summary=f"Provider failed: {type(exc).__name__}: {exc}",
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.REPAIR_FAILED,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
                attempt_ids=(),
                active_function_version=target.slot.load().number,
            )

        generation, candidates = self._record_batch(
            batch=batch,
            episode=episode,
            incident=incident,
            target=target,
            version=version,
            generator_kind=CandidateGeneratorKind.LLM,
            started_at=provider_started_at,
            completed_at=provider_completed_at,
        )
        for candidate, proposal in candidates:
            proposals[candidate.candidate_id] = proposal
            evaluated_item, attempt = self._evaluate_candidate(
                candidate=candidate,
                target=target,
                episode=episode,
                incident=incident,
                policy_snapshot=policy_snapshot,
                attempt_number=len(attempt_ids) + 1,
                validation_state_restore_errors=tuple(
                    self.state_capture.restore_for_validation(
                        function,
                        args,
                        call_state.runtime_snapshot,
                        target.policy.state,
                    )
                ),
            )
            evaluated.append(evaluated_item)
            attempt_ids.append(attempt.attempt_id)

        synthesis = target.policy.selection.synthesis
        parent_pool = (
            (item for item in evaluated if item.score.eligible)
            if synthesis.use_only_eligible_candidates
            else iter(evaluated)
        )
        eligible_initial = sorted(
            (item for item in parent_pool if item.score.total_score >= synthesis.minimum_parent_score),
            key=lambda item: item.score.total_score,
            reverse=True,
        )
        if (
            synthesis.enabled
            and self.provider.supports_synthesis  # type: ignore[union-attr]
            and len(eligible_initial) >= synthesis.minimum_parent_candidates
        ):
            parents = eligible_initial[: synthesis.maximum_parent_candidates]
            parent_payload = [
                (
                    proposals[item.candidate.candidate_id],
                    {
                        "score": item.score.total_score,
                        "safety": item.score.safety_score,
                        "performance": item.score.performance_score,
                        "checks": [
                            {"kind": check.kind.name, "outcome": check.outcome.name, "summary": check.summary}
                            for check in item.report.checks
                        ],
                    },
                )
                for item in parents
            ]
            try:
                synthesized_batch = self.provider.synthesize(request, parent_payload)  # type: ignore[union-attr]
                _, synthesized_candidates = self._record_batch(
                    batch=synthesized_batch,
                    episode=episode,
                    incident=incident,
                    target=target,
                    version=version,
                    generator_kind=CandidateGeneratorKind.CONSOLIDATION,
                    parent_ids=tuple(item.candidate.candidate_id for item in parents),
                )
                parent_best_score = max(item.score.total_score for item in parents)
                for candidate, proposal in synthesized_candidates:
                    proposals[candidate.candidate_id] = proposal
                    evaluated_item, attempt = self._evaluate_candidate(
                        candidate=candidate,
                        target=target,
                        episode=episode,
                        incident=incident,
                        policy_snapshot=policy_snapshot,
                        attempt_number=len(attempt_ids) + 1,
                        validation_state_restore_errors=tuple(
                            self.state_capture.restore_for_validation(
                                function,
                                args,
                                call_state.runtime_snapshot,
                                target.policy.state,
                            )
                        ),
                    )
                    if (
                        synthesis.require_score_improvement
                        and evaluated_item.score.total_score
                        < parent_best_score + synthesis.minimum_improvement
                    ):
                        evaluated_item = replace(
                            evaluated_item,
                            score=replace(
                                evaluated_item.score,
                                eligible=False,
                                disqualification_reasons=tuple(
                                    dict.fromkeys(
                                        (*evaluated_item.score.disqualification_reasons,
                                         "synthesized candidate did not meet minimum score improvement")
                                    )
                                ),
                            ),
                        )
                    evaluated.append(evaluated_item)
                    attempt_ids.append(attempt.attempt_id)
            except Exception as exc:
                self.store.append_event(
                    RepairEvent.create(
                        "candidate.synthesis_failed",
                        target.target_id,
                        incident_id=incident.incident_id,
                        episode_id=episode.episode_id,
                        details={"error": f"{type(exc).__name__}: {exc}"},
                    )
                )

        selected = self.selector.select(evaluated, target.policy)
        if selected is None:
            # A validation policy may deliberately allow an operator to decide
            # whether to proceed when the required isolation backend is unavailable.
            # This path never activates automatically; it preserves the candidate
            # and the missing-isolation evidence for explicit approval.
            approval_candidate = next(
                (
                    item
                    for item in evaluated
                    if item.report.requires_operator_approval
                    and not item.report.hard_disqualifications
                ),
                None,
            )
            if approval_candidate is not None:
                target.slot.abandon_repair(lease)
                selected_attempt = next(
                    attempt for attempt in self._attempt_records(attempt_ids)
                    if attempt.candidate_id == approval_candidate.candidate.candidate_id
                )
                source = approval_candidate.candidate.artifact.files[0].content
                pending = PendingRepairApproval(
                    episode_id=episode.episode_id,
                    target_id=target.target_id,
                    candidate_id=approval_candidate.candidate.candidate_id,
                    attempt_id=selected_attempt.attempt_id,
                    source=source,
                    artifact_hash=approval_candidate.candidate.artifact.artifact_hash,
                    expected_function_version=version.number,
                    logging_policy_generation=logging_policy_generation,
                    authority_policy_generation=authority_policy_generation,
                    authority_policy_fingerprint=authority_policy_fingerprint,
                    reason=(
                        "Required validation isolation backend is unavailable and "
                        "validation.backend_unavailable_action requires operator approval"
                    ),
                )
                self._pending_approvals[episode.episode_id] = pending
                selected_attempt = replace(
                    selected_attempt, completed_at=utcnow(),
                    stage=RepairAttemptStage.COMPLETE,
                    outcome=RepairAttemptOutcome.AWAITING_APPROVAL,
                )
                self.store.record_attempt(selected_attempt)
                self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
                episode = replace(
                    episode, completed_at=utcnow(),
                    outcome=RepairEpisodeOutcome.AWAITING_APPROVAL,
                    selected_candidate_id=approval_candidate.candidate.candidate_id,
                    selected_attempt_id=selected_attempt.attempt_id,
                    summary=(
                        "Candidate could not be validated at the policy-required isolation "
                        "level and is awaiting explicit operator approval. It has not been deployed."
                    ),
                )
                self.store.record_episode(episode)
                return RepairResolution(
                    kind=ResolutionKind.AWAITING_APPROVAL,
                    incident_id=incident.incident_id,
                    episode_id=episode.episode_id,
                    attempt_ids=tuple(attempt_ids),
                    active_function_version=target.slot.load().number,
                )

            target.slot.abandon_repair(lease)
            proposal_only = any(item.report.proposal_only for item in evaluated)
            episode = replace(
                episode,
                completed_at=utcnow(),
                outcome=RepairEpisodeOutcome.NO_ACCEPTABLE_CANDIDATE,
                summary=(
                    "Candidate retained as proposal only because the required validation isolation backend is unavailable."
                    if proposal_only
                    else "No candidate passed validation and scoring thresholds."
                ),
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.REPAIR_FAILED,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
                attempt_ids=tuple(attempt_ids),
                active_function_version=target.slot.load().number,
            )

        selected_attempt = next(
            attempt for attempt in self._attempt_records(attempt_ids)
            if attempt.candidate_id == selected.candidate.candidate_id
        )
        source = selected.candidate.artifact.files[0].content
        current_logging_runtime = get_logging_runtime()
        current_logging_generation = current_logging_runtime.effective.generation if current_logging_runtime is not None else None
        current_authority_policy = get_authority_runtime_context().effective
        if (
            current_authority_policy.generation != authority_policy_generation
            or current_authority_policy.fingerprint != authority_policy_fingerprint
        ):
            target.slot.abandon_repair(lease)
            selected_attempt = replace(
                selected_attempt, completed_at=utcnow(), stage=RepairAttemptStage.COMPLETE,
                outcome=RepairAttemptOutcome.STALE_POLICY,
            )
            self.store.record_attempt(selected_attempt)
            self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
            episode = replace(
                episode, completed_at=utcnow(), outcome=RepairEpisodeOutcome.STALE_POLICY,
                selected_candidate_id=selected.candidate.candidate_id,
                selected_attempt_id=selected_attempt.attempt_id,
                summary="Authority policy changed during repair; candidate revalidation is required.",
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.STALE_POLICY, incident_id=incident.incident_id,
                episode_id=episode.episode_id, attempt_ids=tuple(attempt_ids),
                active_function_version=target.slot.load().number,
            )
        if current_logging_generation != logging_policy_generation:
            target.slot.abandon_repair(lease)
            selected_attempt = replace(
                selected_attempt, completed_at=utcnow(), stage=RepairAttemptStage.COMPLETE,
                outcome=RepairAttemptOutcome.STALE_POLICY,
            )
            self.store.record_attempt(selected_attempt)
            self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
            episode = replace(
                episode, completed_at=utcnow(), outcome=RepairEpisodeOutcome.STALE_POLICY,
                selected_candidate_id=selected.candidate.candidate_id,
                selected_attempt_id=selected_attempt.attempt_id,
                summary="Effective logging policy changed during repair; revalidation and explicit review are required.",
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.STALE_POLICY, incident_id=incident.incident_id,
                episode_id=episode.episode_id, attempt_ids=tuple(attempt_ids),
                active_function_version=target.slot.load().number,
            )
        if target.policy.authority is not RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS:
            target.slot.abandon_repair(lease)
            pending = PendingRepairApproval(
                episode_id=episode.episode_id, target_id=target.target_id,
                candidate_id=selected.candidate.candidate_id,
                attempt_id=selected_attempt.attempt_id, source=source,
                artifact_hash=selected.candidate.artifact.artifact_hash,
                expected_function_version=version.number,
                logging_policy_generation=logging_policy_generation,
                authority_policy_generation=authority_policy_generation,
                authority_policy_fingerprint=authority_policy_fingerprint,
                reason=f"Repair authority is {target.policy.authority.name}",
            )
            self._pending_approvals[episode.episode_id] = pending
            selected_attempt = replace(
                selected_attempt, completed_at=utcnow(), stage=RepairAttemptStage.COMPLETE,
                outcome=RepairAttemptOutcome.AWAITING_APPROVAL,
            )
            self.store.record_attempt(selected_attempt)
            self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
            episode = replace(
                episode, completed_at=utcnow(), outcome=RepairEpisodeOutcome.AWAITING_APPROVAL,
                selected_candidate_id=selected.candidate.candidate_id,
                selected_attempt_id=selected_attempt.attempt_id,
                summary="Validated repair is awaiting operator approval and has not been deployed.",
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.AWAITING_APPROVAL, incident_id=incident.incident_id,
                episode_id=episode.episode_id, attempt_ids=tuple(attempt_ids),
                active_function_version=target.slot.load().number,
            )
        try:
            implementation = self._compile_for_activation(source, target, version)
            activated = target.slot.activate(
                lease=lease,
                implementation=implementation,
                source=source,
                source_hash=selected.candidate.artifact.artifact_hash,
                repair_attempt_id=selected_attempt.attempt_id,
                candidate_id=selected.candidate.candidate_id,
            )
        except (SlotConflictError, Exception) as exc:
            try:
                target.slot.abandon_repair(lease)
            except Exception:
                pass
            selected_attempt = replace(
                selected_attempt,
                completed_at=utcnow(),
                stage=RepairAttemptStage.COMPLETE,
                outcome=RepairAttemptOutcome.ACTIVATION_FAILED,
                activation=ActivationResult(
                    attempted=True,
                    succeeded=False,
                    previous_version=version.number,
                    activated_version=None,
                    error=f"{type(exc).__name__}: {exc}",
                ),
            )
            self.store.record_attempt(selected_attempt)
            self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
            return RepairResolution(
                kind=ResolutionKind.REPAIR_FAILED,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
                attempt_ids=tuple(attempt_ids),
                active_function_version=target.slot.load().number,
            )

        if self.guard is not None and target.policy.guard.enabled:
            self.guard.seal_behavior_snapshot(target.target_id, reason="repair-activated")

        selected_attempt = replace(
            selected_attempt,
            stage=RepairAttemptStage.RETRY,
            activation=ActivationResult(
                attempted=True,
                succeeded=True,
                previous_version=version.number,
                activated_version=activated.number,
                activated_at=utcnow(),
            ),
        )
        self.store.record_attempt(selected_attempt)
        self._attempt_cache[selected_attempt.attempt_id] = selected_attempt

        if target.policy.retry.max_attempts <= 0:
            selected_attempt = replace(
                selected_attempt,
                completed_at=utcnow(),
                stage=RepairAttemptStage.COMPLETE,
                outcome=RepairAttemptOutcome.SUCCEEDED,
                retry=RetryResult(
                    attempted=False,
                    permitted=False,
                    state_restore_required=target.policy.state.restore_before_retry,
                    state_restore_succeeded=None,
                    succeeded=None,
                    elapsed_seconds=None,
                ),
            )
            self.store.record_attempt(selected_attempt)
            self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
            episode = replace(
                episode,
                completed_at=utcnow(),
                outcome=RepairEpisodeOutcome.REPAIRED_NOT_RETRIED,
                selected_candidate_id=selected.candidate.candidate_id,
                selected_attempt_id=selected_attempt.attempt_id,
                final_function_version=activated.number,
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.REPAIRED_NOT_RETRIED,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
                attempt_ids=tuple(attempt_ids),
                active_function_version=activated.number,
            )

        failure_summaries: list[str] = []
        final_exception: BaseException | None = None
        successful_output: Any = None
        successful_elapsed: float | None = None
        restored_for_success = False
        contract_validated = False
        contract_failure_reason: str | None = None
        attempts_made = 0

        for retry_number in range(1, target.policy.retry.max_attempts + 1):
            if retry_number > 1 and target.policy.retry.backoff_seconds > 0:
                time.sleep(target.policy.retry.backoff_seconds)
            retry_args, retry_kwargs, restored, restore_errors = self.state_capture.retry_arguments(
                args,
                kwargs,
                call_state.runtime_snapshot,
                target.policy.state,
            )
            live_restore_errors = self.state_capture.restore_live_environment(
                function,
                args,
                call_state.runtime_snapshot,
                target.policy.state,
            )
            restored = restored and not live_restore_errors
            if target.policy.retry.require_successful_state_restore and not restored:
                final_exception = RuntimeError(
                    "State restoration failed: "
                    + "; ".join(restore_errors + live_restore_errors)
                )
                failure_summaries.append(str(final_exception))
                break

            attempts_made += 1
            retry_started = time.perf_counter()
            if self.guard is not None and target.policy.guard.enabled:
                self.guard.before_call(
                    target.target_id,
                    activated.implementation,
                    incident.call_id,
                    candidate_id=selected.candidate.candidate_id,
                )
            try:
                output = activated.implementation(*retry_args, **retry_kwargs)
            except BaseException as retry_exception:
                if self.guard is not None and target.policy.guard.enabled:
                    self.guard.after_call(
                        target.target_id,
                        activated.implementation,
                        incident.call_id,
                        candidate_id=selected.candidate.candidate_id,
                        succeeded=False,
                        elapsed_seconds=time.perf_counter() - retry_started,
                    )
                elapsed = time.perf_counter() - retry_started
                final_exception = retry_exception
                summary = (
                    f"retry {retry_number} raised {type(retry_exception).__name__}: "
                    f"{retry_exception}"
                )
                failure_summaries.append(summary)
                self.store.append_event(
                    RepairEvent.create(
                        "repair.retry_failed",
                        target.target_id,
                        incident_id=incident.incident_id,
                        episode_id=episode.episode_id,
                        attempt_id=selected_attempt.attempt_id,
                        candidate_id=selected.candidate.candidate_id,
                        details={
                            "retry_number": retry_number,
                            "elapsed_seconds": elapsed,
                            "exception": summary,
                        },
                    )
                )
                if (
                    target.policy.retry.retry_original_exception_only
                    and incident.trigger is TriggerKind.EXCEPTION
                    and type(retry_exception) is not type(original_exception)
                ):
                    failure_summaries.append(
                        "retry loop stopped because the exception type changed from "
                        f"{type(original_exception).__name__} to {type(retry_exception).__name__}"
                    )
                    break
                continue

            elapsed = time.perf_counter() - retry_started
            if self.guard is not None and target.policy.guard.enabled:
                self.guard.after_call(
                    target.target_id,
                    activated.implementation,
                    incident.call_id,
                    candidate_id=selected.candidate.candidate_id,
                    succeeded=True,
                    elapsed_seconds=elapsed,
                )
                close_window = getattr(self.guard, "close_target_window", None)
                if close_window is not None:
                    close_window(target.target_id)
                if (
                    target.policy.guard.monitor_during_probation
                    and self.guard.candidate_deviated(selected.candidate.candidate_id)
                ):
                    contract_failure_reason = "Guard detected significant behavioral deviation during candidate probation"
                    final_exception = RuntimeError(contract_failure_reason)
                    failure_summaries.append(contract_failure_reason)
                    break
            contract = self._validate_retry_contract(
                target=target,
                incident=incident,
                output=output,
                elapsed_seconds=elapsed,
            )
            contract_validated = contract.valid
            if not contract.valid:
                contract_failure_reason = contract.reason or "post-repair contract failed"
                final_exception = RuntimeError(contract_failure_reason)
                failure_summaries.append(
                    f"retry {retry_number} returned but failed contract validation: "
                    f"{contract_failure_reason}"
                )
                self.store.append_event(
                    RepairEvent.create(
                        "repair.retry_contract_failed",
                        target.target_id,
                        incident_id=incident.incident_id,
                        episode_id=episode.episode_id,
                        attempt_id=selected_attempt.attempt_id,
                        candidate_id=selected.candidate.candidate_id,
                        details={
                            "retry_number": retry_number,
                            "elapsed_seconds": elapsed,
                            "reason": contract_failure_reason,
                            "evidence": dict(contract.evidence),
                        },
                    )
                )
                continue

            successful_output = output
            successful_elapsed = elapsed
            restored_for_success = restored
            final_exception = None
            break

        if final_exception is not None or successful_elapsed is None:
            if target.policy.activation.rollback_on_retry_failure and target.slot.load().number == activated.number:
                target.slot.rollback(activated.number)
            selected_attempt = replace(
                selected_attempt,
                completed_at=utcnow(),
                stage=RepairAttemptStage.COMPLETE,
                outcome=RepairAttemptOutcome.RETRY_FAILED,
                retry=RetryResult(
                    attempted=attempts_made > 0,
                    permitted=True,
                    state_restore_required=target.policy.state.restore_before_retry,
                    state_restore_succeeded=(False if attempts_made == 0 else None),
                    succeeded=False,
                    elapsed_seconds=None,
                    exception_type=type(final_exception).__name__ if final_exception else "ContractValidationError",
                    exception_message=str(final_exception or contract_failure_reason or "retry failed"),
                    attempts_made=attempts_made,
                    failure_summaries=tuple(failure_summaries),
                    contract_validated=contract_validated,
                    contract_failure_reason=contract_failure_reason,
                ),
                rollback_performed=target.policy.activation.rollback_on_retry_failure,
                rollback_reason="retry or post-repair contract validation failed",
            )
            self.store.record_attempt(selected_attempt)
            self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
            episode = replace(
                episode,
                completed_at=utcnow(),
                outcome=RepairEpisodeOutcome.RETRY_FAILED,
                selected_candidate_id=selected.candidate.candidate_id,
                selected_attempt_id=selected_attempt.attempt_id,
                final_function_version=target.slot.load().number,
                summary="; ".join(failure_summaries[-3:]),
            )
            self.store.record_episode(episode)
            return RepairResolution(
                kind=ResolutionKind.RETRY_FAILED,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
                attempt_ids=tuple(attempt_ids),
                active_function_version=target.slot.load().number,
                retry_exception=final_exception,
            )

        output = successful_output
        elapsed = successful_elapsed
        self.observation.record_success(
            slot=target.slot,
            call_id=incident.call_id,
            policy=target.policy.observation,
            output=output,
            mode="repair-retry",
        )
        if target.policy.retry.safety in {ReplaySafety.PURE, ReplaySafety.IDEMPOTENT}:
            regression_case = self.regression.add_successful_replay(
                target_id=target.target_id,
                args=retry_args,
                kwargs=retry_kwargs,
                expected=output,
                incident_id=incident.incident_id,
                candidate_id=selected.candidate.candidate_id,
                source_function_version=activated.number,
                source_function_hash=activated.source_hash,
                replay_safety=target.policy.retry.safety.name,
            )
            if regression_case is not None:
                self.store.append_event(
                    RepairEvent.create(
                        "regression.case_added",
                        target.target_id,
                        incident_id=incident.incident_id,
                        episode_id=episode.episode_id,
                        candidate_id=selected.candidate.candidate_id,
                        details={
                            "case_id": str(regression_case.case_id),
                            "name": regression_case.name,
                            "persistent_fixture_id": self.regression.last_persistent_fixture_id,
                            "persistent_fixture_status": (
                                "PERSISTED_DATA_ONLY"
                                if self.regression.last_persistent_fixture_id
                                else "NOT_PERSISTED"
                            ),
                        },
                    )
                )
        selected_attempt = replace(
            selected_attempt,
            completed_at=utcnow(),
            stage=RepairAttemptStage.COMPLETE,
            outcome=RepairAttemptOutcome.SUCCEEDED,
            retry=RetryResult(
                attempted=True,
                permitted=True,
                state_restore_required=target.policy.state.restore_before_retry,
                state_restore_succeeded=restored_for_success,
                succeeded=True,
                elapsed_seconds=elapsed,
                output_snapshot=value_snapshot(output),
                attempts_made=attempts_made,
                failure_summaries=tuple(failure_summaries),
                contract_validated=True,
            ),
        )
        self.store.record_attempt(selected_attempt)
        self._attempt_cache[selected_attempt.attempt_id] = selected_attempt
        episode = replace(
            episode,
            completed_at=utcnow(),
            outcome=RepairEpisodeOutcome.REPAIRED,
            selected_candidate_id=selected.candidate.candidate_id,
            selected_attempt_id=selected_attempt.attempt_id,
            final_function_version=activated.number,
        )
        self.store.record_episode(episode)
        self.store.append_event(
            RepairEvent.create(
                "repair.retry_succeeded",
                target.target_id,
                incident_id=incident.incident_id,
                episode_id=episode.episode_id,
                attempt_id=selected_attempt.attempt_id,
                candidate_id=selected.candidate.candidate_id,
                details={
                    "version": activated.number,
                    "score": selected.score.total_score,
                    "attempts_made": attempts_made,
                    "contract_validated": True,
                },
            )
        )
        return RepairResolution(
            kind=ResolutionKind.RETRY_SUCCEEDED,
            incident_id=incident.incident_id,
            episode_id=episode.episode_id,
            attempt_ids=tuple(attempt_ids),
            active_function_version=activated.number,
            retry_output=output,
        )

    def _record_batch(
        self,
        *,
        batch: CandidateBatch,
        episode: RepairEpisode,
        incident: Incident,
        target: RepairTarget,
        version: FunctionVersion,
        generator_kind: CandidateGeneratorKind,
        parent_ids: tuple[UUID, ...] = (),
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> tuple[CandidateGeneration, list[tuple[RepairCandidate, CandidateProposal]]]:
        generation_id = uuid4()
        candidates: list[tuple[RepairCandidate, CandidateProposal]] = []
        for proposal in batch.candidates[: target.policy.limits.maximum_candidates_per_incident]:
            source = textwrap.dedent(proposal.source).strip() + "\n"
            source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
            candidate_id = uuid4()
            artifact = RepairArtifact(
                kind=RepairArtifactKind.FUNCTION_REPLACEMENT,
                files=(
                    ArtifactFile(
                        relative_path="__candidate__.py",
                        operation="replace-function",
                        content=source,
                        content_hash=source_hash,
                    ),
                ),
                entrypoint=target.display_name.split(".")[-1],
                artifact_hash=source_hash,
            )
            candidate = RepairCandidate(
                candidate_id=candidate_id,
                generation_id=generation_id,
                episode_id=episode.episode_id,
                incident_id=incident.incident_id,
                target_id=target.target_id,
                created_at=utcnow(),
                base_function_version=version.number,
                base_source_hash=version.source_hash,
                artifact=artifact,
                explanation=proposal.explanation,
                assumptions=proposal.assumptions,
                generated_tests=tuple(
                    GeneratedTest(
                        name=f"generated-test-{index}",
                        source=test_source,
                    )
                    for index, test_source in enumerate(proposal.generated_tests, start=1)
                ),
                generator_kind=generator_kind,
                generator_name=proposal.generator_name,
                provider_name=batch.provider_name,
                model_name=batch.model_name,
                authority_policy_generation=incident.authority_policy_generation,
                authority_policy_fingerprint=incident.authority_policy_fingerprint,
                lineage=(
                    CandidateLineage(
                        parent_candidate_ids=parent_ids,
                        mechanism="candidate-consolidation",
                        generation_id=generation_id,
                    )
                    if parent_ids
                    else None
                ),
            )
            self.store.record_candidate(candidate)
            candidates.append((candidate, proposal))
        generation = CandidateGeneration(
            generation_id=generation_id,
            episode_id=episode.episode_id,
            incident_id=incident.incident_id,
            target_id=target.target_id,
            generator_kind=generator_kind,
            generator_name=batch.provider_name,
            provider_name=batch.provider_name,
            model_name=batch.model_name,
            started_at=started_at or utcnow(),
            completed_at=completed_at or utcnow(),
            outcome=(
                CandidateGenerationOutcome.SUCCEEDED
                if candidates
                else CandidateGenerationOutcome.NO_CANDIDATES
            ),
            prompt_version=batch.prompt_version,
            prompt_hash=hashlib.sha256(batch.prompt_text.encode("utf-8")).hexdigest(),
            candidate_ids=tuple(candidate.candidate_id for candidate, _ in candidates),
        )
        self.store.record_generation(generation)
        return generation, candidates

    def _evaluate_candidate(
        self,
        *,
        candidate: RepairCandidate,
        target: RepairTarget,
        episode: RepairEpisode,
        incident: Incident,
        policy_snapshot: Any,
        attempt_number: int,
        validation_state_restore_errors: tuple[str, ...] = (),
    ) -> tuple[EvaluatedCandidate, RepairAttempt]:
        attempt = RepairAttempt(
            attempt_id=uuid4(),
            episode_id=episode.episode_id,
            incident_id=incident.incident_id,
            candidate_id=candidate.candidate_id,
            target_id=target.target_id,
            attempt_number=attempt_number,
            created_at=utcnow(),
            completed_at=None,
            policy_snapshot_id=policy_snapshot.policy_snapshot_id,
            validation_profile_id=target.policy.validation.profile_id,
            base_function_version=candidate.base_function_version,
            base_source_hash=candidate.base_source_hash,
            stage=RepairAttemptStage.VALIDATION,
            outcome=RepairAttemptOutcome.PENDING,
            authority_policy_generation=incident.authority_policy_generation,
            authority_policy_fingerprint=incident.authority_policy_fingerprint,
        )
        self.store.record_attempt(attempt)
        self._attempt_cache[attempt.attempt_id] = attempt
        validation_backend = self.validation_registry.select(
            target.policy.validation.minimum_isolation
        )
        validation_capabilities = validation_backend.capabilities()
        with self._activity_lock:
            self._active_validations[attempt.attempt_id] = {
                "attempt_id": str(attempt.attempt_id),
                "candidate_id": str(candidate.candidate_id),
                "episode_id": str(episode.episode_id),
                "incident_id": str(incident.incident_id),
                "target_id": target.target_id,
                "started_at": attempt.created_at.isoformat(),
                "validation_backend": validation_capabilities.name,
                "validation_isolation": validation_capabilities.isolation_level.name,
                "validation_separate_kernel": validation_capabilities.separate_kernel,
                "authority_policy_generation": get_authority_runtime_context().effective.generation,
                "authority_policy_fingerprint": get_authority_runtime_context().effective.fingerprint,
            }
        tokens = set_runtime_context(attempt_id=attempt.attempt_id, candidate_id=candidate.candidate_id, operation="candidate-validation")
        try:
            report = validation_backend.validate_candidate(
                candidate,
                target,
                timeout_seconds=target.policy.validation.validation_timeout_seconds,
                regression_cases=self.regression.registered_cases_for_target(target.target_id),
            )
            if validation_state_restore_errors:
                now = utcnow()
                restore_summary = (
                    "Validation state restoration failed: "
                    + "; ".join(validation_state_restore_errors)
                )
                report = replace(
                    report,
                    eligible=False,
                    checks=report.checks + (
                        ValidationCheckResult(
                            kind=ValidationCheckKind.STATIC_POLICY,
                            outcome=CheckOutcome.FAILED,
                            started_at=now,
                            finished_at=now,
                            summary=restore_summary,
                        ),
                    ),
                    hard_disqualifications=report.hard_disqualifications + (restore_summary,),
                )
            can_activate, activation_reason = target.slot.can_activate_source(
                candidate.artifact.artifact_hash,
                prevent_failed_reactivation=target.policy.stability.prevent_reactivation_of_failed_version,
                detect_oscillation=target.policy.stability.detect_oscillation,
                oscillation_window_versions=target.policy.stability.oscillation_window_versions,
            )
            if not can_activate:
                now = utcnow()
                report = replace(
                    report,
                    eligible=False,
                    checks=report.checks + (
                        ValidationCheckResult(
                            kind=ValidationCheckKind.STATIC_POLICY,
                            outcome=CheckOutcome.FAILED,
                            started_at=now,
                            finished_at=now,
                            summary=activation_reason or "candidate activation was rejected by stability policy",
                        ),
                    ),
                    hard_disqualifications=report.hard_disqualifications + (
                        activation_reason or "stability policy rejected candidate",
                    ),
                )
            if (
                self.guard is not None
                and target.policy.guard.enabled
                and target.policy.guard.validate_candidate_behavior
            ):
                behavior_score = self.guard.evaluate_candidate(
                    target.target_id,
                    candidate.artifact.files[0].content,
                    candidate_id=candidate.candidate_id,
                    policy=target.policy.candidate_guard,
                )
                now = utcnow()
                behavior_check = ValidationCheckResult(
                    kind=ValidationCheckKind.STATIC_POLICY,
                    outcome=(CheckOutcome.PASSED if behavior_score.eligible else CheckOutcome.FAILED),
                    started_at=now,
                    finished_at=now,
                    summary=(
                        "Guard candidate behavior is compatible with the observed baseline"
                        if behavior_score.eligible
                        else "; ".join(behavior_score.rejection_reasons)
                    ),
                    details={
                        "baseline_compatibility": behavior_score.baseline_compatibility,
                        "new_capability_risk": behavior_score.new_capability_risk,
                        "detected_capabilities": list(behavior_score.detected_capabilities),
                    },
                )
                report = replace(
                    report,
                    eligible=report.eligible and behavior_score.eligible,
                    checks=report.checks + (behavior_check,),
                    hard_disqualifications=(
                        report.hard_disqualifications + behavior_score.rejection_reasons
                    ),
                    risk_findings=(
                        report.risk_findings
                        + tuple(
                            f"Guard detected candidate capability: {item}"
                            for item in behavior_score.detected_capabilities
                        )
                    ),
                )
            score = self.scorer.score(candidate, report, target.policy)
            attempt = replace(
                attempt,
                stage=RepairAttemptStage.SCORING,
                validation_results=report.checks,
                validation_backend_name=report.backend_name,
                validation_isolation_level=report.isolation_level,
                validation_backend_details=dict(report.backend_details or {}),
                score_card=score,
                outcome=(
                    RepairAttemptOutcome.PENDING
                    if score.eligible
                    else RepairAttemptOutcome.VALIDATION_FAILED
                ),
            )
            self.store.record_attempt(attempt)
            self._attempt_cache[attempt.attempt_id] = attempt
            if report.eligible:
                self.store.record_candidate(replace(candidate, state=CandidateState.SANDBOX_VALIDATED))
            return EvaluatedCandidate(candidate=candidate, report=report, score=score), attempt
        finally:
            with self._activity_lock:
                self._active_validations.pop(attempt.attempt_id, None)
            tokens.reset()

    def _attempt_records(self, attempt_ids: list[UUID]) -> list[RepairAttempt]:
        return [self._attempt_cache[attempt_id] for attempt_id in attempt_ids]

    def _compile_for_activation(
        self,
        source: str,
        target: RepairTarget,
        version: FunctionVersion,
    ) -> Any:
        tree = sanitized_function_tree(source)
        namespace = dict(version.implementation.__globals__)
        exec(
            compile(tree, "<caretaker-activated-candidate>", "exec", dont_inherit=True),
            namespace,
            namespace,
        )
        temporary = namespace[target.display_name.split(".")[-1]]
        implementation = types.FunctionType(
            temporary.__code__,
            version.implementation.__globals__,
            name=temporary.__name__,
            argdefs=temporary.__defaults__,
            closure=None,
        )
        implementation.__kwdefaults__ = temporary.__kwdefaults__
        implementation.__annotations__ = dict(getattr(version.implementation, "__annotations__", {}))
        implementation.__doc__ = temporary.__doc__
        implementation.__module__ = version.implementation.__module__
        implementation.__qualname__ = version.implementation.__qualname__
        return implementation

    def _build_request(
        self,
        target: RepairTarget,
        version: FunctionVersion,
        incident: Incident,
        policy_summary: str,
    ) -> RepairRequest:
        failure = incident.failure
        context_policy = target.policy.context
        traceback_summary = ""
        if context_policy.include_traceback and hasattr(failure, "traceback"):
            traceback_lines: list[str] = []
            for frame in failure.traceback:
                line = (
                    f"{frame.filename}:{frame.line_number} in {frame.function_name}: "
                    f"{frame.source_line or ''}"
                )
                if context_policy.send_local_values and frame.locals:
                    local_summary = ", ".join(
                        f"{name}={value.representation}"
                        for name, value in sorted(frame.locals.items())
                    )
                    line += f"\n  locals: {local_summary}"
                traceback_lines.append(line)
            traceback_summary = "\n".join(traceback_lines)
        elif not context_policy.include_traceback:
            traceback_summary = "Traceback omitted by repair context policy."

        if context_policy.include_state_diff:
            state_summary = "\n".join(
                f"{item.path}: {item.before.representation if item.before else '<missing>'} -> "
                f"{item.after.representation if item.after else '<missing>'}"
                for item in incident.state_differences
            ) or "No captured state changes."
        else:
            state_summary = "State differences omitted by repair context policy."
        all_cases = target.registered_cases + self.regression.registered_cases_for_target(target.target_id)
        if context_policy.send_argument_values:
            cases = "\n".join(
                f"- {case.name}: args={case.args!r}, kwargs={dict(case.kwargs)!r}, "
                f"expected={case.expected!r}, expected_exception={case.expected_exception!r}"
                for case in all_cases
            ) or "No registered or regression cases."
        else:
            cases = "\n".join(
                f"- {case.name}: input/output values omitted; "
                f"expected_exception={case.expected_exception!r}"
                for case in all_cases
            ) or "No registered or regression cases."
        log_records = tuple(incident.logs)[-max(0, context_policy.maximum_log_records):]
        logs_summary = "\n".join(
            f"{record.timestamp.isoformat()} {record.level} {record.logger_name}: "
            f"{self._redact_log_message(record.message)}"
            for record in log_records
        ) or "No correlated logs."
        logs_summary = logs_summary[: target.policy.context.maximum_context_characters]
        incident_summary = f"Trigger: {incident.trigger.name}\nFailure type: {type(failure).__name__}"
        if context_policy.send_argument_values:
            arguments = ", ".join(
                f"{name}={value.representation}"
                for name, value in sorted(incident.call.bound_arguments.items())
            )
            incident_summary += f"\nCall arguments: {arguments or '<none>'}"
            failure_arguments = getattr(failure, "arguments", ())
            if failure_arguments:
                incident_summary += "\nException arguments: " + ", ".join(
                    item.representation for item in failure_arguments
                )
        else:
            exception_type = getattr(failure, "exception_type", None)
            if exception_type:
                incident_summary += f"\nException: {exception_type}"
        if incident.metadata:
            if context_policy.send_argument_values:
                incident_summary += f"\nAdditional evidence: {incident.metadata!r}"
            else:
                incident_summary += (
                    "\nAdditional evidence fields: "
                    + ", ".join(sorted(map(str, incident.metadata)))
                    + " (values omitted by repair context policy)"
                )
        guard_summary = "No Guard evidence."
        if (
            self.guard is not None
            and target.policy.guard.enabled
            and target.policy.guard.include_guard_context_in_repair
        ):
            bundle = self.guard.evidence_bundle(
                target.target_id,
                calls=target.policy.context.previous_calls,
            )
            if bundle is not None:
                guard_summary = (
                    f"Subject: {bundle.subject.logical_name}\n"
                    f"Baseline: {bundle.baseline_summary!r}\n"
                    f"Observed: {bundle.observation_summary!r}\n"
                    "Significant deviations:\n"
                    + (
                        "\n".join(
                            f"- {item.category.name}: {item.explanation} "
                            f"(significance={item.significance_score:.1f})"
                            for item in bundle.deviations
                        )
                        or "- none"
                    )
                )
        original_source = (
            version.source or inspect.getsource(version.implementation)
            if context_policy.include_source
            else "Source omitted by repair context policy."
        )
        context_values = {
            "original_source": original_source,
            "incident_summary": incident_summary,
            "traceback_summary": traceback_summary,
            "state_summary": state_summary,
            "policy_summary": policy_summary,
            "registered_cases_summary": cases,
            "logs_summary": logs_summary,
            "guard_summary": guard_summary,
        }
        total_characters = sum(len(value) for value in context_values.values())
        maximum_characters = context_policy.maximum_context_characters
        if total_characters > maximum_characters:
            scale = maximum_characters / total_characters
            bounded: dict[str, str] = {}
            remaining = maximum_characters
            keys = tuple(context_values)
            for index, key in enumerate(keys):
                value = context_values[key]
                if index == len(keys) - 1:
                    allowance = remaining
                else:
                    allowance = min(len(value), max(0, int(len(value) * scale)))
                    allowance = min(allowance, remaining)
                bounded[key] = value[:allowance]
                remaining -= allowance
            context_values = bounded

        return RepairRequest(
            target_id=target.target_id,
            function_name=target.display_name.split(".")[-1],
            module_name=target.source.module_name,
            original_source=context_values["original_source"],
            incident_summary=context_values["incident_summary"],
            traceback_summary=context_values["traceback_summary"],
            state_summary=context_values["state_summary"],
            policy_summary=context_values["policy_summary"],
            registered_cases_summary=context_values["registered_cases_summary"],
            logs_summary=context_values["logs_summary"],
            guard_summary=context_values["guard_summary"],
            maximum_candidates=min(
                target.policy.selection.maximum_candidates_to_evaluate,
                target.policy.limits.maximum_candidates_per_incident,
            ),
        )

    def _validate_retry_contract(
        self,
        *,
        target: RepairTarget,
        incident: Incident,
        output: Any,
        elapsed_seconds: float,
    ) -> ValidationResult:
        for trigger in target.policy.triggers:
            if isinstance(trigger, OutputValidationTrigger):
                validator = (
                    trigger.validator
                    if trigger.validator is not None
                    else self.resolve_validator(trigger.validator_id or "")
                )
                try:
                    result = normalize_validation_result(validator(output))
                except Exception as exc:
                    if trigger.on_validator_error.name == "FAIL_OPEN":
                        self.postmortem.capture(
                            exc,
                            component="output-validator",
                            operation=f"post-repair:{trigger.name}",
                        )
                        continue
                    return ValidationResult(
                        valid=False,
                        reason=(
                            f"validator {trigger.name} raised {type(exc).__name__}: {exc}"
                        ),
                    )
                if not result.valid:
                    return ValidationResult(
                        valid=False,
                        reason=(
                            result.reason
                            or f"output failed validator {trigger.name}"
                        ),
                        evidence=result.evidence,
                    )
            elif isinstance(trigger, TimeoutTrigger) and trigger.mode is TimeoutMode.SOFT:
                if elapsed_seconds > trigger.seconds:
                    return ValidationResult(
                        valid=False,
                        reason=(
                            f"repaired function exceeded soft timeout: "
                            f"{elapsed_seconds:.6f}s > {trigger.seconds:.6f}s"
                        ),
                        evidence={
                            "elapsed_seconds": elapsed_seconds,
                            "configured_seconds": trigger.seconds,
                        },
                    )
        return ValidationResult(valid=True)

    def _repair_allowed_by_limits(
        self,
        target: RepairTarget,
        incident: Incident,
    ) -> bool:
        occurred_at = incident.occurred_at
        key = (target.target_id, incident.fingerprint or "unknown")
        history = self._repair_history.setdefault(key, [])
        cutoff = occurred_at.timestamp() - max(0.0, target.policy.limits.cooldown_seconds)
        history[:] = [item for item in history if item.timestamp() >= cutoff]
        if history and target.policy.limits.cooldown_seconds > 0:
            return False
        attempts_for_target = getattr(self.store, "attempts_for_target", None)
        if callable(attempts_for_target):
            try:
                if len(attempts_for_target(target.target_id)) >= target.policy.limits.maximum_repairs_per_target:
                    return False
            except Exception:
                pass
        history.append(occurred_at)
        return True

    @staticmethod
    def _redact_log_message(message: str) -> str:
        patterns = (
            r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]+)",
            r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*",
        )
        redacted = message
        for pattern in patterns:
            redacted = re.sub(
                pattern,
                lambda match: (
                    f"{match.group(1)}=<redacted>"
                    if match.lastindex and match.lastindex >= 1 and not match.group(0).lower().startswith("bearer")
                    else "Bearer <redacted>"
                ),
                redacted,
            )
        return redacted

    @staticmethod
    def _fingerprint(
        target: RepairTarget,
        version: FunctionVersion,
        trigger: TriggerKind,
        failure: Any,
    ) -> str:
        payload = (
            target.target_id,
            version.number,
            trigger.name,
            type(failure).__name__,
            getattr(failure, "exception_type", None),
            getattr(failure, "message", None),
            getattr(failure, "reason", None),
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()
if TYPE_CHECKING:
    from .guard.facade import GuardFacade
    from .guard.models import BehaviorDeviation
