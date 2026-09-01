from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import importlib
import math
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .authority import (
    PolicyAuthoritySupervisor,
    PolicySetting,
)
from .capsule import IncidentCapsuleStore
from .capsule_assistance import assist_capsules
from .adaptive_aggregation import (
    SupervisorAdaptiveAggregationStore,
    compare_adaptive_populations,
    extended_aggregation_target_id,
    normalize_adaptive_observation_batch,
)
from .communications import (
    generate_communication_draft,
    review_communication_draft,
    tailor_communication_draft,
)
from .console_identity import ConsoleIdentityStore, normalize_console_public_identity
from .behavior import (
    BehaviorSnapshotStore,
    BehaviorStatisticsRepository,
    OllamaBehaviorSnapshotAnalyst,
    compare_snapshots,
    snapshot_payload,
    wrap_snapshot,
)
from .logging import (
    CaretakerApplicationSupervisor,
    EvidencePriority,
    LogChannel,
    LoggingMode,
    InterrogationRequest,
    LogInterrogator,
    OllamaRootCauseProvider,
    WorkerFailureAction,
    WorkerKind,
    WorkerState,
)
from .logging.handler import LoggingRuntime
from .logging.ipc import (
    ControlSocketServer,
    SocketLogServer,
    control_request,
    unix_socket_exists,
)
from .logging.policy import OperatorLoggingPolicy, load_operator_policy
from .logging.segments import read_segment
from .regression import RegressionFixtureStore
from .repair_recovery import worker_failure_recovery_status
from .repair_rollout import (
    RepairRolloutAuthority,
    RepairRolloutCoordinator,
    RepairRolloutError,
    RepairRolloutLedger,
    RepairRolloutStage,
)
from .replay import (
    IsolatedReplayCoordinator,
    RootlessPodmanReplayBackend,
    ReplayResultStore,
    execute_capsule_replay,
    execute_historical_capsule_replays,
)
from .integrity import SignatureVerificationMode, verify_release_publication
from .builtin_profiles import builtin_profile_names, load_builtin_profile_supervisor
from .system import SystemCollectionPolicy, SystemDataCollector, SystemOutputPolicy, load_system_policy
from .store import SQLiteRepairStore


_ADAPTIVE_THRESHOLD_SETTING_PATHS = {
    "exception.occurrences": "lightweight.exception.occurrences",
    "exception.window_seconds": "lightweight.exception.window_seconds",
    "soft_timing.occurrences": "lightweight.soft_timing.occurrences",
    "soft_timing.window_seconds": "lightweight.soft_timing.window_seconds",
    "repair_evidence.minimum_behavior_samples": (
        "lightweight.repair_evidence.minimum_behavior_samples"
    ),
    "repair_evidence.minimum_observation_calls": (
        "lightweight.repair_evidence.minimum_observation_calls"
    ),
    "repair_evidence.minimum_duration_seconds": (
        "lightweight.repair_evidence.minimum_duration_seconds"
    ),
    "repair_evidence.require_problem_reproduction": (
        "lightweight.repair_evidence.require_problem_reproduction"
    ),
    "transition_timeout_seconds": "lightweight.aggregation.transition_timeout_seconds",
}


_VALIDATION_AUDIT_SCOPE_FIELDS = frozenset({
    "target_id", "incident_id", "episode_id", "candidate_id", "attempt_id",
})
_VALIDATION_AUDIT_POLICY_FIELDS = frozenset({
    "policy_id", "fingerprint", "authority_policy_generation",
    "authority_policy_fingerprint",
})
_VALIDATION_AUDIT_OUTCOME_FIELDS = frozenset({
    "state", "eligible", "requires_operator_approval", "proposal_only",
    "total_score",
})
_VALIDATION_AUDIT_DETAIL_FIELDS = frozenset({
    "validation_backend", "validation_isolation", "backend_available",
    "check_count", "passed_check_count", "failed_check_count",
    "risk_finding_count", "hard_disqualification_count",
    "review_required_finding_count",
})
_ADAPTIVE_BACKPRESSURE_AUDIT_SCOPE_FIELDS = frozenset({
    "target_id", "aggregation_scope", "generation_id", "batch_id",
})
_ADAPTIVE_BACKPRESSURE_AUDIT_POLICY_FIELDS = frozenset({
    "fingerprint", "authority_generation", "authority_fingerprint",
})
_ADAPTIVE_BACKPRESSURE_AUDIT_OUTCOME_FIELDS = frozenset({
    "state", "incident_recorded", "authority_granted",
})
_ADAPTIVE_BACKPRESSURE_AUDIT_DETAIL_FIELDS = frozenset({
    "action", "pending_records", "sequence_start", "sequence_end",
    "incident_id", "error", "authority_granted",
})
_ADAPTIVE_BACKPRESSURE_INCIDENT_FIELDS = frozenset({
    "event", "action", "batch_id", "target_id", "aggregation_scope",
    "generation_id", "policy_fingerprint", "authority_policy_generation",
    "authority_policy_fingerprint", "pending_records", "sequence_start",
    "sequence_end", "error",
})


def _emit_adaptive_policy_transition_audit(
    runtime: Any,
    transition: Mapping[str, Any],
    *,
    state: str,
    actor_type: str,
    actor_id: str,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Record adaptive policy lineage without turning audit input into authority."""
    audit = getattr(runtime, "audit", None)
    emit = getattr(audit, "emit", None)
    if not callable(emit):
        return
    transition_id = str(
        transition.get("transition_id") or transition.get("request_id") or ""
    ).strip()
    if not transition_id:
        return
    policy: dict[str, Any] = {}
    for output_name, input_name in (
        ("policy_id", "policy_id"),
        ("prior_policy_id", "prior_policy_id"),
        ("fingerprint", "policy_fingerprint"),
        ("prior_fingerprint", "previous_policy_fingerprint"),
        ("authority_type", "authority_type"),
        ("authority_generation", "authority_policy_generation"),
        ("authority_fingerprint", "authority_policy_fingerprint"),
    ):
        value = transition.get(input_name)
        if value is not None:
            policy[output_name] = str(value)[:512]
    fields = transition.get("changes")
    if isinstance(fields, Mapping):
        policy["fields_affected"] = sorted(str(name)[:256] for name in fields)[:100]
    bounded_details = {
        str(name)[:128]: value
        for name, value in (details or {}).items()
        if isinstance(name, str)
    }
    emit(
        "ADAPTIVE_POLICY_TRANSITION",
        actor={"type": str(actor_type)[:32], "id": str(actor_id)[:128]},
        scope={
            "target_id": str(transition.get("target_id") or "")[:512] or None,
            "aggregation_scope": transition.get("aggregation_scope"),
            "transition_id": transition_id[:128],
        },
        policy=policy,
        outcome={
            "state": str(state).strip().upper()[:64],
            "policy_applied": bool(transition.get("policy_applied", False)),
            "authority_granted": False,
            "effective_at": transition.get("effective_at"),
        },
        details={
            **bounded_details,
            "record_id": str(transition.get("record_id") or "")[:128] or None,
            "proposal_request_id": str(transition.get("proposal_request_id") or "")[:128] or None,
            "authority_lease_id": str(transition.get("authority_lease_id") or "")[:128] or None,
            "signature_status": str(transition.get("signature_status") or "")[:64] or None,
            "authority_granted": False,
        },
        priority=EvidencePriority.CRITICAL,
    )


def _emit_communication_audit(
    runtime: Any,
    *,
    event_type: str,
    result: Mapping[str, Any],
    actor_id: str,
) -> None:
    """Record communication lifecycle evidence without authorizing delivery."""
    audit = getattr(runtime, "audit", None)
    emit = getattr(audit, "emit", None)
    if not callable(emit):
        return
    draft = result.get("draft") if isinstance(result.get("draft"), Mapping) else {}
    review = result.get("review") if isinstance(result.get("review"), Mapping) else {}
    review_metadata = review.get("metadata") if isinstance(review.get("metadata"), Mapping) else {}
    communication_id = str(
        review.get("communication_id")
        or draft.get("communication_id")
        or draft.get("draft_id")
        or result.get("draft_id")
        or ""
    ).strip()
    if not communication_id:
        return
    is_review = event_type == "INCIDENT_COMMUNICATION_REVIEWED"
    state = (
        str(review_metadata.get("review_decision") or review.get("status") or "REVIEWED")
        if is_review
        else "RECORDED"
        if str((result.get("recording") or {}).get("status") or "")
        in {"RECORDED", "ALREADY_RECORDED"}
        else "GENERATED"
    )
    source_incident_id = str(
        draft.get("source_incident_id")
        or result.get("source_incident_id")
        or ""
    ).strip()
    scope = {
        "communication_id": communication_id[:128],
        "draft_id": str(draft.get("draft_id") or "")[:128] or None,
        "incident_id": source_incident_id[:128] or None,
        "capsule_id": str(draft.get("source_capsule_id") or "")[:128] or None,
    }
    details = {
        "audience_profile_id": str(
            draft.get("audience_profile_id")
            or review.get("audience_profile_id")
            or ""
        )[:128]
        or None,
        "recording_status": str(
            (result.get("recording") or {}).get("status")
            or result.get("status")
            or ""
        )[:64]
        or None,
        "capsule_revision": draft.get("source_capsule_revision")
        or result.get("capsule_revision"),
        "content_sha256": str(
            (result.get("integrity") or {}).get("content_sha256")
            or review.get("content_sha256")
            or ""
        )[:128]
        or None,
        "review_reason": str(review_metadata.get("review_reason") or "")[:500] or None,
        "delivery_authorized": False,
    }
    emit(
        event_type,
        actor={"type": "operator" if is_review else "caretaker", "id": str(actor_id)[:128]},
        scope=scope,
        outcome={
            "state": state.upper()[:64],
            "delivery_authorized": False,
            "capsule_mutated": bool(result.get("capsule_mutated", False)),
        },
        details=details,
        priority=(
            EvidencePriority.CRITICAL
            if is_review
            else EvidencePriority.IMPORTANT
        ),
    )


def _emit_incident_replay_audit(
    runtime: Any,
    *,
    replay_scope: str,
    actor_id: str,
    request: Mapping[str, Any],
    result: Mapping[str, Any] | None = None,
    error: BaseException | str | None = None,
) -> None:
    """Record replay activity in the canonical, output-only audit stream.

    Replay is evidence production, not an authority operation. Keep the audit
    projection bounded and identity-focused; replay output remains in the
    response or the separately content-addressed replay-result store.
    """
    audit = getattr(runtime, "audit", None)
    emit = getattr(audit, "emit", None)
    if not callable(emit):
        return
    payload = result if isinstance(result, Mapping) else {}
    raw_results = payload.get("results")
    batch_results = raw_results if isinstance(raw_results, list) else []
    if error is not None:
        state = "REJECTED"
    elif replay_scope == "selected":
        state = str(payload.get("outcome") or "COMPLETED").strip().upper()
        if state not in {"PASSED", "FAILED", "ERROR", "COMPLETED"}:
            state = "COMPLETED"
    else:
        state = (
            "PARTIAL"
            if any(
                str(item.get("status") or "") != "COMPLETED"
                for item in batch_results
                if isinstance(item, Mapping)
            )
            else "COMPLETED"
        )
    scope = {
        "replay_scope": str(replay_scope)[:32],
        "capsule_id": payload.get("capsule_id") or request.get("capsule_id"),
        "incident_id": payload.get("incident_id") or request.get("incident_id"),
        "fixture_id": payload.get("fixture_id") or request.get("fixture_id"),
    }
    details: dict[str, Any] = {
        "non_interactive": replay_scope != "selected",
        "capsule_modified": False,
        "authority_granted": False,
    }
    for name in (
        "backend_name",
        "isolation_level",
        "fixture_count",
        "completed_count",
        "dispatched_count",
        "replay_status",
    ):
        if name in payload:
            details[name] = payload[name]
    if error is not None:
        details["error"] = str(error)[:500]
    emit(
        "INCIDENT_REPLAY_OUTCOME",
        actor={"type": "operator", "id": str(actor_id)[:128]},
        scope=scope,
        outcome={
            "state": state,
            "capsule_modified": False,
            "authority_granted": False,
            "integrity_verified": error is None,
        },
        details=details,
        priority=EvidencePriority.IMPORTANT,
    )


def _emit_adaptive_aggregation_audit(
    runtime: Any,
    result: Mapping[str, Any],
    *,
    actor_type: str = "supervisor",
    actor_id: str = "application-supervisor",
) -> None:
    """Record meaningful supervisor aggregation activity as audit evidence."""
    if not isinstance(result, Mapping):
        return
    promotions = result.get("promotions")
    promotion_count = (
        int(promotions.get("created") or 0)
        if isinstance(promotions, Mapping)
        else 0
    )
    counts = {
        name: int(result.get(name) or 0)
        for name in ("merged", "duplicates", "rejected", "conflicts", "conflict_reports")
    }
    errors = result.get("errors")
    error_count = len(errors) if isinstance(errors, list) else 0
    if not any((*counts.values(), promotion_count, error_count, int(result.get("pending") or 0))):
        return
    audit = getattr(runtime, "audit", None)
    emit = getattr(audit, "emit", None)
    if not callable(emit):
        return
    state = "RECONCILED" if not counts["rejected"] and not error_count else "PARTIAL"
    effective = getattr(runtime, "effective", None)
    emit(
        "ADAPTIVE_AGGREGATION_RECONCILED",
        actor={"type": str(actor_type)[:32], "id": str(actor_id)[:128]},
        scope={"aggregation_scope": "application"},
        policy={
            "fingerprint": getattr(effective, "fingerprint", None),
            "generation": getattr(effective, "generation", None),
        },
        outcome={
            "state": state,
            "authority_granted": False,
        },
        details={
            **counts,
            "error_count": error_count,
            "promotion_requests_created": promotion_count,
            "pending": int(result.get("pending") or 0),
            "authority_granted": False,
        },
        priority=EvidencePriority.IMPORTANT,
    )


def _emit_behavior_collection_audit(
    runtime: Any,
    *,
    request: Mapping[str, Any],
    capture: Mapping[str, Any] | None = None,
    result: Mapping[str, Any] | None = None,
    actor_id: str,
    actor_type: str = "operator",
    error: BaseException | str | None = None,
) -> None:
    """Record one supervisor-mediated behavior collection outcome.

    The application worker returns a bounded collection projection, but never
    submits an audit event. The supervisor constructs this evidence record and
    derives the actor from the authenticated control-socket peer. No snapshot
    payload or authority operation is included in the audit projection.
    """
    audit = getattr(runtime, "audit", None)
    emit = getattr(audit, "emit", None)
    if not callable(emit):
        return
    collection = capture.get("collection_request") if isinstance(capture, Mapping) else None
    collection = collection if isinstance(collection, Mapping) else {}
    scope = str(collection.get("scope") or request.get("scope") or "function").strip().lower()
    subject = str(collection.get("subject") or request.get("subject") or "").strip()
    if not subject:
        subject = "unknown"
    state = str(
        collection.get("outcome")
        or collection.get("status")
        or ("FAILED" if error is not None else "FAILED")
    ).strip().upper()
    if state not in {"CAPTURED", "FAILED", "CANCELLED", "DEFERRED"}:
        state = "FAILED"

    def bounded_text(value: Any, limit: int = 500) -> str | None:
        if value in (None, ""):
            return None
        return str(value)[:limit]

    def bounded_nonnegative_int(value: Any) -> int | None:
        if value in (None, "") or isinstance(value, bool):
            return None
        try:
            return max(0, min(int(value), 1000))
        except (TypeError, ValueError, OverflowError):
            return None

    details: dict[str, Any] = {
        "requested_by": bounded_text(
            collection.get("requested_by") or request.get("requested_by"), 128
        ),
        "reason": bounded_text(collection.get("reason") or request.get("reason")),
        "requested_calls": bounded_nonnegative_int(
            collection.get("requested_calls") or request.get("calls")
        ),
        "observed_calls": bounded_nonnegative_int(collection.get("observed_calls")),
        "requested_generation": bounded_text(collection.get("requested_generation"), 128),
        "observed_generation": bounded_text(collection.get("observed_generation"), 128),
        "snapshot_id": bounded_text(collection.get("snapshot_id"), 128),
        "duration_seconds": None,
        "authority_granted": False,
    }
    duration = collection.get("duration_seconds")
    if duration not in (None, "") and not isinstance(duration, bool):
        try:
            duration_value = float(duration)
        except (TypeError, ValueError, OverflowError):
            duration_value = None
        if duration_value is not None and math.isfinite(duration_value):
            details["duration_seconds"] = max(0.0, min(duration_value, 86_400.0))
    if error is not None:
        details["error"] = bounded_text(error)
    elif isinstance(result, Mapping) and result.get("ok") is False:
        raw_error = result.get("error")
        if isinstance(raw_error, Mapping):
            raw_error = raw_error.get("message") or raw_error.get("failure_kind")
        details["error"] = bounded_text(raw_error)
    details = {key: value for key, value in details.items() if value is not None}
    effective = getattr(runtime, "effective", None)
    emit(
        "BEHAVIOR_COLLECTION_OUTCOME",
        actor={"type": str(actor_type)[:32], "id": str(actor_id)[:128]},
        scope={
            "scope": scope[:32],
            "subject": subject[:500],
            "collection_request_id": bounded_text(collection.get("request_id"), 128),
        },
        policy={
            "fingerprint": getattr(effective, "fingerprint", None),
            "generation": getattr(effective, "generation", None),
        },
        outcome={
            "state": state,
            "authority_granted": False,
        },
        details=details,
        priority=EvidencePriority.IMPORTANT,
    )


def _handle_console_invocation_event(
    runtime: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    invocations: dict[str, int],
    identity_store: ConsoleIdentityStore | None = None,
) -> dict[str, Any]:
    """Record a console session lifecycle event without granting authority."""
    command = request.get("command")
    invocation_id = str(request.get("invocation_id") or "").strip()
    if not invocation_id:
        raise ValueError(f"{command} requires invocation_id")
    try:
        invocation_id = str(UUID(invocation_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("console invocation_id must be a UUID") from exc
    process_id = credentials[0]
    if process_id < 0:
        raise PermissionError("console peer process identity is unavailable")
    if command == "console-invocation-start":
        if invocation_id in invocations:
            raise ValueError("console invocation is already active")
        console_identity = normalize_console_public_identity(
            request.get("console_identity")
        )
        if identity_store is not None and console_identity is not None:
            identity_store.record_start(
                invocation_id,
                identity=console_identity,
                process_id=process_id,
                uid=credentials[1],
                gid=credentials[2],
            )
        event_type = "CONSOLE_INVOCATION_STARTED"
        outcome = {"state": "STARTED"}
    elif command == "console-invocation-end":
        if invocations.get(invocation_id) != process_id:
            raise PermissionError("console invocation is not owned by this process")
        console_identity = (
            identity_store.get(invocation_id) if identity_store is not None else None
        )
        if identity_store is not None and console_identity is not None:
            identity_store.record_end(invocation_id, process_id=process_id)
        event_type = "CONSOLE_INVOCATION_ENDED"
        outcome = {"state": "ENDED"}
    else:
        raise ValueError("unsupported console invocation command")
    reason = str(request.get("reason") or "operator_exit")[:256]
    identity_details = (
        {
            key: console_identity[key]
            for key in (
                "identity_id",
                "algorithm",
                "encoding",
                "public_key",
                "public_key_fingerprint",
            )
            if key in console_identity
        }
        if isinstance(console_identity, Mapping)
        else {"status": "UNAVAILABLE"}
    )
    audit_event = runtime.audit.emit(
        event_type,
        actor={"type": "operator", "id": f"uid:{credentials[1]}"},
        scope={
            "console_invocation_id": invocation_id,
            "process_id": process_id,
        },
        policy={
            "policy_id": str(runtime.snapshot.snapshot_id),
            "fingerprint": runtime.snapshot.content_hash,
            "authority_generation": runtime.effective.generation,
        },
        outcome=outcome,
        details={
            "uid": credentials[1],
            "gid": credentials[2],
            "reason": reason,
            "authority_granted": False,
            "console_identity": identity_details,
        },
        priority=(
            EvidencePriority.CRITICAL
            if event_type == "CONSOLE_INVOCATION_STARTED"
            else EvidencePriority.IMPORTANT
        ),
    )
    if event_type == "CONSOLE_INVOCATION_STARTED":
        invocations[invocation_id] = process_id
    else:
        invocations.pop(invocation_id, None)
    return {
        "ok": True,
        "recorded": audit_event is not None,
        "event_id": audit_event.get("event_id") if audit_event else None,
        "stream_sequence": audit_event.get("stream_sequence") if audit_event else None,
    }


def _handle_console_identity_request(
    identity_store: ConsoleIdentityStore,
    request: Mapping[str, Any],
) -> dict[str, Any]:
    """Return one recorded public console identity without private material."""
    invocation_id = str(request.get("invocation_id") or "").strip()
    if not invocation_id:
        raise ValueError("console-invocation-identity requires invocation_id")
    try:
        invocation_id = str(UUID(invocation_id))
    except (ValueError, AttributeError) as exc:
        raise ValueError("console invocation_id must be a UUID") from exc
    record = identity_store.get(invocation_id)
    if record is None:
        raise KeyError("console invocation identity was not found")
    public_fields = {
        key: record[key]
        for key in (
            "invocation_id",
            "identity_id",
            "public_key",
            "public_key_fingerprint",
            "algorithm",
            "encoding",
            "process_id",
            "uid",
            "gid",
            "started_at",
            "ended_at",
        )
        if key in record
    }
    return {"ok": True, "identity": public_fields, "authority_granted": False}


def _handle_rollout_advance_request(
    ledger: RepairRolloutLedger,
    coordinator: RepairRolloutCoordinator,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    *,
    policy_fingerprint: str,
    authority_fingerprint: str,
) -> dict[str, Any]:
    """Apply one explicitly confirmed operator rollout transition.

    The control socket authenticates the OS peer before calling this helper.
    Readiness is an evidence gate, not authority: an operator may explicitly
    override an unmet or unavailable readiness result, and that choice is
    retained in the returned transition context for the audit caller.
    """

    if request.get("confirm") is not True:
        raise PermissionError("repair-rollout-advance requires confirm=true")
    reason = str(request.get("reason") or "").strip()
    if not reason:
        raise ValueError("repair rollout advancement requires an operator reason")
    try:
        rollout_id = UUID(str(request["rollout_id"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("repair-rollout-advance requires a valid rollout_id") from exc
    try:
        to_stage = RepairRolloutStage(str(request["to_stage"]).strip().lower())
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("repair-rollout-advance requires a valid to_stage") from exc

    record = ledger.get(rollout_id)
    if record.stage is RepairRolloutStage.PROPOSED:
        raise PermissionError(
            "proposed rollouts must enter validated through the validation workflow"
        )
    readiness = coordinator.readiness(rollout_id)
    readiness_status = str(readiness.get("status") or "UNKNOWN")
    override_readiness = request.get("override_readiness") is True
    readiness_required = to_stage in {
        RepairRolloutStage.SHADOW,
        RepairRolloutStage.CANARY,
        RepairRolloutStage.ACTIVE,
    }
    if readiness_required and readiness_status in {
        "NOT_READY",
        "UNAVAILABLE",
        "STALE_OR_UNAVAILABLE",
    } and not override_readiness:
        raise PermissionError(
            "rollout readiness does not permit advancement; "
            "set override_readiness=true for an explicitly justified operator override"
        )

    raw_incident_id = str(request.get("incident_id") or "").strip()
    incident_id = None
    if raw_incident_id:
        try:
            incident_id = UUID(raw_incident_id)
        except ValueError as exc:
            raise ValueError("repair-rollout-advance incident_id must be a UUID") from exc
    updated = ledger.advance(
        rollout_id,
        to_stage=to_stage,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id=f"uid:{credentials[1]}",
        reason=reason,
        policy_fingerprint=policy_fingerprint,
        authority_fingerprint=authority_fingerprint,
        incident_id=incident_id,
    )
    transition = ledger.transitions(rollout_id)[-1]
    return {
        "ok": True,
        "read_only": False,
        "authority_granted": True,
        "readiness": readiness,
        "readiness_overridden": override_readiness,
        "record": json.loads(json.dumps(asdict(updated), default=str)),
        "transition": json.loads(json.dumps(asdict(transition), default=str)),
    }


def _handle_rollout_pause_request(
    ledger: RepairRolloutLedger,
    coordinator: RepairRolloutCoordinator,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    *,
    paused: bool,
    policy_fingerprint: str,
    authority_fingerprint: str,
) -> dict[str, Any]:
    """Apply one explicitly confirmed operator pause/resume control action."""

    command = "pause" if paused else "resume"
    if request.get("confirm") is not True:
        raise PermissionError(f"repair-rollout-{command} requires confirm=true")
    reason = str(request.get("reason") or "").strip()
    if not reason:
        raise ValueError(f"repair rollout {command} requires an operator reason")
    try:
        rollout_id = UUID(str(request["rollout_id"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            f"repair-rollout-{command} requires a valid rollout_id"
        ) from exc

    record = ledger.get(rollout_id)
    readiness = coordinator.readiness(rollout_id)
    override_readiness = request.get("override_readiness") is True
    if not paused and readiness.get("status") in {
        "NOT_READY",
        "UNAVAILABLE",
        "STALE_OR_UNAVAILABLE",
    } and not override_readiness:
        raise PermissionError(
            "rollout readiness does not permit resume; "
            "set override_readiness=true for an explicitly justified operator override"
        )

    operation = ledger.pause if paused else ledger.resume
    updated = operation(
        rollout_id,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id=f"uid:{credentials[1]}",
        reason=reason,
        policy_fingerprint=policy_fingerprint,
        authority_fingerprint=authority_fingerprint,
    )
    transition = ledger.transitions(rollout_id)[-1] if updated != record else None
    return {
        "ok": True,
        "read_only": False,
        "authority_granted": True,
        "action": command,
        "readiness": readiness,
        "readiness_overridden": override_readiness,
        "record": json.loads(json.dumps(asdict(updated), default=str)),
        "transition": (
            json.loads(json.dumps(asdict(transition), default=str))
            if transition is not None
            else None
        ),
    }


def _handle_rollout_percentage_request(
    ledger: RepairRolloutLedger,
    coordinator: RepairRolloutCoordinator,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    *,
    policy_fingerprint: str,
    authority_fingerprint: str,
) -> dict[str, Any]:
    """Apply one explicitly confirmed operator routing update."""

    if request.get("confirm") is not True:
        raise PermissionError("repair-rollout-routing-update requires confirm=true")
    reason = str(request.get("reason") or "").strip()
    if not reason:
        raise ValueError("repair rollout routing update requires an operator reason")
    try:
        rollout_id = UUID(str(request["rollout_id"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(
            "repair-rollout-routing-update requires a valid rollout_id"
        ) from exc

    percentages: dict[str, int] = {}
    for name in (
        "shadow_sample_percentage",
        "canary_percentage",
        "active_candidate_percentage",
    ):
        value = request.get(name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"repair-rollout-routing-update requires integer {name}"
            )
        percentages[name] = value

    record = ledger.get(rollout_id)
    readiness = coordinator.readiness(rollout_id)
    override_readiness = request.get("override_readiness") is True
    updated = ledger.update_routing_percentages(
        rollout_id,
        **percentages,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id=f"uid:{credentials[1]}",
        reason=reason,
        policy_fingerprint=policy_fingerprint,
        authority_fingerprint=authority_fingerprint,
        readiness_status=str(readiness.get("status") or ""),
        override_readiness=override_readiness,
    )
    transition = ledger.transitions(rollout_id)[-1] if updated != record else None
    return {
        "ok": True,
        "read_only": False,
        "authority_granted": True,
        "action": "routing-update",
        "readiness": readiness,
        "readiness_overridden": override_readiness,
        "record": json.loads(json.dumps(asdict(updated), default=str)),
        "transition": (
            json.loads(json.dumps(asdict(transition), default=str))
            if transition is not None
            else None
        ),
    }


def _handle_adaptive_observation_submission(
    store: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    child: Any,
) -> dict[str, Any]:
    """Accept one adaptive batch only from the live supervised application."""
    if child is None or child.poll() is not None:
        raise PermissionError("application worker is not running")
    if credentials[0] != child.pid:
        raise PermissionError(
            "adaptive observation submission is not from the application worker"
        )
    raw_batch = request.get("batch")
    if not isinstance(raw_batch, Mapping):
        raise ValueError("adaptive observation submission requires a batch object")
    batch = normalize_adaptive_observation_batch(raw_batch)
    if batch["worker_pid"] != credentials[0]:
        raise PermissionError(
            "adaptive observation worker_pid does not match the application peer"
        )
    result = store.submit(batch)
    return {
        "ok": True,
        "result": dict(result),
        "transport_peer_pid": credentials[0],
    }


def _bounded_validation_audit_fields(
    value: Any,
    *,
    allowed: frozenset[str],
    label: str,
    allow_none: bool = False,
) -> dict[str, Any]:
    """Validate the scalar, allow-listed shape accepted from an application worker."""
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{label} contains unsupported fields: {', '.join(sorted(map(str, unknown)))}")
    if len(value) > len(allowed):
        raise ValueError(f"{label} is too large")
    bounded: dict[str, Any] = {}
    for key, item in value.items():
        name = str(key)
        if item is None and allow_none:
            bounded[name] = None
        elif isinstance(item, str):
            if len(item) > 512:
                raise ValueError(f"{label}.{name} is too long")
            bounded[name] = item
        elif isinstance(item, bool):
            bounded[name] = item
        elif isinstance(item, int):
            if abs(item) > 2**63 - 1:
                raise ValueError(f"{label}.{name} is out of range")
            bounded[name] = item
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError(f"{label}.{name} must be finite")
            bounded[name] = item
        else:
            raise ValueError(f"{label}.{name} must be a scalar")
    return bounded


def _handle_validation_audit_submission(
    runtime: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    child: Any,
) -> dict[str, Any]:
    """Persist one application-worker validation decision on the supervisor."""
    if child is None or child.poll() is not None:
        raise PermissionError("application worker is not running")
    if credentials[0] != child.pid:
        raise PermissionError(
            "validation audit submission is not from the application worker"
        )
    scope = _bounded_validation_audit_fields(
        request.get("scope"),
        allowed=_VALIDATION_AUDIT_SCOPE_FIELDS,
        label="validation audit scope",
    )
    worker_policy = _bounded_validation_audit_fields(
        request.get("policy"),
        allowed=_VALIDATION_AUDIT_POLICY_FIELDS,
        label="validation audit policy",
    )
    outcome = _bounded_validation_audit_fields(
        request.get("outcome"),
        allowed=_VALIDATION_AUDIT_OUTCOME_FIELDS,
        label="validation audit outcome",
    )
    details = _bounded_validation_audit_fields(
        request.get("details"),
        allowed=_VALIDATION_AUDIT_DETAIL_FIELDS,
        label="validation audit details",
    )
    if not isinstance(scope.get("target_id"), str) or not scope["target_id"]:
        raise ValueError("validation audit scope requires a non-empty target_id")
    if not isinstance(scope.get("candidate_id"), str) or not scope["candidate_id"]:
        raise ValueError("validation audit scope requires target_id and candidate_id")
    if not isinstance(outcome.get("state"), str) or not outcome["state"]:
        raise ValueError("validation audit outcome requires a non-empty state")
    if not isinstance(outcome.get("eligible"), bool):
        raise ValueError("validation audit outcome requires state and eligible")
    if not isinstance(worker_policy.get("policy_id"), str) or not worker_policy["policy_id"]:
        raise ValueError("validation audit policy requires a non-empty policy_id")
    if not isinstance(worker_policy.get("fingerprint"), str) or not worker_policy["fingerprint"]:
        raise ValueError("validation audit policy requires policy_id and fingerprint")
    details.update({
        "reported_policy_id": worker_policy["policy_id"],
        "reported_policy_fingerprint": worker_policy["fingerprint"],
        "reported_authority_policy_generation": worker_policy.get(
            "authority_policy_generation"
        ),
        "reported_authority_policy_fingerprint": worker_policy.get(
            "authority_policy_fingerprint"
        ),
        "worker_pid": credentials[0],
    })
    audit_event = runtime.audit.emit(
        "VALIDATION_DECISION",
        actor={
            "type": "worker",
            "id": f"pid:{credentials[0]}",
            "uid": credentials[1],
        },
        scope=scope,
        policy={
            "policy_id": str(runtime.snapshot.snapshot_id),
            "fingerprint": runtime.snapshot.content_hash,
            "authority_generation": runtime.effective.generation,
        },
        outcome=outcome,
        details=details,
        priority=EvidencePriority.IMPORTANT,
    )
    return {
        "ok": True,
        "recorded": audit_event is not None,
        "event_id": audit_event.get("event_id") if audit_event else None,
        "stream_sequence": audit_event.get("stream_sequence") if audit_event else None,
    }


def _handle_adaptive_backpressure_audit_submission(
    runtime: Any,
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    child: Any,
) -> dict[str, Any]:
    """Persist one bounded adaptive backpressure event from the app child.

    The application may report what happened, but the supervisor owns the
    authenticated actor, current policy context, and critical priority. This
    is an output-only path: it records evidence and cannot mutate aggregation,
    policy, authority, or incident state.
    """
    if child is None or child.poll() is not None:
        raise PermissionError("application worker is not running")
    if credentials[0] != child.pid:
        raise PermissionError(
            "adaptive backpressure audit submission is not from the application worker"
        )
    scope = _bounded_validation_audit_fields(
        request.get("scope"),
        allowed=_ADAPTIVE_BACKPRESSURE_AUDIT_SCOPE_FIELDS,
        label="adaptive backpressure audit scope",
        allow_none=True,
    )
    worker_policy = _bounded_validation_audit_fields(
        request.get("policy"),
        allowed=_ADAPTIVE_BACKPRESSURE_AUDIT_POLICY_FIELDS,
        label="adaptive backpressure audit policy",
        allow_none=True,
    )
    outcome = _bounded_validation_audit_fields(
        request.get("outcome"),
        allowed=_ADAPTIVE_BACKPRESSURE_AUDIT_OUTCOME_FIELDS,
        label="adaptive backpressure audit outcome",
        allow_none=True,
    )
    details = _bounded_validation_audit_fields(
        request.get("details"),
        allowed=_ADAPTIVE_BACKPRESSURE_AUDIT_DETAIL_FIELDS,
        label="adaptive backpressure audit details",
        allow_none=True,
    )
    if not isinstance(scope.get("target_id"), str) or not scope["target_id"]:
        raise ValueError("adaptive backpressure audit scope requires target_id")
    if not isinstance(scope.get("batch_id"), str) or not scope["batch_id"]:
        raise ValueError("adaptive backpressure audit scope requires batch_id")
    if not isinstance(outcome.get("state"), str) or not outcome["state"]:
        raise ValueError("adaptive backpressure audit outcome requires state")
    if "incident_recorded" in outcome and not isinstance(
        outcome["incident_recorded"], bool
    ):
        raise ValueError(
            "adaptive backpressure audit outcome incident_recorded must be boolean"
        )
    if outcome.get("authority_granted") is not False:
        raise ValueError(
            "adaptive backpressure audit outcome cannot grant authority"
        )
    if "authority_granted" in details and details["authority_granted"] is not False:
        raise ValueError(
            "adaptive backpressure audit details cannot grant authority"
        )
    if not isinstance(details.get("action"), str) or not details["action"]:
        raise ValueError("adaptive backpressure audit details requires action")
    for field in ("pending_records", "sequence_start", "sequence_end"):
        value = details.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"adaptive backpressure audit details requires non-negative {field}"
            )
    if details["sequence_end"] < details["sequence_start"]:
        raise ValueError(
            "adaptive backpressure audit details sequence range is invalid"
        )
    for field in ("fingerprint", "authority_fingerprint"):
        if field in worker_policy and (
            not isinstance(worker_policy[field], str) or not worker_policy[field]
        ):
            raise ValueError(
                f"adaptive backpressure audit policy requires non-empty {field}"
            )
    if "authority_generation" in worker_policy:
        value = worker_policy["authority_generation"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                "adaptive backpressure audit policy authority_generation must be non-negative"
            )
    details.update({
        "reported_policy_fingerprint": worker_policy.get("fingerprint"),
        "reported_authority_generation": worker_policy.get("authority_generation"),
        "reported_authority_fingerprint": worker_policy.get("authority_fingerprint"),
        "worker_pid": credentials[0],
    })
    audit_event = runtime.audit.emit(
        "ADAPTIVE_AGGREGATION_BACKPRESSURE",
        actor={
            "type": "worker",
            "id": f"pid:{credentials[0]}",
            "uid": credentials[1],
        },
        scope=scope,
        policy={
            "policy_id": str(runtime.snapshot.snapshot_id),
            "fingerprint": runtime.snapshot.content_hash,
            "authority_generation": runtime.effective.generation,
        },
        outcome=outcome,
        details=details,
        priority=EvidencePriority.CRITICAL,
    )
    return {
        "ok": True,
        "recorded": audit_event is not None,
        "event_id": audit_event.get("event_id") if audit_event else None,
        "stream_sequence": audit_event.get("stream_sequence") if audit_event else None,
    }


def _handle_adaptive_backpressure_incident_submission(
    runtime: Any,
    capsule_store: IncidentCapsuleStore,
    incident_by_batch: dict[str, dict[str, str]],
    request: Mapping[str, Any],
    credentials: tuple[int, int, int],
    child: Any,
) -> dict[str, Any]:
    """Capture one policy-requested backpressure incident from the app child."""
    if child is None or child.poll() is not None:
        raise PermissionError("application worker is not running")
    if credentials[0] != child.pid:
        raise PermissionError(
            "adaptive backpressure incident is not from the application worker"
        )
    context = _bounded_validation_audit_fields(
        request.get("context"),
        allowed=_ADAPTIVE_BACKPRESSURE_INCIDENT_FIELDS,
        label="adaptive backpressure incident context",
        allow_none=True,
    )
    if context.get("event") != "adaptive-aggregation-backpressure":
        raise ValueError(
            "adaptive backpressure incident context has an invalid event"
        )
    if context.get("action") != "INCIDENT":
        raise ValueError(
            "adaptive backpressure incident context has an invalid action"
        )
    for field in ("target_id", "batch_id", "generation_id", "policy_fingerprint"):
        if not isinstance(context.get(field), str) or not context[field]:
            raise ValueError(
                f"adaptive backpressure incident context requires {field}"
            )
    for field in ("pending_records", "sequence_start", "sequence_end"):
        value = context.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"adaptive backpressure incident context requires non-negative {field}"
            )
    if context["sequence_end"] < context["sequence_start"]:
        raise ValueError(
            "adaptive backpressure incident context sequence range is invalid"
        )
    batch_id = context["batch_id"]
    existing = incident_by_batch.get(batch_id)
    if existing is not None:
        if (
            existing["target_id"] != context["target_id"]
            or existing["generation_id"] != context["generation_id"]
            or existing.get("policy_fingerprint", context["policy_fingerprint"])
            != context["policy_fingerprint"]
        ):
            raise ValueError(
                "adaptive backpressure batch_id was reused for a different context"
            )
        return {
            "ok": True,
            "accepted": True,
            "incident_id": existing["incident_id"],
            "capsule_id": existing["capsule_id"],
            "incident_recorded": True,
            "idempotent": True,
        }
    if len(incident_by_batch) >= 1024:
        raise RuntimeError("adaptive backpressure incident idempotency bound is exhausted")

    incident_id = uuid4()
    capsule = capsule_store.create_placeholder(
        incident_id,
        run_id=runtime.run_id,
        policy_fingerprint=runtime.snapshot.content_hash,
        incident_state={
            "trigger": "adaptive_aggregation_backpressure",
            "incident_id": str(incident_id),
            "transaction_state": "OBSERVATION_ONLY",
            "backpressure": context,
        },
    )
    capsule_payload = capsule.get("capsule")
    if not isinstance(capsule_payload, Mapping):
        raise RuntimeError("adaptive backpressure incident capsule is malformed")
    capsule_id = str(capsule_payload.get("capsule_id") or "").strip()
    if not capsule_id:
        raise RuntimeError("adaptive backpressure incident capsule has no id")
    incident_by_batch[batch_id] = {
        "incident_id": str(incident_id),
        "capsule_id": capsule_id,
        "target_id": context["target_id"],
        "generation_id": context["generation_id"],
        "policy_fingerprint": context["policy_fingerprint"],
    }
    audit_event = runtime.audit.emit(
        "INCIDENT_CAPTURED",
        actor={
            "type": "worker",
            "id": f"pid:{credentials[0]}",
            "uid": credentials[1],
        },
        scope={
            "target_id": context["target_id"],
            "incident_id": str(incident_id),
            "batch_id": batch_id,
        },
        policy={
            "policy_id": str(runtime.snapshot.snapshot_id),
            "fingerprint": runtime.snapshot.content_hash,
            "authority_generation": runtime.effective.generation,
        },
        outcome={"state": "CAPTURED", "authority_granted": False},
        details={
            "capture_level": "MINIMAL",
            "trigger": "adaptive_aggregation_backpressure",
            "capsule_id": capsule_id,
            "authority_granted": False,
        },
        priority=EvidencePriority.IMPORTANT,
    )
    return {
        "ok": True,
        "accepted": True,
        "incident_id": str(incident_id),
        "capsule_id": capsule_id,
        "incident_recorded": True,
        "audit_recorded": audit_event is not None,
        "idempotent": False,
    }


def _adaptive_threshold_policy_settings(
    changes: Mapping[str, Any], *, target_id: str
) -> tuple[PolicySetting, ...]:
    """Translate validated proposal fields into target-scoped authority settings."""
    target = str(target_id).strip()
    if not target:
        raise ValueError("adaptive threshold application requires a target id")
    if not isinstance(changes, Mapping) or not changes:
        raise ValueError("adaptive threshold application requires threshold changes")
    settings: list[PolicySetting] = []
    for raw_name, value in changes.items():
        name = str(raw_name).strip()
        path = _ADAPTIVE_THRESHOLD_SETTING_PATHS.get(name)
        if path is None:
            raise ValueError(f"unsupported adaptive threshold field {name!r}")
        settings.append(PolicySetting(path=path, value=value, target=target))
    return tuple(settings)


def create_worker_failure_incident_capsule(
    capsule_store: IncidentCapsuleStore,
    envelope: dict[str, object],
    *,
    run_id: UUID | None = None,
    policy_fingerprint: str | None = None,
    authority_policy_generation: int | None = None,
    authority_policy_fingerprint: str | None = None,
) -> dict[str, object]:
    """Create the initial application-scoped capsule for a worker failure.

    The capsule store owns bounded serialization and integrity protection. The
    returned identifier is evidence of the capsule write only; it does not
    authorize a restart, shutdown, or policy change.
    """
    incident_id = uuid4()
    envelope_copy = dict(envelope)
    capsule = capsule_store.create_placeholder(
        incident_id,
        run_id=run_id,
        policy_fingerprint=policy_fingerprint,
        authority_policy_generation=authority_policy_generation,
        authority_policy_fingerprint=authority_policy_fingerprint,
        incident_state={
            "trigger": "worker_failure",
            "incident_id": str(incident_id),
            "transaction_state": "ROLLED_BACK",
            "worker_failure": envelope_copy,
        },
    )
    capsule_payload = capsule.get("capsule")
    if not isinstance(capsule_payload, dict):
        raise RuntimeError("worker failure capsule did not return a capsule payload")
    return {
        "accepted": True,
        "incident_id": str(incident_id),
        "capsule_id": str(capsule_payload.get("capsule_id") or ""),
        "incident_recorded": True,
        "capsule_integrity": (capsule.get("integrity") or {}).get("content_sha256"),
    }


def _load_external_signer(specification: str | None):
    if not specification:
        return None
    module_name, separator, attribute = specification.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("external signer must use module:attribute syntax")
    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    if isinstance(value, type):
        value = value()
    elif callable(value) and not hasattr(value, "sign_artifact") and not hasattr(value, "sign_manifest"):
        value = value()
    if not hasattr(value, "public_identity"):
        raise TypeError("external signer must provide public_identity()")
    if not hasattr(value, "sign_artifact") and not hasattr(value, "sign_manifest"):
        raise TypeError("external signer must provide sign_artifact() or sign_manifest()")
    return value


def _behavior_materialization_log(
    envelopes: tuple[dict[str, object], ...],
) -> tuple[str, dict[str, object]]:
    snapshots = [dict(item.get("snapshot") or {}) for item in envelopes]
    subjects = sorted({str(item.get("subject_key") or "unknown") for item in snapshots})
    subject_preview = ", ".join(subjects[:3])
    if len(subjects) > 3:
        subject_preview += f", +{len(subjects) - 3} more"
    count = len(snapshots)
    message = (
        f"Materialized {count} behavior snapshot{'s' if count != 1 else ''}"
        + (f" for {subject_preview}" if subject_preview else "")
    )
    return message, {
        "snapshot_count": count,
        "subject_keys": subjects,
        "snapshot_ids": [str(item.get("snapshot_id") or "") for item in snapshots],
        "seal_reasons": sorted({str(item.get("seal_reason") or "unknown") for item in snapshots}),
        "signature_states": sorted({
            str((envelope.get("integrity") or {}).get("signature_state") or "unknown")
            for envelope in envelopes
        }),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caretaker-run")
    parser.add_argument("--policy")
    parser.add_argument("--data-directory")
    parser.add_argument(
        "--external-signer",
        help="trusted supervisor signer provider in module:attribute form",
    )
    parser.add_argument("--system-data", action="store_true")
    parser.add_argument(
        "--authority-stack",
        help="TOML descriptor for signed/unsigned Caretaker policy authority layers",
    )
    parser.add_argument(
        "--profile",
        choices=builtin_profile_names(),
        help="select a built-in framework profile before importing the application",
    )
    parser.add_argument(
        "--profile-trusted-fingerprint",
        action="append",
        default=[],
        help="independently trusted profile-root fingerprint; repeat for all three identities",
    )
    parser.add_argument(
        "--integrity-publication-directory",
        help="verify signed root and release manifests before starting the application",
    )
    parser.add_argument(
        "--integrity-artifact-root",
        help="source/artifact tree covered by the manifests (defaults to publication directory)",
    )
    parser.add_argument(
        "--integrity-trusted-fingerprint",
        action="append",
        default=[],
        help="independently trusted primary fingerprint; repeat for each trusted root identity",
    )
    parser.add_argument(
        "--integrity-verification-mode",
        choices=[item.value for item in SignatureVerificationMode],
        default=SignatureVerificationMode.FULL_PUBLICATION.value,
    )
    parser.add_argument(
        "--replay-podman-image",
        help=(
            "pre-provisioned local rootless Podman image for isolated historical replay; "
            "replay remains disabled unless policy enables it"
        ),
    )
    parser.add_argument(
        "--replay-podman-executable",
        default="podman",
        help="Podman executable used by the optional isolated replay backend",
    )
    parser.add_argument(
        "--replay-cgroup-manager",
        choices=("cgroupfs", "systemd"),
        default="cgroupfs",
        help="cgroup manager for the optional rootless replay backend",
    )
    parser.add_argument("module")
    parser.add_argument("module_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.profile and args.authority_stack:
        parser.error("--profile and --authority-stack are mutually exclusive")
    release_integrity: dict[str, object] = {
        "status": "NOT_CONFIGURED",
        "configured": False,
        "root_anchored": False,
        "manifests": {},
    }
    if args.integrity_publication_directory:
        if not args.integrity_trusted_fingerprint:
            parser.error(
                "--integrity-publication-directory requires at least one "
                "--integrity-trusted-fingerprint obtained independently"
            )
        try:
            release_integrity = verify_release_publication(
                args.integrity_publication_directory,
                trusted_primary_fingerprints=args.integrity_trusted_fingerprint,
                artifact_root=args.integrity_artifact_root,
                verification_mode=SignatureVerificationMode(args.integrity_verification_mode),
            )
        except Exception as exc:
            parser.error(f"release-integrity verification could not complete: {type(exc).__name__}: {exc}")
        if release_integrity["status"] != "TRUSTED":
            parser.error("configured release-integrity verification failed")
    if args.policy:
        declared_policy, _ = load_operator_policy(args.policy)
    else:
        directory = args.data_directory or f"./caretaker-data/{args.module}"
        declared_policy = OperatorLoggingPolicy.application_defaults(
            directory=directory, application_id=args.module
        )

    if args.profile:
        try:
            authority = load_builtin_profile_supervisor(
                args.profile,
                trusted_primary_fingerprints=(
                    tuple(args.profile_trusted_fingerprint)
                    if args.profile_trusted_fingerprint
                    else None
                ),
            )
        except Exception as exc:
            parser.error(f"built-in profile could not be loaded: {type(exc).__name__}: {exc}")
    elif args.authority_stack:
        authority = PolicyAuthoritySupervisor.from_stack_file(args.authority_stack)
    else:
        authority = PolicyAuthoritySupervisor()
    policy_transform = lambda value: authority.effective.apply_dataclass(
        value, prefix="logging"
    )
    policy = policy_transform(declared_policy)
    authority.set_snapshot_path(
        Path(policy.directory) / "policy" / "authority-effective.json"
    )
    try:
        external_signer = _load_external_signer(args.external_signer)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        parser.error(f"external signer configuration is invalid: {exc}")
    runtime = LoggingRuntime(
        declared_policy,
        source_path=args.policy,
        supervised=True,
        policy_transform=policy_transform,
        external_signer=external_signer,
    )
    policy = runtime.active_policy
    behavior_store = BehaviorSnapshotStore(
        policy.directory, artifact_signer=runtime.writer.signing_service
    )
    capsule_store = IncidentCapsuleStore(
        policy.directory,
        policy=policy.capsules,
        artifact_signer=runtime.writer.signing_service,
    )
    regression_fixture_store = (
        RegressionFixtureStore(policy.directory, policy=policy.regression)
        if policy.regression.enabled
        else None
    )
    replay_coordinator = None
    if regression_fixture_store is not None:
        replay_backend = (
            RootlessPodmanReplayBackend(
                args.replay_podman_image,
                podman_executable=args.replay_podman_executable,
                cgroup_manager=args.replay_cgroup_manager,
            )
            if args.replay_podman_image
            else None
        )
        replay_coordinator = IsolatedReplayCoordinator(
            regression_fixture_store,
            policy=policy.regression,
            backend=replay_backend,
        ) if replay_backend is not None else IsolatedReplayCoordinator(
            regression_fixture_store,
            policy=policy.regression,
        )
    behavior_statistics = BehaviorStatisticsRepository(policy.directory)
    adaptive_aggregation_store = SupervisorAdaptiveAggregationStore(policy.directory)
    behavior_revision = {"value": 0}
    behavior_collection_id = str(uuid4())
    runtime.event(
        logger_name="caretaker.authority",
        severity=30 if authority.effective.overall_assurance in {"GUARANTEE_VIOLATED", "INVALID_AUTHORITY_CHAIN"} else 20,
        channel=LogChannel.CARETAKER_INTERNAL,
        message="Policy authority stack loaded",
        fields={
            "generation": authority.effective.generation,
            "fingerprint": authority.effective.fingerprint,
            "assurance": authority.effective.overall_assurance,
            "layers": authority.effective.layer_status(),
        },
    )
    run_dir = Path(policy.directory) / "run"
    event_socket = run_dir / "events.sock"
    control_socket = run_dir / "control.sock"
    runtime_control_socket = run_dir / "runtime.sock"
    server = SocketLogServer(event_socket, runtime.sink, allowed_uids={os.getuid()}, attachment_store=runtime.attachments)
    server.start()
    server_thread = threading.Thread(target=server.serve_forever, name="caretaker-event-server", daemon=True)
    server_thread.start()

    leases: dict[str, object] = {}
    console_invocations: dict[str, int] = {}
    console_identity_store = ConsoleIdentityStore(policy.directory)
    child_holder: dict[str, subprocess.Popen] = {}
    supervisor_holder: dict[str, CaretakerApplicationSupervisor] = {}
    failure_store_holder: dict[str, SQLiteRepairStore] = {}
    rollout_ledger_holder: dict[str, RepairRolloutLedger] = {}
    rollout_coordinator_holder: dict[str, RepairRolloutCoordinator] = {}
    authority_generation_holder = {"generation": authority.effective.generation}
    authority_runtime_match_holder: dict[str, bool | None] = {"match": None}
    authority_lease_holder = {
        str(lease.lease_id): lease for lease in authority.effective.runtime_leases
    }
    adaptive_incident_by_batch: dict[str, dict[str, str]] = {}

    def deployment_fingerprint() -> str | None:
        layer = next(
            (
                item
                for item in authority.effective.layers
                if getattr(getattr(item, "kind", None), "value", None) == "deployment"
            ),
            None,
        )
        return layer.fingerprint if layer else None

    def materialize_behavior_snapshots(*, maximum: int = 100) -> int:
        envelopes = behavior_statistics.materialize_pending(
            behavior_store,
            authority_fingerprint=authority.effective.fingerprint,
            deployment_fingerprint=deployment_fingerprint(),
            maximum=maximum,
        )
        if envelopes:
            message, fields = _behavior_materialization_log(envelopes)
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message=message,
                fields=fields,
            )
        behavior_revision["value"] += len(envelopes)
        return len(envelopes)

    def recent_log_records(limit: int = 1000):
        event_directory = Path(policy.directory) / "application" / "events"
        paths = sorted(event_directory.glob("*.ctlog")) + sorted(event_directory.glob("*.ctlog.gz"))
        records = []
        for path in paths[-16:]:
            try:
                records.extend(read_segment(path))
            except Exception:
                continue
        return records[-max(1, limit):]

    def capsule_evidence_references(incident_id: UUID, *, limit: int = 100) -> list[dict[str, object]]:
        references = []
        for record in recent_log_records(max(1000, limit)):
            if record.incident_id != incident_id:
                continue
            references.append({
                "record_id": str(record.record_id),
                "occurred_at": record.occurred_at.isoformat(),
                "channel": record.channel.name,
                "content_sha256": hashlib.sha256(
                    json.dumps(
                        {
                            "record_id": str(record.record_id),
                            "sequence_number": record.sequence_number,
                            "message": record.formatted_message or record.message_template,
                            "fields": dict(record.fields),
                        },
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest(),
            })
        return references

    def capsule_timeline(incident_id: UUID, *, limit: int = 100) -> list[dict[str, object]]:
        timeline = []
        for record in recent_log_records(max(1000, limit)):
            if record.incident_id != incident_id:
                continue
            message = record.formatted_message or record.message_template
            timeline.append({
                "record_id": str(record.record_id),
                "sequence_number": record.sequence_number,
                "occurred_at": record.occurred_at.isoformat(),
                "severity": record.severity,
                "channel": record.channel.name,
                "logger": record.logger_name,
                "message": message,
                "target_id": str(record.target_id) if record.target_id else None,
                "call_id": str(record.call_id) if record.call_id else None,
                "incident_id": str(record.incident_id) if record.incident_id else None,
                "fields": dict(record.fields),
                "content_sha256": hashlib.sha256(
                    json.dumps(
                        {
                            "record_id": str(record.record_id),
                            "sequence_number": record.sequence_number,
                            "message": message,
                            "fields": dict(record.fields),
                        },
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest(),
                "evidence_status": "PERSISTED_LOG_RECORD",
            })
        return timeline[-max(1, limit):]

    def runtime_authority_match() -> tuple[bool | None, dict[str, object] | None]:
        if not unix_socket_exists(runtime_control_socket):
            return None, None
        try:
            child_status = control_request(runtime_control_socket, {"command": "status"})
        except OSError:
            return None, None
        child_authority = child_status.get("authority_policy")
        if not isinstance(child_authority, dict):
            return False, child_status
        expected = authority.effective
        matches = (
            int(child_authority.get("generation", -1)) == expected.generation
            and str(child_authority.get("fingerprint", "")) == expected.fingerprint
        )
        return matches, child_status

    def current_adaptive_context() -> tuple[
        dict[str, str], dict[str, str], dict[str, dict[str, Any]]
    ] | None:
        """Read the child's current adaptive context without mutating state."""
        if not unix_socket_exists(runtime_control_socket):
            return None
        try:
            response = control_request(
                runtime_control_socket,
                {"command": "adaptive-aggregation-context"},
            )
        except OSError:
            return None
        contexts = response.get("contexts")
        if not response.get("ok") or not isinstance(contexts, list):
            return None
        current_generations: dict[str, str] = {}
        policy_fingerprints: dict[str, str] = {}
        promotion_policies: dict[str, dict[str, Any]] = {}
        promotion_policy_values: dict[str, object] = {}
        ambiguous_targets: set[str] = set()
        for item in contexts:
            if not isinstance(item, dict) or not item.get("enabled"):
                continue
            target = str(item.get("target_id") or "").strip()
            aggregation_scope = item.get("aggregation_scope")
            if aggregation_scope is not None:
                aggregation_scope = str(aggregation_scope).strip() or None
            generation = str(item.get("generation_id") or "").strip()
            policy_fingerprint = str(item.get("policy_fingerprint") or "").strip()
            if not target or not generation or not policy_fingerprint:
                continue
            aggregation_target = extended_aggregation_target_id(
                target,
                aggregation_scope,
            )
            promotion_policy = item.get("promotion_policy")
            if (
                aggregation_target in current_generations
                and (
                    current_generations[aggregation_target] != generation
                    or policy_fingerprints[aggregation_target] != policy_fingerprint
                    or (
                        aggregation_target in promotion_policy_values
                        and promotion_policy_values[aggregation_target] != promotion_policy
                    )
                )
            ):
                ambiguous_targets.add(aggregation_target)
                continue
            current_generations[aggregation_target] = generation
            policy_fingerprints[aggregation_target] = policy_fingerprint
            promotion_policy_values[aggregation_target] = promotion_policy
            if isinstance(promotion_policy, dict):
                promotion_policies[aggregation_target] = dict(promotion_policy)
        for aggregation_target in ambiguous_targets:
            current_generations.pop(aggregation_target, None)
            policy_fingerprints.pop(aggregation_target, None)
            promotion_policies.pop(aggregation_target, None)
        return current_generations, policy_fingerprints, promotion_policies

    def reconcile_adaptive_aggregation(
        *,
        maximum: int = 100,
        actor_type: str = "supervisor",
        actor_id: str = "application-supervisor",
    ) -> dict[str, Any] | None:
        """Reconcile worker evidence using supervisor-owned authority context."""
        context = current_adaptive_context()
        if context is None:
            return None
        current_generations, policy_fingerprints, promotion_policies = context
        effective_authority = authority.effective
        result = adaptive_aggregation_store.reconcile(
            current_generations=current_generations,
            policy_fingerprints=policy_fingerprints,
            authority_policy_generation=str(effective_authority.generation),
            authority_policy_fingerprint=effective_authority.fingerprint,
            maximum_batches=maximum,
        )
        result["promotions"] = adaptive_aggregation_store.evaluate_promotions(
            current_generations=current_generations,
            policy_fingerprints=policy_fingerprints,
            authority_policy_generation=str(effective_authority.generation),
            authority_policy_fingerprint=effective_authority.fingerprint,
            promotion_policies=promotion_policies,
            maximum=maximum,
        )
        _emit_adaptive_aggregation_audit(
            runtime,
            result,
            actor_type=actor_type,
            actor_id=actor_id,
        )
        return result

    def authenticated_rollout_worker(request: Mapping[str, Any], credentials: tuple[int, int, int]):
        supervisor = supervisor_holder.get("supervisor")
        if supervisor is None:
            raise RuntimeError("supervisor is not initialized")
        try:
            worker_id = UUID(str(request["worker_id"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("rollout worker request requires a valid worker_id") from exc
        worker = supervisor.workers.get(worker_id)
        if worker.process_id != credentials[0]:
            raise PermissionError("rollout worker process identity does not match registration")
        if str(request.get("process_start_id") or "") != str(worker.process_start_id):
            raise PermissionError("rollout worker process start identity does not match registration")
        if str(request.get("authority_packet_id") or "") != str(worker.authority_packet_id or ""):
            raise PermissionError("rollout worker authority packet identity does not match registration")
        if worker.authority_packet_id is None:
            raise PermissionError("rollout worker has no active authority packet")
        if worker.state not in {WorkerState.STARTING, WorkerState.HEALTHY, WorkerState.DEGRADED}:
            raise PermissionError("rollout worker is not in an executable lifecycle state")
        return worker


    def control_handler(request, credentials):
        command = request.get("command")
        if command == "console-invocation-identity":
            return _handle_console_identity_request(console_identity_store, request)
        if command in {"console-invocation-start", "console-invocation-end"}:
            return _handle_console_invocation_event(
                runtime,
                request,
                credentials,
                console_invocations,
                console_identity_store,
            )
        if command == "adaptive-observation-submit":
            return _handle_adaptive_observation_submission(
                adaptive_aggregation_store,
                request,
                credentials,
                child_holder.get("child"),
            )
        if command == "audit-validation-decision":
            return _handle_validation_audit_submission(
                runtime,
                request,
                credentials,
                child_holder.get("child"),
            )
        if command == "audit-adaptive-backpressure":
            return _handle_adaptive_backpressure_audit_submission(
                runtime,
                request,
                credentials,
                child_holder.get("child"),
            )
        if command == "adaptive-backpressure-incident":
            return _handle_adaptive_backpressure_incident_submission(
                runtime,
                capsule_store,
                adaptive_incident_by_batch,
                request,
                credentials,
                child_holder.get("child"),
            )
        if command == "worker-acceptance-observation":
            supervisor = supervisor_holder.get("supervisor")
            if supervisor is None:
                raise RuntimeError("supervisor is not initialized")
            return supervisor.handle_worker_acceptance_observation(request, credentials)
        if command in {"status", "health"}:
            child = child_holder.get("child")
            supervisor = supervisor_holder.get("supervisor")
            runtime_policy_match, application_runtime = runtime_authority_match()
            effective_authority = authority.effective
            signing_identity = None
            if runtime.active_policy.signing.publish_public_key_to_control_clients:
                identity = runtime.writer.signing_service.identity
                if identity is not None:
                    signing_identity = asdict(identity) if hasattr(identity, "__dataclass_fields__") else dict(identity)
            return {"ok": True, "application_pid": child.pid if child else None,
                    "application_running": child.poll() is None if child else False,
                    "behavior_collection_id": behavior_collection_id,
                    "behavior_revision": behavior_revision["value"],
                    "policy_generation": runtime.effective.generation,
                    "active_leases": list(leases),
                    "runtime_signing_identity": signing_identity,
                    "release_integrity": release_integrity,
                    "authority_policy": {
                        "generation": effective_authority.generation,
                        "fingerprint": effective_authority.fingerprint,
                        "overall_assurance": effective_authority.overall_assurance,
                        "violations": len(effective_authority.violations),
                        "layers": effective_authority.layer_status(),
                        "runtime_matches_supervisor": runtime_policy_match,
                    },
                    "workers": [asdict(item) for item in supervisor.workers.all()] if supervisor else [],
                    "runtime": application_runtime,
                    "caretaker_overhead": runtime.overhead_status(),
                    "caretaker_metrics": runtime.metrics_status(),
            }
        if command == "adaptive-aggregation-status":
            policy_contexts: list[dict[str, Any]] = []
            policy_context_available = False
            if unix_socket_exists(runtime_control_socket):
                try:
                    context_response = control_request(
                        runtime_control_socket,
                        {"command": "adaptive-aggregation-context", "limit": 200},
                    )
                except OSError:
                    context_response = {}
                raw_contexts = context_response.get("contexts")
                if context_response.get("ok") and isinstance(raw_contexts, list):
                    policy_contexts = [
                        dict(item) for item in raw_contexts if isinstance(item, dict)
                    ]
                    policy_context_available = True
            adaptive_context = current_adaptive_context()
            transition_context_kwargs: dict[str, Any] = {}
            if adaptive_context is not None:
                current_generations, policy_fingerprints, _ = adaptive_context
                effective_authority = authority.effective
                transition_context_kwargs = {
                    "current_generations": current_generations,
                    "policy_fingerprints": policy_fingerprints,
                    "authority_policy_generation": str(effective_authority.generation),
                    "authority_policy_fingerprint": effective_authority.fingerprint,
                }
            return {
                "ok": True,
                "store": adaptive_aggregation_store.status(),
                "aggregates": list(adaptive_aggregation_store.list_aggregates()),
                "transitions": list(
                    adaptive_aggregation_store.list_transition_requests(
                        **transition_context_kwargs,
                    )
                ),
                "policy_ledger": list(
                    adaptive_aggregation_store.list_policy_transition_ledger()
                ),
                "policy_acceptances": list(
                    adaptive_aggregation_store.list_policy_transition_acceptances()
                ),
                "policy_contexts": policy_contexts,
                "policy_context_available": policy_context_available,
            }
        if command == "adaptive-population-compare":
            target_value = request.get("target_id")
            generation_value = request.get("generation_id")
            target_id = (
                str(target_value).strip() if target_value is not None else None
            )
            generation_id = (
                str(generation_value).strip()
                if generation_value is not None
                else None
            )
            limit = max(1, min(int(request.get("limit", 128)), 128))
            report = compare_adaptive_populations(
                adaptive_aggregation_store.list_aggregates(limit=limit),
                target_id=target_id or None,
                generation_id=generation_id or None,
                minimum_observations=request.get("minimum_observations", 30),
                z_threshold=request.get("z_threshold", 3.0),
            )
            return {
                "ok": True,
                "report": report,
                "read_only": True,
                "authority_granted": False,
            }
        if command == "worker-failure-recovery-status":
            store = failure_store_holder.get("store")
            if store is None:
                return {
                    "ok": True,
                    "available": False,
                    "reason": "worker failure store is not initialized",
                    "read_only": True,
                    "authority_granted": False,
                }
            limit = max(1, min(int(request.get("limit", 100)), 500))
            return {
                "ok": True,
                "available": True,
                **worker_failure_recovery_status(store, limit=limit),
            }
        if command == "repair-rollout-worker-ack":
            worker = authenticated_rollout_worker(request, credentials)
            coordinator = rollout_coordinator_holder.get("coordinator")
            if coordinator is None:
                raise RuntimeError("rollout coordinator is not initialized")
            try:
                rollout_id = UUID(str(request["rollout_id"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("rollout worker acknowledgement requires a valid rollout_id") from exc
            record = coordinator.ledger.get(rollout_id)
            if worker.target_id != record.target_id:
                raise PermissionError("rollout worker target does not match rollout target")
            acknowledgement = coordinator.acknowledge_worker(
                rollout_id=rollout_id,
                worker_id=str(worker.worker_id),
                worker_process_id=worker.process_id,
                stage=request.get("stage"),
                acknowledgement_id=(
                    UUID(str(request["acknowledgement_id"]))
                    if request.get("acknowledgement_id")
                    else None
                ),
            )
            return {
                "ok": True,
                "read_only": True,
                "authority_granted": False,
                "acknowledgement": {
                    "acknowledgement_id": str(acknowledgement.acknowledgement_id),
                    "rollout_id": str(acknowledgement.rollout_id),
                    "target_id": acknowledgement.target_id,
                    "candidate_id": str(acknowledgement.candidate_id),
                    "worker_id": acknowledgement.worker_id,
                    "worker_process_id": acknowledgement.worker_process_id,
                    "stage": acknowledgement.stage.value,
                    "routing_policy_fingerprint": acknowledgement.routing_policy_fingerprint,
                    "acknowledged_at": acknowledgement.acknowledged_at.isoformat(),
                    "content_hash": acknowledgement.content_hash,
                },
            }
        if command == "repair-rollout-route":
            worker = authenticated_rollout_worker(request, credentials)
            coordinator = rollout_coordinator_holder.get("coordinator")
            if coordinator is None:
                raise RuntimeError("rollout coordinator is not initialized")
            try:
                rollout_id = UUID(str(request["rollout_id"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError("rollout route request requires a valid rollout_id") from exc
            record = coordinator.ledger.get(rollout_id)
            if worker.target_id != record.target_id:
                raise PermissionError("rollout worker target does not match rollout target")
            decision = coordinator.route(
                rollout_id=rollout_id,
                worker_id=str(worker.worker_id),
                worker_process_id=worker.process_id,
                routing_scope=str(request.get("routing_scope") or ""),
                routing_key=str(request.get("routing_key") or ""),
            )
            return {
                "ok": True,
                "read_only": True,
                "authority_granted": False,
                "decision": {
                    "rollout_id": str(decision.rollout_id),
                    "target_id": decision.target_id,
                    "candidate_id": str(decision.candidate_id),
                    "stage": decision.stage.value,
                    "routing_scope": decision.routing_scope,
                    "routing_key_digest": decision.routing_key_digest,
                    "bucket": decision.bucket,
                    "bucket_count": decision.bucket_count,
                    "configured_percentage": decision.configured_percentage,
                    "candidate_selected": decision.candidate_selected,
                    "candidate_authoritative": decision.candidate_authoritative,
                    "authoritative_implementation": decision.authoritative_implementation.value,
                    "strategy": decision.strategy,
                    "policy_fingerprint": decision.policy_fingerprint,
                    "decision_hash": decision.decision_hash,
                    "reason": decision.reason,
                },
            }
        if command == "repair-rollout-advance":
            ledger = rollout_ledger_holder.get("ledger")
            coordinator = rollout_coordinator_holder.get("coordinator")
            if ledger is None or coordinator is None:
                raise RuntimeError("rollout coordinator is not initialized")
            return _handle_rollout_advance_request(
                ledger,
                coordinator,
                request,
                credentials,
                policy_fingerprint=runtime.effective.fingerprint,
                authority_fingerprint=authority.effective.fingerprint,
            )
        if command in {"repair-rollout-pause", "repair-rollout-resume"}:
            ledger = rollout_ledger_holder.get("ledger")
            coordinator = rollout_coordinator_holder.get("coordinator")
            if ledger is None or coordinator is None:
                raise RuntimeError("rollout coordinator is not initialized")
            return _handle_rollout_pause_request(
                ledger,
                coordinator,
                request,
                credentials,
                paused=command == "repair-rollout-pause",
                policy_fingerprint=runtime.effective.fingerprint,
                authority_fingerprint=authority.effective.fingerprint,
            )
        if command == "repair-rollout-routing-update":
            ledger = rollout_ledger_holder.get("ledger")
            coordinator = rollout_coordinator_holder.get("coordinator")
            if ledger is None or coordinator is None:
                raise RuntimeError("rollout coordinator is not initialized")
            return _handle_rollout_percentage_request(
                ledger,
                coordinator,
                request,
                credentials,
                policy_fingerprint=runtime.effective.fingerprint,
                authority_fingerprint=authority.effective.fingerprint,
            )
        if command == "repair-rollout-status":
            ledger = rollout_ledger_holder.get("ledger")
            if ledger is None:
                return {
                    "ok": True,
                    "available": False,
                    "reason": "repair rollout ledger is not initialized",
                    "read_only": True,
                    "authority_granted": False,
                    "records": [],
                    "transitions": [],
                }
            raw_rollout_id = str(request.get("rollout_id") or "").strip()
            rollout_id = UUID(raw_rollout_id) if raw_rollout_id else None
            limit = max(1, min(int(request.get("limit", 100)), 500))
            transition_limit = max(
                1, min(int(request.get("transition_limit", 200)), 1000)
            )
            try:
                projection = ledger.operator_projection(
                    policy_fingerprint=runtime.effective.fingerprint,
                    rollout_id=rollout_id,
                    limit=limit,
                    transition_limit=transition_limit,
                )
            except RepairRolloutError as exc:
                return {
                    "ok": True,
                    "available": False,
                    "reason": str(exc),
                    "read_only": True,
                    "authority_granted": False,
                    "records": [],
                    "transitions": [],
                }
            coordinator = rollout_coordinator_holder.get("coordinator")
            if coordinator is not None:
                projection["worker_coordination"] = coordinator.status(rollout_id)
            return {"ok": True, "available": True, **projection}
        if command == "adaptive-aggregation-reconcile":
            result = reconcile_adaptive_aggregation(
                maximum=max(1, min(int(request.get("maximum", 100)), 1000)),
                actor_type="operator",
                actor_id=f"uid:{credentials[1]}",
            )
            return {"ok": True, "result": result}
        if command == "adaptive-transition-list":
            target_id = str(request.get("target_id") or "").strip() or None
            worker_id = str(request.get("worker_id") or "").strip() or None
            limit = max(1, min(int(request.get("limit", 100)), 500))
            adaptive_context = current_adaptive_context()
            transition_context_kwargs: dict[str, Any] = {}
            if adaptive_context is not None:
                current_generations, policy_fingerprints, _ = adaptive_context
                effective_authority = authority.effective
                transition_context_kwargs = {
                    "current_generations": current_generations,
                    "policy_fingerprints": policy_fingerprints,
                    "authority_policy_generation": str(effective_authority.generation),
                    "authority_policy_fingerprint": effective_authority.fingerprint,
                }
            return {
                "ok": True,
                "transitions": list(
                    adaptive_aggregation_store.list_transition_requests(
                        target_id=target_id,
                        worker_id=worker_id,
                        limit=limit,
                        **transition_context_kwargs,
                    )
                ),
                "policy_ledger": list(
                    adaptive_aggregation_store.list_policy_transition_ledger()
                ),
                "policy_acceptances": list(
                    adaptive_aggregation_store.list_policy_transition_acceptances()
                ),
            }
        if command == "adaptive-threshold-proposal":
            target_id = str(request.get("target_id") or "").strip()
            if not target_id:
                raise ValueError("adaptive-threshold-proposal requires target_id")
            requested_scope = request.get("aggregation_scope")
            requested_scope = (
                str(requested_scope).strip() if requested_scope is not None else None
            )
            if not unix_socket_exists(runtime_control_socket):
                raise PermissionError(
                    "adaptive threshold proposal requires current worker context"
                )
            try:
                context_response = control_request(
                    runtime_control_socket,
                    {"command": "adaptive-aggregation-context", "limit": 200},
                )
            except OSError as exc:
                raise PermissionError(
                    "adaptive threshold proposal requires current worker context"
                ) from exc
            contexts = context_response.get("contexts")
            if not context_response.get("ok") or not isinstance(contexts, list):
                raise PermissionError(
                    "adaptive threshold proposal requires current worker context"
                )
            matching_contexts = [
                item
                for item in contexts
                if isinstance(item, dict)
                and item.get("enabled")
                and str(item.get("target_id") or "").strip() == target_id
                and (
                    str(item.get("aggregation_scope") or "").strip() or None
                )
                == requested_scope
            ]
            if len(matching_contexts) != 1:
                raise PermissionError(
                    "adaptive threshold proposal requires one unambiguous enabled target context"
                )
            context = matching_contexts[0]
            effective_authority = authority.effective
            return {
                "ok": True,
                "proposal": adaptive_aggregation_store.create_threshold_proposal(
                    target_id=target_id,
                    aggregation_scope=requested_scope,
                    generation_id=str(context.get("generation_id") or ""),
                    code_hash=str(context.get("code_hash") or ""),
                    monitoring_fingerprint=str(
                        context.get("monitoring_fingerprint") or ""
                    ),
                    policy_fingerprint=str(context.get("policy_fingerprint") or ""),
                    authority_policy_generation=str(effective_authority.generation),
                    authority_policy_fingerprint=effective_authority.fingerprint,
                    changes=request.get("changes"),
                    requested_by=f"uid:{credentials[1]}",
                    reason=str(request.get("reason") or ""),
                    effective_after_seconds=float(
                        request.get("effective_after_seconds", 60)
                    ),
                    expires_in_seconds=float(
                        request.get("expires_in_seconds", 3600)
                    ),
                ),
            }
        if command == "adaptive-threshold-review":
            request_id = str(request.get("request_id") or "").strip()
            if not request_id:
                raise ValueError("adaptive-threshold-review requires request_id")
            adaptive_context = current_adaptive_context()
            if adaptive_context is None:
                raise PermissionError(
                    "adaptive threshold review requires current worker context"
                )
            current_generations, policy_fingerprints, _ = adaptive_context
            effective_authority = authority.effective
            reviews = adaptive_aggregation_store.list_transition_requests(
                request_id=request_id,
                current_generations=current_generations,
                policy_fingerprints=policy_fingerprints,
                authority_policy_generation=str(effective_authority.generation),
                authority_policy_fingerprint=effective_authority.fingerprint,
            )
            if len(reviews) != 1:
                raise KeyError(f"No adaptive threshold proposal found for {request_id}")
            proposal = reviews[0]
            review = adaptive_aggregation_store.review_threshold_proposal(
                request_id,
                decision=str(request.get("decision") or ""),
                reviewed_by=f"uid:{credentials[1]}",
                reason=str(request.get("reason") or ""),
                current_generations=current_generations,
                policy_fingerprints=policy_fingerprints,
                authority_policy_generation=str(effective_authority.generation),
                authority_policy_fingerprint=effective_authority.fingerprint,
            )
            runtime.event(
                logger_name="caretaker.adaptive",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Adaptive threshold proposal reviewed",
                fields={
                    "request_id": request_id,
                    "target_id": proposal.get("target_id"),
                    "review_decision": review.get("review_decision"),
                    "review_status": review.get("review_status"),
                    "policy_applied": False,
                    "authority_granted": False,
                },
                origin="caretaker",
            )
            runtime.audit.emit(
                "POLICY_REVIEWED",
                actor={"type": "operator", "id": f"uid:{credentials[1]}"},
                scope={
                    "target_id": proposal.get("target_id"),
                    "aggregation_scope": proposal.get("aggregation_scope"),
                    "transition_id": request_id,
                },
                policy={
                    "fingerprint": proposal.get("policy_fingerprint"),
                    "authority_type": "operator",
                },
                outcome={
                    "state": review.get("review_decision") or review.get("review_status"),
                },
                details={
                    "review_status": review.get("review_status"),
                    "policy_applied": False,
                    "authority_granted": False,
                },
                priority=EvidencePriority.CRITICAL,
            )
            return {"ok": True, "review": review}
        if command == "adaptive-threshold-apply":
            request_id = str(request.get("request_id") or "").strip()
            if not request_id:
                raise ValueError("adaptive-threshold-apply requires request_id")
            existing_transitions = [
                item
                for item in adaptive_aggregation_store.list_transition_requests()
                if item.get("request_kind") == "ADAPTIVE_POLICY_TRANSITION"
                and str(item.get("proposal_request_id") or "") == request_id
            ]
            if existing_transitions:
                if len(existing_transitions) > 1:
                    raise RuntimeError(
                        "adaptive threshold proposal has conflicting policy transitions"
                    )
                existing = existing_transitions[0]
                if existing.get("rollback_status") == "ROLLED_BACK":
                    raise PermissionError(
                        "adaptive threshold policy transition has been rolled back"
                    )
                return {
                    "ok": True,
                    "proposal_request_id": request_id,
                    "lease_id": existing.get("authority_lease_id"),
                    "lease_expires_at": existing.get("expires_at"),
                    "transition": existing,
                    "already_applied": True,
                    "authority_policy": authority.effective.snapshot_dict(),
                }
            adaptive_context = current_adaptive_context()
            if adaptive_context is None:
                raise PermissionError(
                    "adaptive threshold application requires current worker context"
                )
            current_generations, policy_fingerprints, _ = adaptive_context
            previous_authority = authority.effective
            proposals = adaptive_aggregation_store.list_transition_requests(
                request_id=request_id,
                current_generations=current_generations,
                policy_fingerprints=policy_fingerprints,
                authority_policy_generation=str(previous_authority.generation),
                authority_policy_fingerprint=previous_authority.fingerprint,
            )
            if len(proposals) != 1:
                raise KeyError(f"No adaptive threshold proposal found for {request_id}")
            proposal = proposals[0]
            if proposal.get("request_kind") != "ADAPTIVE_THRESHOLD_PROPOSAL":
                raise PermissionError("adaptive threshold application requires a threshold proposal")
            if proposal.get("context_status") != "CURRENT":
                raise PermissionError(
                    f"adaptive threshold proposal context is stale: {proposal.get('context_status')}"
                )
            if proposal.get("review_status") != "APPROVED_FOR_STAGED_POLICY_REVIEW":
                raise PermissionError(
                    "adaptive threshold application requires an approved operator review"
                )
            now = datetime.now(timezone.utc)
            try:
                effective_at = datetime.fromisoformat(str(proposal["effective_at"]))
                expires_at = datetime.fromisoformat(str(proposal["expires_at"]))
            except (KeyError, TypeError, ValueError) as exc:
                raise PermissionError("adaptive threshold proposal has invalid timing") from exc
            if effective_at.tzinfo is None:
                effective_at = effective_at.replace(tzinfo=timezone.utc)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= effective_at:
                raise PermissionError("adaptive threshold proposal has invalid timing")
            if now < effective_at:
                raise PermissionError("adaptive threshold proposal is not effective yet")
            remaining_seconds = int((expires_at - now).total_seconds())
            if remaining_seconds <= 0:
                raise PermissionError("adaptive threshold proposal has expired")

            aggregation_target = str(
                proposal.get("aggregation_target_id")
                or extended_aggregation_target_id(
                    str(proposal["target_id"]), proposal.get("aggregation_scope")
                )
            )
            if policy_fingerprints.get(aggregation_target) != str(
                proposal.get("policy_fingerprint") or ""
            ):
                raise PermissionError("adaptive threshold proposal policy is stale")
            aggregate = next(
                (
                    item
                    for item in adaptive_aggregation_store.list_aggregates()
                    if str(item.get("aggregation_target_id") or "") == aggregation_target
                    and str(item.get("generation_id") or "")
                    == str(proposal.get("generation_id") or "")
                    and str(item.get("policy_fingerprint") or "")
                    == str(proposal.get("policy_fingerprint") or "")
                    and str(item.get("authority_policy_generation") or "")
                    == str(previous_authority.generation)
                    and str(item.get("authority_policy_fingerprint") or "")
                    == previous_authority.fingerprint
                ),
                None,
            )
            workers = aggregate.get("workers") if isinstance(aggregate, Mapping) else None
            if not isinstance(workers, Mapping):
                raise PermissionError(
                    "adaptive threshold application requires an aggregate with worker provenance"
                )
            required_workers = [
                {
                    "worker_id": str(worker_id),
                    "worker_pid": int(worker.get("worker_pid")),
                }
                for worker_id, worker in sorted(workers.items())
                if isinstance(worker, Mapping)
            ]
            if not required_workers:
                raise PermissionError(
                    "adaptive threshold application requires at least one worker"
                )
            settings = _adaptive_threshold_policy_settings(
                proposal.get("changes") or {},
                target_id=str(proposal["target_id"]),
            )
            lease = authority.acquire_runtime_lease(
                settings=settings,
                requested_by=f"uid:{credentials[1]}",
                reason=(
                    f"approved adaptive threshold proposal {request_id}: "
                    f"{str(request.get('reason') or proposal.get('reason') or '')[:400]}"
                ).strip(),
                duration_seconds=remaining_seconds,
            )
            try:
                runtime.refresh_authority_policy()
                if not unix_socket_exists(runtime_control_socket):
                    raise RuntimeError("application runtime control is unavailable")
                response = control_request(
                    runtime_control_socket,
                    {
                        "command": "policy-authority-update",
                        "snapshot": authority.effective.snapshot_dict(),
                    },
                )
                if response.get("ok") is False:
                    raise RuntimeError(
                        str(response.get("error", "application rejected authority policy"))
                    )
                authority_generation_holder["generation"] = authority.effective.generation
                post_context = current_adaptive_context()
                if post_context is None:
                    raise RuntimeError("application adaptive context is unavailable after policy update")
                post_generations, post_policies, post_promotion_policies = post_context
                applied_policy = str(post_policies.get(aggregation_target) or "")
                if not applied_policy or applied_policy == str(proposal["policy_fingerprint"]):
                    raise RuntimeError(
                        "application did not expose a changed adaptive policy fingerprint"
                    )
                if post_generations.get(aggregation_target) != str(proposal["generation_id"]):
                    raise RuntimeError("application adaptive generation changed during policy update")
                post_policy = post_promotion_policies.get(aggregation_target) or {}
                transition_timeout = float(post_policy.get("transition_timeout_seconds", 60.0))
                transition = adaptive_aggregation_store.create_threshold_policy_transition(
                    request_id,
                    applied_policy_fingerprint=applied_policy,
                    current_generations=post_generations,
                    current_policy_fingerprints=post_policies,
                    authority_policy_generation=str(authority.effective.generation),
                    authority_policy_fingerprint=authority.effective.fingerprint,
                    required_workers=required_workers,
                    applied_by=f"uid:{credentials[1]}",
                    reason=str(request.get("reason") or proposal.get("reason") or "")[:512],
                    authority_lease_id=str(lease.lease_id),
                    authority_expires_at=lease.expires_at.isoformat(),
                    artifact_signer=runtime.writer.signing_service,
                    transition_timeout_seconds=transition_timeout,
                )
            except Exception:
                authority.release_runtime_lease(lease.lease_id)
                runtime.refresh_authority_policy()
                if unix_socket_exists(runtime_control_socket):
                    try:
                        control_request(
                            runtime_control_socket,
                            {
                                "command": "policy-authority-update",
                                "snapshot": authority.effective.snapshot_dict(),
                            },
                        )
                    except OSError:
                        pass
                authority_generation_holder["generation"] = authority.effective.generation
                raise
            runtime.event(
                logger_name="caretaker.adaptive",
                severity=30,
                channel=LogChannel.AUDIT,
                message="Approved adaptive threshold proposal applied",
                fields={
                    "request_id": request_id,
                    "target_id": proposal.get("target_id"),
                    "aggregation_target_id": aggregation_target,
                    "lease_id": str(lease.lease_id),
                    "transition_request_id": transition.get("request_id"),
                    "policy_applied": True,
                    "authority_granted": False,
                    "authority_policy_generation": authority.effective.generation,
                    "authority_policy_fingerprint": authority.effective.fingerprint,
                },
                origin="caretaker",
            )
            runtime.audit.emit(
                "POLICY_APPLIED",
                actor={"type": "operator", "id": f"uid:{credentials[1]}"},
                scope={
                    "target_id": proposal.get("target_id"),
                    "aggregation_scope": proposal.get("aggregation_scope"),
                    "transition_id": transition.get("transition_id"),
                },
                policy={
                    "prior_policy_id": transition.get("prior_policy_id"),
                    "policy_id": transition.get("policy_id"),
                    "prior_fingerprint": transition.get("previous_policy_fingerprint"),
                    "fingerprint": transition.get("policy_fingerprint"),
                    "authority_type": transition.get("authority_type"),
                    "authority_generation": authority.effective.generation,
                    "fields_affected": sorted(
                        str(field) for field in (proposal.get("changes") or {})
                    ),
                },
                outcome={
                    "state": "APPLIED",
                    "effective_at": transition.get("effective_at"),
                    "reason": transition.get("change_description"),
                },
                details={
                    "proposal_request_id": request_id,
                    "lease_id": str(lease.lease_id),
                    "required_worker_count": len(required_workers),
                    "authority_granted": False,
                },
                priority=EvidencePriority.CRITICAL,
            )
            _emit_adaptive_policy_transition_audit(
                runtime,
                transition,
                state="PENDING",
                actor_type="operator",
                actor_id=f"uid:{credentials[1]}",
                details={
                    "proposal_reviewed": True,
                    "worker_verification_required": True,
                    "required_worker_count": len(required_workers),
                },
            )
            return {
                "ok": True,
                "proposal_request_id": request_id,
                "lease_id": str(lease.lease_id),
                "lease_expires_at": lease.expires_at.isoformat(),
                "transition": transition,
                "authority_policy": authority.effective.snapshot_dict(),
            }
        if command == "adaptive-threshold-accept":
            request_id = str(request.get("request_id") or "").strip()
            if not request_id:
                raise ValueError("adaptive-threshold-accept requires request_id")
            if request.get("confirm") is not True:
                raise PermissionError("adaptive-threshold-accept requires confirm=true")
            reason = str(request.get("reason") or "").strip()
            if not reason:
                raise ValueError("adaptive threshold acceptance requires an operator reason")
            adaptive_context = current_adaptive_context()
            if adaptive_context is None:
                raise PermissionError(
                    "adaptive policy acceptance requires current worker context"
                )
            current_generations, policy_fingerprints, promotion_policies = adaptive_context
            transitions = adaptive_aggregation_store.list_transition_requests(
                request_id=request_id,
                current_generations=current_generations,
                policy_fingerprints=policy_fingerprints,
                authority_policy_generation=str(authority.effective.generation),
                authority_policy_fingerprint=authority.effective.fingerprint,
            )
            if len(transitions) != 1:
                raise KeyError(f"No adaptive policy transition found for {request_id}")
            transition = transitions[0]
            if transition.get("request_kind") != "ADAPTIVE_POLICY_TRANSITION":
                raise PermissionError("adaptive policy acceptance requires a policy transition")
            aggregation_target = str(
                transition.get("aggregation_target_id")
                or extended_aggregation_target_id(
                    str(transition.get("target_id") or ""),
                    transition.get("aggregation_scope"),
                )
            )
            promotion_policy = promotion_policies.get(aggregation_target) or {}
            if promotion_policy.get("allow_persistent_acceptance") is not True:
                raise PermissionError(
                    "persistent adaptive policy acceptance is disabled by policy"
                )
            acceptance = adaptive_aggregation_store.record_policy_transition_acceptance(
                request_id,
                accepted_by=f"uid:{credentials[1]}",
                reason=reason,
                policy_allows_persistent_acceptance=True,
                current_generations=current_generations,
                current_policy_fingerprints=policy_fingerprints,
                authority_policy_generation=str(authority.effective.generation),
                authority_policy_fingerprint=authority.effective.fingerprint,
                authority_type="operator",
                incident_id=str(request.get("incident_id") or "").strip() or None,
                artifact_signer=runtime.writer.signing_service,
            )
            runtime.event(
                logger_name="caretaker.adaptive",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Adaptive policy transition accepted for persistent deployment review",
                fields={
                    "transition_request_id": request_id,
                    "acceptance_id": acceptance.get("acceptance_id"),
                    "target_id": transition.get("target_id"),
                    "policy_id": acceptance.get("policy_id"),
                    "policy_mutated": False,
                    "authority_granted": False,
                },
                origin="caretaker",
            )
            runtime.audit.emit(
                "POLICY_ACCEPTED",
                actor={"type": "operator", "id": f"uid:{credentials[1]}"},
                scope={
                    "target_id": transition.get("target_id"),
                    "aggregation_scope": transition.get("aggregation_scope"),
                    "transition_id": request_id,
                },
                policy={
                    "prior_policy_id": acceptance.get("prior_policy_id"),
                    "policy_id": acceptance.get("policy_id"),
                    "prior_fingerprint": acceptance.get("prior_policy_fingerprint"),
                    "fingerprint": acceptance.get("policy_fingerprint"),
                    "authority_type": "operator",
                    "authority_generation": authority.effective.generation,
                    "fields_affected": acceptance.get("fields_affected"),
                },
                outcome={
                    "state": "ACCEPTED",
                    "effective_at": acceptance.get("effective_at"),
                    "reason": reason,
                },
                details={
                    "acceptance_id": acceptance.get("acceptance_id"),
                    "policy_mutated": False,
                    "authority_granted": False,
                    "deployment_handoff_required": True,
                },
                priority=EvidencePriority.CRITICAL,
            )
            _emit_adaptive_policy_transition_audit(
                runtime,
                {**transition, **acceptance},
                state="ACCEPTED",
                actor_type="operator",
                actor_id=f"uid:{credentials[1]}",
                details={
                    "acceptance_id": acceptance.get("acceptance_id"),
                    "deployment_handoff_required": True,
                },
            )
            return {
                "ok": True,
                "transition_request_id": request_id,
                "acceptance": acceptance,
                "policy_mutated": False,
                "authority_granted": False,
                "deployment_handoff_required": True,
            }
        if command == "adaptive-threshold-rollback":
            request_id = str(request.get("request_id") or "").strip()
            if not request_id:
                raise ValueError("adaptive-threshold-rollback requires request_id")
            if request.get("confirm") is not True:
                raise PermissionError(
                    "adaptive-threshold-rollback requires confirm=true"
                )
            reason = str(request.get("reason") or "").strip()
            if not reason:
                raise ValueError("adaptive threshold rollback requires an operator reason")
            transitions = [
                item
                for item in adaptive_aggregation_store.list_transition_requests()
                if item.get("request_kind") == "ADAPTIVE_POLICY_TRANSITION"
                and str(item.get("request_id") or "") == request_id
            ]
            if len(transitions) != 1:
                raise KeyError(f"No adaptive policy transition found for {request_id}")
            transition = transitions[0]
            if transition.get("rollback_status") == "ROLLED_BACK":
                return {
                    "ok": True,
                    "transition_request_id": request_id,
                    "already_rolled_back": True,
                    "rollback": transition.get("rollback"),
                    "authority_granted": False,
                }
            if transition.get("status") == "APPLIED":
                raise PermissionError(
                    "accepted adaptive policy transitions require a new incident"
                )
            lease_id = str(transition.get("authority_lease_id") or "").strip() or None
            if lease_id:
                active_lease_ids = {
                    str(lease.lease_id) for lease in authority.effective.runtime_leases
                }
                if lease_id in active_lease_ids:
                    authority.release_runtime_lease(UUID(lease_id))
                    runtime.refresh_authority_policy()
                    authority_generation_holder["generation"] = authority.effective.generation
                    if unix_socket_exists(runtime_control_socket):
                        response = control_request(
                            runtime_control_socket,
                            {
                                "command": "policy-authority-update",
                                "snapshot": authority.effective.snapshot_dict(),
                            },
                        )
                        if response.get("ok") is False:
                            raise RuntimeError(
                                str(response.get("error", "application rejected authority rollback"))
                            )
            rollback = adaptive_aggregation_store.record_transition_rollback(
                request_id,
                rolled_back_by=f"uid:{credentials[1]}",
                reason=reason,
                authority_lease_id=lease_id,
            )
            runtime.event(
                logger_name="caretaker.adaptive",
                severity=30,
                channel=LogChannel.AUDIT,
                message="Adaptive policy transition rolled back before acceptance",
                fields={
                    "transition_request_id": request_id,
                    "proposal_request_id": transition.get("proposal_request_id"),
                    "target_id": transition.get("target_id"),
                    "lease_id": lease_id,
                    "policy_applied": False,
                    "authority_granted": False,
                },
                origin="caretaker",
            )
            runtime.audit.emit(
                "POLICY_ROLLED_BACK",
                actor={"type": "operator", "id": f"uid:{credentials[1]}"},
                scope={
                    "target_id": transition.get("target_id"),
                    "aggregation_scope": transition.get("aggregation_scope"),
                    "transition_id": request_id,
                },
                policy={
                    "prior_policy_id": transition.get("prior_policy_id"),
                    "policy_id": transition.get("policy_id"),
                    "prior_fingerprint": transition.get("previous_policy_fingerprint"),
                    "fingerprint": transition.get("policy_fingerprint"),
                    "authority_type": transition.get("authority_type"),
                },
                outcome={
                    "state": "ROLLED_BACK",
                    "reason": reason,
                },
                details={
                    "rollback_recorded": True,
                    "authority_granted": False,
                },
                priority=EvidencePriority.CRITICAL,
            )
            _emit_adaptive_policy_transition_audit(
                runtime,
                {**transition, **rollback},
                state="ROLLED_BACK",
                actor_type="operator",
                actor_id=f"uid:{credentials[1]}",
                details={"rollback_recorded": True},
            )
            return {
                "ok": True,
                "transition_request_id": request_id,
                "rollback": rollback,
                "authority_policy": authority.effective.snapshot_dict(),
                "authority_granted": False,
            }
        if command == "adaptive-transition-ack":
            adaptive_context = current_adaptive_context()
            if adaptive_context is None:
                raise PermissionError(
                    "adaptive transition acknowledgement requires current worker context"
                )
            current_generations, policy_fingerprints, _ = adaptive_context
            effective_authority = authority.effective
            acknowledgement = adaptive_aggregation_store.acknowledge_transition(
                request,
                peer_pid=credentials[0],
                current_generations=current_generations,
                policy_fingerprints=policy_fingerprints,
                authority_policy_generation=str(effective_authority.generation),
                authority_policy_fingerprint=effective_authority.fingerprint,
            )
            _emit_adaptive_policy_transition_audit(
                runtime,
                request,
                state=str(acknowledgement.get("transition_status") or "ACKNOWLEDGED"),
                actor_type="worker",
                actor_id=str(request.get("worker_id") or "worker"),
                details={
                    "acknowledgement_status": acknowledgement.get("status"),
                    "worker_pid": credentials[0],
                    "applied": request.get("applied"),
                    "observed_level": request.get("observed_level"),
                },
            )
            return {
                "ok": True,
                "acknowledgement": acknowledgement,
            }
        if command == "adaptive-aggregation-ack":
            batch_id = str(request.get("batch_id") or "").strip()
            if not batch_id:
                raise ValueError("adaptive-aggregation-ack requires batch_id")
            return {
                "ok": True,
                "acknowledgement": adaptive_aggregation_store.acknowledgement(batch_id),
            }
        if command == "incident-capsule-list":
            raw_incident_id = str(request.get("incident_id") or "").strip() or None
            incident_id = UUID(raw_incident_id) if raw_incident_id else None
            limit = max(1, min(int(request.get("limit", 100)), 200))
            return {
                "ok": True,
                "capsules": capsule_store.list_summaries(
                    incident_id=incident_id,
                    limit=limit,
                ),
            }
        if command == "incident-capsule-replay-results":
            replay_results = ReplayResultStore(policy.directory, create_directory=False)
            digest = str(request.get("content_sha256") or "").strip() or None
            if digest is not None:
                return {
                    "ok": True,
                    "read_only": True,
                    "integrity_verified": True,
                    "result": replay_results.load(digest),
                }
            limit = max(1, min(int(request.get("limit", 100)), 500))
            return {
                "ok": True,
                "read_only": True,
                "results": replay_results.list_summaries(limit=limit),
            }
        if command == "regression-fixture-list":
            target_id = str(request.get("target_id") or "").strip() or None
            limit = max(1, min(int(request.get("limit", 100)), 500))
            if regression_fixture_store is None:
                return {"ok": True, "enabled": False, "fixtures": []}
            return {
                "ok": True,
                "enabled": True,
                "fixtures": regression_fixture_store.list_summaries(
                    target_id=target_id,
                    limit=limit,
                ),
            }
        if command == "regression-fixture-get":
            fixture_id = str(request.get("fixture_id") or "").strip()
            if not fixture_id:
                raise ValueError("regression-fixture-get requires fixture_id")
            if regression_fixture_store is None:
                raise PermissionError("logging.regression.enabled=False")
            return {
                "ok": True,
                "envelope": regression_fixture_store.load(fixture_id),
                "integrity_verified": True,
                "replay_status": "DATA_ONLY_NOT_EXECUTABLE",
            }
        if command == "incident-capsule-get":
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            if not raw_capsule_id:
                raise ValueError("incident-capsule-get requires capsule_id")
            revision_value = request.get("revision")
            revision = int(revision_value) if revision_value is not None else None
            return {
                "ok": True,
                "envelope": capsule_store.load(raw_capsule_id, revision=revision),
                "integrity_verified": True,
            }
        if command == "incident-capsule-replay":
            if replay_coordinator is None:
                raise PermissionError(
                    "persistent regression fixtures are disabled; capsule replay is unavailable"
                )
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            fixture_id = str(request.get("fixture_id") or "").strip()
            entrypoint = str(request.get("entrypoint") or "").strip()
            source = request.get("source")
            if not raw_capsule_id:
                raise ValueError("incident-capsule-replay requires capsule_id")
            if not fixture_id:
                raise ValueError("incident-capsule-replay requires fixture_id")
            if not entrypoint:
                raise ValueError("incident-capsule-replay requires entrypoint")
            if not isinstance(source, str) or not source:
                raise ValueError("incident-capsule-replay requires source text")
            try:
                result = execute_capsule_replay(
                    replay_coordinator,
                    capsule_store,
                    capsule_id=raw_capsule_id,
                    fixture_id=fixture_id,
                    entrypoint=entrypoint,
                    source=source,
                )
            except Exception as exc:
                _emit_incident_replay_audit(
                    runtime,
                    replay_scope="selected",
                    actor_id=f"uid:{credentials[1]}",
                    request=request,
                    error=exc,
                )
                raise
            _emit_incident_replay_audit(
                runtime,
                replay_scope="selected",
                actor_id=f"uid:{credentials[1]}",
                request=request,
                result=result,
            )
            runtime.event(
                logger_name="caretaker.capsule",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Incident Capsule fixture replay completed",
                fields={
                    "capsule_id": result["capsule_id"],
                    "incident_id": result["incident_id"],
                    "fixture_id": result["fixture_id"],
                    "outcome": result["outcome"],
                    "backend_name": result["backend_name"],
                    "isolation_level": result["isolation_level"],
                    "capsule_modified": False,
                },
                origin="caretaker",
            )
            return {"ok": True, **result}
        if command == "incident-capsule-replay-batch":
            if replay_coordinator is None or regression_fixture_store is None:
                raise PermissionError(
                    "persistent regression fixtures are disabled; capsule replay is unavailable"
                )
            scope = str(request.get("scope") or "all").strip().lower()
            if scope not in {"incident", "all"}:
                raise ValueError(
                    "incident-capsule-replay-batch scope must be incident or all"
                )
            entrypoint = str(request.get("entrypoint") or "").strip()
            source = request.get("source")
            if not entrypoint:
                raise ValueError("incident-capsule-replay-batch requires entrypoint")
            if not isinstance(source, str) or not source:
                raise ValueError("incident-capsule-replay-batch requires source text")
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if scope == "incident" and not raw_incident_id:
                raise ValueError(
                    "incident-capsule-replay-batch incident scope requires incident_id"
                )
            incident_id = UUID(raw_incident_id) if raw_incident_id else None
            target_id = str(request.get("target_id") or "").strip() or None
            limit = max(1, min(int(request.get("limit", 50)), 200))
            summaries = regression_fixture_store.list_summaries(
                target_id=target_id,
                limit=500,
            )
            if incident_id is not None:
                summaries = tuple(
                    summary for summary in summaries
                    if str(summary.get("source_incident_id") or "") == str(incident_id)
                )
            try:
                result = execute_historical_capsule_replays(
                    replay_coordinator,
                    capsule_store,
                    summaries,
                    entrypoint=entrypoint,
                    source=source,
                    limit=limit,
                )
            except Exception as exc:
                _emit_incident_replay_audit(
                    runtime,
                    replay_scope=scope,
                    actor_id=f"uid:{credentials[1]}",
                    request=request,
                    error=exc,
                )
                raise
            _emit_incident_replay_audit(
                runtime,
                replay_scope=scope,
                actor_id=f"uid:{credentials[1]}",
                request=request,
                result=result,
            )
            runtime.event(
                logger_name="caretaker.capsule",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Historical Incident Capsule fixture replay batch completed",
                fields={
                    "scope": scope,
                    "fixture_count": result["fixture_count"],
                    "completed_count": result["completed_count"],
                    "dispatched_count": result["dispatched_count"],
                    "capsule_modified": False,
                },
                origin="caretaker",
            )
            return {"ok": True, "scope": scope, "non_interactive": True, **result}
        if command == "incident-capsule-artifact":
            raw_artifact_id = str(request.get("artifact_id") or "").strip()
            if not raw_artifact_id:
                raise ValueError("incident-capsule-artifact requires artifact_id")
            return {
                "ok": True,
                "envelope": capsule_store.load_artifact(raw_artifact_id),
                "integrity_verified": True,
            }
        if command == "incident-capsule-timeline":
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if not raw_incident_id:
                raise ValueError("incident-capsule-timeline requires incident_id")
            limit = max(1, min(int(request.get("limit", 100)), 200))
            return {
                "ok": True,
                "incident_id": raw_incident_id,
                "records": capsule_timeline(UUID(raw_incident_id), limit=limit),
                "evidence_status": "PERSISTED_LOG_WINDOW",
            }
        if command == "incident-capsule-assist":
            query = str(request.get("query") or "").strip()
            model = str(request.get("model") or "").strip()
            if not query:
                raise ValueError("incident-capsule-assist requires query")
            if not model:
                raise ValueError("incident-capsule-assist requires model")
            scope = str(request.get("scope") or "all").strip().lower()
            limit = max(1, min(int(request.get("limit", 50)), 50))
            if scope == "selected":
                raw_capsule_id = str(request.get("capsule_id") or "").strip()
                if not raw_capsule_id:
                    raise ValueError("selected Incident Capsule assistance requires capsule_id")
                summaries = [
                    item
                    for item in capsule_store.list_summaries(limit=200)
                    if str(item.get("capsule_id") or "") == raw_capsule_id
                ]
            elif scope == "incident":
                raw_incident_id = str(request.get("incident_id") or "").strip()
                if not raw_incident_id:
                    raise ValueError("incident-scoped assistance requires incident_id")
                summaries = capsule_store.list_summaries(
                    incident_id=UUID(raw_incident_id),
                    limit=limit,
                )
            elif scope == "all":
                summaries = capsule_store.list_summaries(limit=limit)
            else:
                raise ValueError("incident-capsule-assist scope must be selected, incident, or all")
            result = assist_capsules(
                capsule_store,
                summaries,
                query=query,
                model=model,
                endpoint=str(
                    request.get("endpoint")
                    or "http://127.0.0.1:11434/api/generate"
                ),
                timeline_provider=lambda incident_id: capsule_timeline(
                    incident_id,
                    limit=200,
                ),
            )
            return {
                "ok": True,
                "scope": scope,
                "non_interactive": True,
                **result,
            }
        if command == "incident-communication-draft":
            profile_id = str(request.get("audience_profile_id") or "").strip()
            if not profile_id:
                raise ValueError("incident-communication-draft requires audience_profile_id")
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if bool(raw_capsule_id) == bool(raw_incident_id):
                raise ValueError(
                    "incident-communication-draft requires exactly one of capsule_id or incident_id"
                )
            envelope = (
                capsule_store.load(raw_capsule_id)
                if raw_capsule_id
                else capsule_store.latest_for_incident(UUID(raw_incident_id))
            )
            if envelope is None:
                raise KeyError(f"No Incident Capsule found for incident {raw_incident_id}")
            raw_record = request.get("record", True)
            if not isinstance(raw_record, bool):
                raise ValueError("incident-communication-draft record must be boolean")
            result = generate_communication_draft(
                capsule_store,
                envelope,
                audience_profile_id=profile_id,
                policy=runtime.active_policy.communications,
                capsule_policy=runtime.active_policy.capsules,
                effective_policy_fingerprint=runtime.snapshot.content_hash,
                record=raw_record,
                run_id=runtime.run_id,
            )
            raw_tailor_model = request.get("tailor_model")
            if raw_tailor_model is not None:
                if not isinstance(raw_tailor_model, str) or not raw_tailor_model.strip():
                    raise ValueError("incident-communication-draft tailor_model must be non-empty text")
                raw_tailor_endpoint = request.get(
                    "tailor_endpoint",
                    "http://127.0.0.1:11434/api/generate",
                )
                if not isinstance(raw_tailor_endpoint, str) or not raw_tailor_endpoint.strip():
                    raise ValueError("incident-communication-draft tailor_endpoint must be non-empty text")
                result = {
                    **result,
                    "tailoring": tailor_communication_draft(
                        result,
                        policy=runtime.active_policy.communications,
                        model=raw_tailor_model,
                        endpoint=raw_tailor_endpoint,
                    ),
                }
            draft = result.get("draft") or {}
            recording = result.get("recording") or {}
            runtime.event(
                logger_name="caretaker.communication",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Incident communication draft generated",
                fields={
                    "draft_id": draft.get("draft_id"),
                    "audience_profile_id": draft.get("audience_profile_id"),
                    "source_capsule_id": draft.get("source_capsule_id"),
                    "recording_status": recording.get("status"),
                    "delivery_authorized": False,
                },
            )
            _emit_communication_audit(
                runtime,
                event_type="INCIDENT_COMMUNICATION_DRAFTED",
                result=result,
                actor_id="communication-drafter",
            )
            return {
                "ok": True,
                "reviewable": True,
                "delivery_authorized": False,
                **result,
            }
        if command == "incident-communication-review":
            draft_id = str(request.get("draft_id") or "").strip()
            decision = str(request.get("decision") or "").strip()
            reason = str(request.get("reason") or "").strip()
            if not draft_id:
                raise ValueError("incident-communication-review requires draft_id")
            if not decision:
                raise ValueError("incident-communication-review requires decision")
            if not reason:
                raise ValueError("incident-communication-review requires reason")
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if bool(raw_capsule_id) == bool(raw_incident_id):
                raise ValueError(
                    "incident-communication-review requires exactly one of capsule_id or incident_id"
                )
            envelope = (
                capsule_store.load(raw_capsule_id)
                if raw_capsule_id
                else capsule_store.latest_for_incident(UUID(raw_incident_id))
            )
            if envelope is None:
                raise KeyError(f"No Incident Capsule found for incident {raw_incident_id}")
            result = review_communication_draft(
                capsule_store,
                envelope,
                draft_id=draft_id,
                decision=decision,
                reason=reason,
                capsule_policy=runtime.active_policy.capsules,
                reviewer_identity=f"uid:{credentials[1]}",
                run_id=runtime.run_id,
            )
            review = result.get("review") or {}
            runtime.event(
                logger_name="caretaker.communication",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Incident communication draft reviewed",
                fields={
                    "draft_id": draft_id,
                    "review_decision": (review.get("metadata") or {}).get("review_decision"),
                    "recording_status": result.get("status"),
                    "delivery_authorized": False,
                },
            )
            _emit_communication_audit(
                runtime,
                event_type="INCIDENT_COMMUNICATION_REVIEWED",
                result=result,
                actor_id=f"uid:{credentials[1]}",
            )
            return {
                "ok": True,
                "reviewable": True,
                "delivery_authorized": False,
                **result,
            }
        if command == "incident-capsule-attach-view":
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if not raw_incident_id:
                raise ValueError("incident-capsule-attach-view requires incident_id")
            incident_id = UUID(raw_incident_id)
            operator_view = request.get("operator_view")
            if not isinstance(operator_view, str) or not operator_view.strip():
                raise ValueError("incident-capsule-attach-view requires a non-empty operator_view")
            tab_id = str(request.get("tab_id") or "unknown").strip() or "unknown"
            target_id = str(request.get("target_id") or "").strip() or None
            call_id = str(request.get("call_id") or "").strip() or None
            result = capsule_store.attach_artifact(
                incident_id,
                kind="operator-view",
                content={
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "tab_id": tab_id,
                    "target_id": target_id,
                    "incident_id": raw_incident_id,
                    "call_id": call_id,
                    "view": operator_view,
                },
                source="caretaker-console",
                operator_identity=f"uid:{credentials[1]}",
                metadata={"peer_pid": credentials[0], "peer_gid": credentials[2]},
                policy=runtime.active_policy.capsules,
                run_id=runtime.run_id,
                incident_state={
                    "incident_id": raw_incident_id,
                    "target_id": target_id,
                    "call_id": call_id,
                    "source_evidence": capsule_evidence_references(incident_id),
                    "capture_reason": "operator-view",
                },
            )
            capsule_payload = result["capsule"].get("capsule") or {}
            runtime.event(
                logger_name="caretaker.capsule",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Operator view attached to Incident Capsule",
                fields={
                    "incident_id": raw_incident_id,
                    "capsule_id": capsule_payload.get("capsule_id"),
                    "capsule_revision": capsule_payload.get("revision"),
                    "artifact_id": (result["artifact"].get("artifact") or {}).get("artifact_id"),
                    "artifact_content_sha256": (result["artifact"].get("integrity") or {}).get("content_sha256"),
                    "tab_id": tab_id,
                },
                origin="caretaker",
            )
            return {
                "ok": True,
                "capsule": capsule_payload,
                "artifact": result["artifact"].get("artifact"),
                "artifact_path": result["artifact_path"],
            }
        if command == "behavior-list":
            # Generation summaries are compact. Use the full bounded allowance so
            # the console can retain three generations across many subjects.
            limit = max(1, min(int(request.get("limit", 500)), 500))
            collection_status: dict[str, object] = {}
            if unix_socket_exists(runtime_control_socket):
                try:
                    collection_status = control_request(
                        runtime_control_socket,
                        {"command": "behavior-collection-status"},
                    )
                except OSError:
                    collection_status = {"available": False}
            return {
                "ok": True,
                "collection_id": behavior_collection_id,
                "revision": behavior_revision["value"],
                "snapshots": list(behavior_store.list_summaries(limit=limit)),
                "collection_status": collection_status,
            }

        if command == "behavior-get":
            snapshot_id = str(request.get("snapshot_id") or "").strip()
            if not snapshot_id:
                raise ValueError("behavior-get requires snapshot_id")
            return {"ok": True, "envelope": behavior_store.load(snapshot_id)}

        if command == "behavior-capture":
            if not unix_socket_exists(runtime_control_socket):
                raise RuntimeError("Application runtime is unavailable for behavior capture")
            scope = str(request.get("scope") or "function").strip().lower()
            subject = str(request.get("subject") or "").strip()
            if not subject:
                raise ValueError("behavior-capture requires subject")
            reason = str(request.get("reason") or "operator-requested behavior capture").strip()
            if not reason:
                raise ValueError("behavior-capture requires a non-empty reason")
            if len(reason) > 500:
                raise ValueError("behavior-capture reason exceeds the 500 character limit")
            requested_calls = max(1, min(int(request.get("calls", 50)), 1000))
            requested_at = datetime.now(timezone.utc).isoformat()
            request_id = str(uuid4())
            authority_fingerprint = authority.effective.fingerprint
            deployment_fingerprint_value = deployment_fingerprint()
            capture_request = {
                "command": "behavior-capture",
                "scope": scope,
                "subject": subject,
                "calls": requested_calls,
                "requested_by": f"uid:{credentials[1]}",
                "reason": reason,
                "priority": int(request.get("priority", 100)),
                "deadline": request.get("deadline"),
                "requested_generation": request.get("requested_generation"),
            }
            try:
                response = control_request(runtime_control_socket, capture_request)
            except OSError as exc:
                _emit_behavior_collection_audit(
                    runtime,
                    request=capture_request,
                    actor_id=f"uid:{credentials[1]}",
                    error=exc,
                )
                raise
            if response.get("ok") is False:
                _emit_behavior_collection_audit(
                    runtime,
                    request=capture_request,
                    result=response,
                    actor_id=f"uid:{credentials[1]}",
                )
                return response
            capture = dict(response["capture"])
            profile = capture.get("profile")
            observed_calls = (
                int(profile.get("call_count") or 0)
                if isinstance(profile, dict)
                else 0
            )
            collection_request = dict(capture.get("collection_request") or {})
            collection_request.update(
                {
                    "request_id": collection_request.get("request_id") or request_id,
                    "requested_at": collection_request.get("requested_at") or requested_at,
                    "requested_by": collection_request.get("requested_by") or f"uid:{credentials[1]}",
                    "reason": collection_request.get("reason") or reason,
                    "scope": collection_request.get("scope") or scope,
                    "subject": collection_request.get("subject") or subject,
                    "requested_calls": collection_request.get("requested_calls") or requested_calls,
                    "requested_generation": collection_request.get("requested_generation")
                    or capture.get("generation_id"),
                    "authority_policy_generation": authority.effective.generation,
                    "authority_policy_fingerprint": authority_fingerprint,
                    "observed_calls": observed_calls,
                    "outcome": collection_request.get("outcome") or "CAPTURED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            capture["collection_request"] = collection_request
            # Generation identity is derived from observed subject/code/
            # monitoring metadata, not request metadata. Previewing it keeps
            # the identity stable before the store adds sequence commitments.
            collection_request["observed_generation"] = snapshot_payload(
                capture,
                authority_fingerprint=authority_fingerprint,
                deployment_fingerprint=deployment_fingerprint_value,
            )["generation_id"]
            envelope = behavior_store.create(
                capture,
                authority_fingerprint=authority_fingerprint,
                deployment_fingerprint=deployment_fingerprint_value,
            )
            behavior_revision["value"] += 1
            snapshot = envelope["snapshot"]
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior snapshot captured",
                fields={
                    "snapshot_id": snapshot["snapshot_id"],
                    "scope": snapshot["scope"],
                    "subject_key": snapshot["subject_key"],
                    "code_hash": snapshot.get("code_hash"),
                    "collection_request_id": collection_request.get("request_id"),
                    "requested_by": collection_request.get("requested_by"),
                    "reason": collection_request.get("reason"),
                    "requested_calls": collection_request.get("requested_calls"),
                    "observed_calls": collection_request.get("observed_calls"),
                    "observed_generation": collection_request.get("observed_generation"),
                    "outcome": collection_request.get("outcome"),
                    "content_sha256": envelope["integrity"]["content_sha256"],
                    "signature_state": envelope["integrity"]["signature_state"],
                },
            )
            _emit_behavior_collection_audit(
                runtime,
                request=capture_request,
                capture=capture,
                actor_id=f"uid:{credentials[1]}",
            )
            return {"ok": True, "envelope": envelope}

        if command in {
            "behavior-collection-status",
            "behavior-collection-cancel",
            "behavior-collection-promote",
            "behavior-collection-auto-cycle",
        }:
            if not unix_socket_exists(runtime_control_socket):
                return {
                    "ok": True,
                    "collections": [],
                    "available": False,
                    "reason": "Application runtime is unavailable for collection status",
                }
            return control_request(runtime_control_socket, request)

        if command in {"behavior-compare", "behavior-previous-compare"}:
            snapshot_a_id = str(request.get("snapshot_a_id") or request.get("snapshot_id") or "").strip()
            if not snapshot_a_id:
                raise ValueError(f"{command} requires snapshot_a_id/snapshot_id")
            left = behavior_store.load(snapshot_a_id)
            if command == "behavior-previous-compare":
                current = left["snapshot"]
                candidates = [
                    item
                    for item in behavior_store.list()
                    if item.get("subject_key") == current.get("subject_key")
                    and str(item.get("created_at") or "") < str(current.get("created_at") or "")
                ]
                if not candidates:
                    raise KeyError("No earlier snapshot exists for this behavior subject")
                right_id = candidates[0]["snapshot_id"]
                right = left
                left = behavior_store.load(right_id)
            else:
                snapshot_b_id = str(request.get("snapshot_b_id") or "").strip()
                if not snapshot_b_id:
                    raise ValueError("behavior-compare requires snapshot_b_id")
                right = behavior_store.load(snapshot_b_id)
            return {"ok": True, "comparison": compare_snapshots(left, right)}

        if command == "behavior-live-compare":
            snapshot_id = str(request.get("snapshot_id") or "").strip()
            if not snapshot_id:
                raise ValueError("behavior-live-compare requires snapshot_id")
            if not unix_socket_exists(runtime_control_socket):
                raise RuntimeError("Application runtime is unavailable for live behavior comparison")
            left = behavior_store.load(snapshot_id)
            snapshot = left["snapshot"]
            scope = snapshot["scope"]
            subject_data = snapshot.get("subject") or {}
            subject = (
                subject_data.get("module_name")
                if scope == "module"
                else subject_data.get("target_id")
            )
            if not subject:
                raise ValueError("Stored snapshot does not identify a live comparison subject")
            response = control_request(
                runtime_control_socket,
                {
                    "command": "behavior-capture",
                    "scope": scope,
                    "subject": subject,
                    "calls": int(request.get("calls", 50)),
                    "requested_generation": snapshot.get("generation_id"),
                },
            )
            if response.get("ok") is False:
                return response
            live_profile = response.get("capture", {}).get("profile", {})
            if int(live_profile.get("call_count") or 0) <= 0:
                return {
                    "ok": False,
                    "error": {
                        "message": (
                            "The active unsaved behavior window contains no completed calls. "
                            "This action does not execute the function. Run the function, refresh "
                            "Behavior, and compare the newly persisted snapshot instead."
                        ),
                        "failure_kind": "empty-active-behavior-window",
                    },
                }
            current = wrap_snapshot(
                snapshot_payload(
                    response["capture"],
                    authority_fingerprint=authority.effective.fingerprint,
                    deployment_fingerprint=snapshot.get("deployment_fingerprint"),
                )
            )
            return {
                "ok": True,
                "comparison": compare_snapshots(left, current),
                "live_snapshot": current["snapshot"],
            }

        if command == "behavior-archive":
            subject_key = str(request.get("subject_key") or "").strip()
            generation_id = str(request.get("generation_id") or "").strip()
            reason = str(request.get("reason") or "").strip()
            if not subject_key or not generation_id:
                raise ValueError("behavior-archive requires subject_key and generation_id")
            if not reason:
                raise ValueError("behavior-archive requires an operator reason")
            path, snapshot_ids = behavior_store.archive_generation(
                subject_key,
                generation_id,
                reason=reason,
            )
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior snapshots archived",
                fields={
                    "snapshot_ids": snapshot_ids,
                    "snapshot_count": len(snapshot_ids),
                    "subject_key": subject_key,
                    "generation_id": generation_id,
                    "reason": reason,
                    "archive_path": str(path),
                },
            )
            return {
                "ok": True,
                "archive": str(path),
                "snapshot_count": len(snapshot_ids),
                "subject_key": subject_key,
                "generation_id": generation_id,
                "reason": reason,
            }

        if command == "behavior-archive-list":
            return {"ok": True, "archives": list(behavior_store.list_archives())}

        if command == "behavior-archive-verify":
            name = str(request.get("archive") or "").strip()
            if not name:
                raise ValueError("behavior-archive-verify requires archive")
            path = behavior_store.resolve_archive(name)
            return {"ok": True, "verification": behavior_store.verify_archive(path)}

        if command == "behavior-archive-restore":
            name = str(request.get("archive") or "").strip()
            if not name:
                raise ValueError("behavior-archive-restore requires archive")
            path = behavior_store.resolve_archive(name)
            restored = behavior_store.restore_archive(path)
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior archive restored",
                fields={"archive": path.name, "snapshot_ids": list(restored)},
            )
            return {"ok": True, "archive": path.name, "restored": list(restored)}

        if command == "behavior-delete":
            snapshot_id = str(request.get("snapshot_id") or "").strip()
            if not snapshot_id:
                raise ValueError("behavior-delete requires snapshot_id")
            behavior_store.delete(snapshot_id)
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=30,
                channel=LogChannel.GUARD,
                message="Behavior snapshot deleted",
                fields={"snapshot_id": snapshot_id},
            )
            return {"ok": True, "deleted": snapshot_id}

        if command == "behavior-assess-history":
            model = str(request.get("model") or "").strip()
            if not model:
                raise ValueError("behavior-assess-history requires an Ollama model")
            analyst = OllamaBehaviorSnapshotAnalyst(model)
            return {
                "ok": True,
                "assessment": analyst.assess_history(
                    behavior_store.list(),
                    objective=str(
                        request.get("objective")
                        or "Assess overall behavior snapshot history and identify meaningful changes or trends"
                    ),
                ),
            }

        if command == "behavior-assess":
            comparison = request.get("comparison")
            if not isinstance(comparison, dict):
                raise ValueError("behavior-assess requires comparison object")
            model = str(request.get("model") or "").strip()
            if not model:
                raise ValueError("behavior-assess requires an Ollama model")
            analyst = OllamaBehaviorSnapshotAnalyst(model)
            return {
                "ok": True,
                "assessment": analyst.assess(
                    comparison,
                    objective=str(request.get("objective") or "Assess behavior changes"),
                ),
            }

        if isinstance(command, str) and command.startswith("runtime-"):
            forwarded = dict(request)
            forwarded["command"] = command.removeprefix("runtime-")
            try:
                return control_request(runtime_control_socket, forwarded)
            except OSError as exc:
                return {"ok": False, "error": f"application runtime control unavailable: {exc}"}
        if command == "logs":
            limit = max(1, min(int(request.get("limit", 100)), 500))
            records = recent_log_records(limit)
            return {
                "ok": True,
                "records": [
                    {
                        "occurred_at": item.occurred_at.isoformat(),
                        "severity": item.severity,
                        "channel": item.channel.name,
                        "logger": item.logger_name,
                        "message": item.formatted_message or item.message_template,
                        "target_id": str(item.target_id) if item.target_id else None,
                        "record_id": str(item.record_id),
                        "call_id": str(item.call_id) if item.call_id else None,
                        "incident_id": str(item.incident_id) if item.incident_id else None,
                        "fields": dict(item.fields),
                    }
                    for item in records[-limit:]
                ],
            }
        if command == "investigate":
            interrogation_policy = runtime.active_policy.interrogation
            if not interrogation_policy.enabled:
                raise PermissionError("logging.interrogation.enabled=False")
            target = str(request.get("target") or "").strip()
            call_id = str(request.get("call_id") or "").strip()
            incident_id = str(request.get("incident_id") or "").strip()
            minutes = max(1, min(int(request.get("minutes", 15)), 24 * 60))
            objective = str(request.get("objective") or "Investigate the current Caretaker incident")
            now = datetime.now(timezone.utc)
            interrogation = InterrogationRequest(
                period_start=now - timedelta(minutes=minutes),
                period_end=now,
                target_ids=(target,) if target else (),
                call_ids=(UUID(call_id),) if call_id else (),
                incident_ids=(UUID(incident_id),) if incident_id else (),
                objective=objective,
            )
            behavior = ()
            if target and unix_socket_exists(runtime_control_socket):
                try:
                    response = control_request(
                        runtime_control_socket,
                        {"command": "guard-deviations", "target": target, "limit": 50},
                    )
                    behavior = tuple(
                        json.dumps(item, sort_keys=True, default=str)
                        for item in response.get("deviations", ())
                    )
                except OSError:
                    behavior = ()
            interrogator = LogInterrogator()
            bundle = interrogator.build_bundle(
                interrogation,
                tuple(recent_log_records(interrogation_policy.maximum_records)),
                behavior_deviations=behavior,
                maximum_representative_records=interrogation_policy.maximum_representative_records,
            )
            model = str(request.get("model") or "").strip()
            if model and not interrogation_policy.llm_enabled:
                raise PermissionError("logging.interrogation.llm_enabled=False")
            if model:
                provider = OllamaRootCauseProvider(
                    model=model,
                    endpoint=str(request.get("endpoint") or "http://127.0.0.1:11434/api/generate"),
                )
                assessment = provider.assess(bundle)
            else:
                assessment = interrogator.deterministic_assessment(bundle)
            return {
                "ok": True,
                "provider": "ollama" if model else "deterministic",
                "evidence_hash": bundle.evidence_hash,
                "omitted_record_count": bundle.omitted_record_count,
                "assessment": asdict(assessment),
            }
        if command == "authority-status":
            runtime_policy_match, _ = runtime_authority_match()
            return {
                "ok": True,
                **authority.effective.snapshot_dict(),
                "runtime_matches_supervisor": runtime_policy_match,
            }

        if command == "authority-lease-acquire-signed":
            descriptor = str(request.get("descriptor") or "").strip()
            if not descriptor:
                return {
                    "ok": False,
                    "error": "authority-lease-acquire-signed requires a signed lease descriptor",
                }
            lease_directory = (
                Path(runtime.active_policy.directory) / "policy" / "runtime-leases"
            ).resolve()
            descriptor_path = (lease_directory / descriptor).resolve()
            try:
                descriptor_path.relative_to(lease_directory)
            except ValueError:
                return {
                    "ok": False,
                    "error": "Signed runtime-lease descriptors must be below "
                    f"{lease_directory}",
                }
            reason = str(request.get("reason") or "signed temporary incident policy escalation")
            lease = authority.load_signed_runtime_lease_from_stack_file(
                descriptor_path,
                requested_by=f"uid:{credentials[1]}",
                reason=reason,
            )
            try:
                runtime.refresh_authority_policy()
                if unix_socket_exists(runtime_control_socket):
                    response = control_request(
                        runtime_control_socket,
                        {
                            "command": "policy-authority-update",
                            "snapshot": authority.effective.snapshot_dict(),
                        },
                    )
                    if response.get("ok") is False:
                        raise RuntimeError(
                            str(response.get("error", "application rejected authority policy"))
                        )
            except Exception:
                authority.release_runtime_lease(lease.lease_id)
                runtime.refresh_authority_policy()
                raise
            runtime.event(
                logger_name="caretaker.authority",
                severity=30,
                channel=LogChannel.CARETAKER_INTERNAL,
                message="Signed temporary authority policy lease acquired",
                fields={
                    "lease_id": str(lease.lease_id),
                    "requested_by": lease.requested_by,
                    "reason": lease.reason,
                    "expires_at": lease.expires_at.isoformat(),
                    "signature_state": lease.signature_state.value,
                    "source_layer_fingerprint": lease.source_layer_fingerprint,
                    "authority_generation": authority.effective.generation,
                    "authority_fingerprint": authority.effective.fingerprint,
                    "assurance": authority.effective.overall_assurance,
                },
            )
            return {
                "ok": True,
                "lease_id": str(lease.lease_id),
                "expires_at": lease.expires_at.isoformat(),
                "authority_policy": authority.effective.snapshot_dict(),
            }

        if command == "authority-lease-acquire":
            path = str(request.get("path") or "").strip()
            if not path:
                return {"ok": False, "error": "authority-lease-acquire requires path"}
            reason = str(request.get("reason") or "temporary incident policy escalation")
            duration_seconds = max(1, int(request.get("duration_seconds", 3600)))
            target_scope = str(request.get("target")) if request.get("target") else None
            if path.startswith("repair.") and not target_scope:
                return {
                    "ok": False,
                    "error": "Temporary repair.* authority leases require an explicit target id or glob",
                }
            setting = PolicySetting(
                path=path,
                value=request.get("value"),
                target=target_scope,
                override_constraints=bool(request.get("override_constraints", False)),
                reason=reason,
            )
            lease = authority.acquire_runtime_lease(
                settings=(setting,),
                requested_by=f"uid:{credentials[1]}",
                reason=reason,
                duration_seconds=duration_seconds,
            )
            try:
                runtime.refresh_authority_policy()
                if unix_socket_exists(runtime_control_socket):
                    response = control_request(
                        runtime_control_socket,
                        {
                            "command": "policy-authority-update",
                            "snapshot": authority.effective.snapshot_dict(),
                        },
                    )
                    if response.get("ok") is False:
                        raise RuntimeError(str(response.get("error", "application rejected authority policy")))
            except Exception:
                authority.release_runtime_lease(lease.lease_id)
                runtime.refresh_authority_policy()
                raise
            runtime.event(
                logger_name="caretaker.authority",
                severity=30,
                channel=LogChannel.CARETAKER_INTERNAL,
                message="Temporary authority policy lease acquired",
                fields={
                    "lease_id": str(lease.lease_id),
                    "requested_by": lease.requested_by,
                    "reason": lease.reason,
                    "expires_at": lease.expires_at.isoformat(),
                    "path": setting.path,
                    "target": setting.target,
                    "value": setting.value,
                    "override_constraints": setting.override_constraints,
                    "authority_generation": authority.effective.generation,
                    "authority_fingerprint": authority.effective.fingerprint,
                    "assurance": authority.effective.overall_assurance,
                },
            )
            return {
                "ok": True,
                "lease_id": str(lease.lease_id),
                "expires_at": lease.expires_at.isoformat(),
                "authority_policy": authority.effective.snapshot_dict(),
            }

        if command == "authority-lease-release":
            lease_id = UUID(str(request["lease_id"]))
            authority.release_runtime_lease(lease_id)
            runtime.refresh_authority_policy()
            if unix_socket_exists(runtime_control_socket):
                response = control_request(
                    runtime_control_socket,
                    {
                        "command": "policy-authority-update",
                        "snapshot": authority.effective.snapshot_dict(),
                    },
                )
                if response.get("ok") is False:
                    return response
            runtime.event(
                logger_name="caretaker.authority",
                severity=20,
                channel=LogChannel.CARETAKER_INTERNAL,
                message="Temporary authority policy lease released",
                fields={
                    "lease_id": str(lease_id),
                    "authority_generation": authority.effective.generation,
                    "authority_fingerprint": authority.effective.fingerprint,
                },
            )
            return {"ok": True, "released": str(lease_id), "authority_policy": authority.effective.snapshot_dict()}

        if command == "policy-effective":
            return {"ok": True, "requested_modes": [item.name for item in runtime.effective.requested_modes],
                    "effective_modes": [item.name for item in runtime.effective.effective_modes],
                    "overrides": [item.field_path for item in runtime.effective.overrides]}
        if command == "mode-acquire":
            mode = LoggingMode[str(request["mode"]).upper()]
            lease = runtime.acquire_mode(mode, requested_by=f"uid:{credentials[1]}", reason=str(request.get("reason", "operator request")))
            leases[str(lease.lease_id)] = lease
            return {"ok": True, "lease_id": str(lease.lease_id), "overrides": [item.field_path for item in lease.required_overrides]}
        if command == "mode-release":
            lease_id = UUID(str(request["lease_id"]))
            runtime.release_mode(lease_id)
            leases.pop(str(lease_id), None)
            return {"ok": True, "released": str(lease_id)}
        return {"ok": False, "error": "unsupported declarative command"}

    control = ControlSocketServer(control_socket, control_handler, allowed_uids={os.getuid()})
    control.start()
    control_thread = threading.Thread(target=control.serve_forever, name="caretaker-control-server", daemon=True)
    control_thread.start()

    env = os.environ.copy()
    env.update({
        "CARETAKER_SUPERVISED": "1",
        "CARETAKER_EVENT_SOCKET": str(event_socket),
        "CARETAKER_RUN_ID": str(runtime.run_id),
        "CARETAKER_APPLICATION_ID": policy.application_id,
        "CARETAKER_DATA_DIR": policy.directory,
        "CARETAKER_RUNTIME_CONTROL_SOCKET": str(runtime_control_socket),
        "CARETAKER_SUPERVISOR_CONTROL_SOCKET": str(control_socket),
        "CARETAKER_AUTHORITY_POLICY": str(authority.snapshot_path),
    })
    if args.policy:
        env["CARETAKER_LOGGING_POLICY"] = str(Path(args.policy).resolve())
    child = subprocess.Popen(
        [sys.executable, "-m", "caretaker.bootstrap", args.module, *args.module_args],
        env=env,
        start_new_session=True,
    )
    child_holder["child"] = child
    failure_store = SQLiteRepairStore(Path(policy.directory) / "repair.sqlite")
    failure_store_holder["store"] = failure_store
    rollout_ledger_holder["ledger"] = RepairRolloutLedger(
        policy=policy.rollout,
        store=failure_store,
        signer=runtime.writer.signing_service,
        audit_event=lambda event_type, **fields: runtime.audit.emit(
            event_type,
            priority=EvidencePriority.CRITICAL,
            **fields,
        ),
    )
    rollout_coordinator_holder["coordinator"] = RepairRolloutCoordinator(
        rollout_ledger_holder["ledger"],
        policy_fingerprint=runtime.effective.fingerprint,
        authority_fingerprint=authority.effective.fingerprint,
        store=failure_store,
    )
    supervisor = CaretakerApplicationSupervisor(
        runtime,
        application_pid=child.pid,
        application_process_group_id=os.getpgid(child.pid),
        application_process=child,
        acceptance_store_path=Path(policy.directory) / "worker-acceptance.sqlite",
        failure_store=failure_store,
    )
    supervisor_holder["supervisor"] = supervisor
    supervisor.start()
    writer_health = supervisor.workers.register(WorkerKind.WRITER, os.getpid())
    event_health = supervisor.workers.register(WorkerKind.EVENT_SERVER, os.getpid())
    control_health = supervisor.workers.register(WorkerKind.CONTROL_SERVER, os.getpid())

    collector = None
    collector_thread = None
    system_directory = str(Path(policy.directory) / "system")
    if args.policy:
        system_policy = load_system_policy(args.policy, default_directory=system_directory)
    else:
        system_policy = SystemCollectionPolicy(
            enabled=False,
            output=SystemOutputPolicy(directory=system_directory),
        )
    if args.system_data and not system_policy.enabled:
        system_policy = replace(system_policy, enabled=True)
    system_policy = authority.effective.apply_dataclass(system_policy, prefix="system")
    system_health = None
    if system_policy.enabled:
        collector = SystemDataCollector(system_policy, application_pid=child.pid)
        collector_thread = threading.Thread(target=collector.run, name="caretaker-system-collector", daemon=True)
        collector_thread.start()
        system_health = supervisor.workers.register(WorkerKind.SYSTEM_COLLECTOR, os.getpid())

    health_stop = threading.Event()
    system_restart_times: list[float] = []
    application_stop_requested = False
    system_failure_handled = False
    internal_failure_handled: set[UUID] = set()

    def handle_internal_worker_failure(
        worker: object,
        *,
        error_fingerprint: str,
    ) -> dict[str, object]:
        """Route an in-process caretaker worker failure through policy.

        These workers are owned by the application-scoped runtime, so this
        path can record evidence and select the configured failure action but
        deliberately has no process-spawn callback. Process orchestration
        remains an application/deployment responsibility.
        """
        nonlocal application_stop_requested
        worker_id = getattr(worker, "worker_id")
        if worker_id in internal_failure_handled:
            return {"ok": True, "action": "ALREADY_HANDLED"}
        failed_worker = supervisor.workers.mark_failed(
            worker_id,
            error_fingerprint=error_fingerprint,
        )
        result = supervisor.handle_worker_failure(
            failed_worker,
            policy=runtime.active_policy.worker_restart,
            create_incident=record_worker_failure,
            disable_component=lambda current: {
                "accepted": True,
                "component": current.worker_kind.name,
                "disabled": True,
                "authority_granted": False,
            },
        )
        internal_failure_handled.add(worker_id)
        if (
            result.get("action") == WorkerFailureAction.STOP_APPLICATION.name
            and not application_stop_requested
        ):
            application_stop_requested = True
        return result

    def record_worker_failure(envelope: dict[str, object]) -> dict[str, object]:
        try:
            capsule_result = create_worker_failure_incident_capsule(
                capsule_store,
                envelope,
                run_id=runtime.run_id,
                policy_fingerprint=runtime.snapshot.content_hash,
                authority_policy_generation=authority.effective.generation,
                authority_policy_fingerprint=authority.effective.fingerprint,
            )
        except Exception as exc:
            runtime.event(
                logger_name="caretaker.worker-failure",
                severity=40,
                channel=LogChannel.EMERGENCY,
                message="Caretaker worker failure retained without an Incident Capsule",
                fields={
                    **envelope,
                    "capsule_status": "FAILED",
                    "capsule_error": f"{type(exc).__name__}: {exc}"[:256],
                },
                origin="caretaker",
            )
            raise
        runtime.event(
            logger_name="caretaker.worker-failure",
            severity=40,
            channel=LogChannel.EMERGENCY,
            message="Caretaker worker failure recorded as a rolled-back transaction",
            fields={**envelope, **capsule_result},
            origin="caretaker",
        )
        return capsule_result

    def restart_system_collector(_worker: object) -> dict[str, object]:
        nonlocal collector, collector_thread
        if child.poll() is not None:
            return {"started": False, "reason": "application has exited"}
        restart_policy = runtime.active_policy.worker_restart
        now = time.monotonic()
        system_restart_times[:] = [
            value
            for value in system_restart_times
            if value >= now - restart_policy.restart_window_seconds
        ]
        delay = min(
            restart_policy.maximum_backoff_seconds,
            restart_policy.initial_backoff_seconds * (2 ** len(system_restart_times)),
        )
        if health_stop.wait(delay):
            return {"started": False, "reason": "supervisor stopping"}
        collector = SystemDataCollector(system_policy, application_pid=child.pid)
        collector_thread = threading.Thread(
            target=collector.run,
            name="caretaker-system-collector",
            daemon=True,
        )
        collector_thread.start()
        system_restart_times.append(time.monotonic())
        return {"started": True, "pid": os.getpid(), "backoff_seconds": delay}

    def disable_system_collector(_worker: object) -> dict[str, object]:
        nonlocal collector, collector_thread
        if collector is not None:
            collector.stop()
        previous_thread = collector_thread
        collector = None
        collector_thread = None
        if previous_thread is not None and previous_thread is not threading.current_thread():
            previous_thread.join(timeout=1)
        return {"disabled": True}

    def health_loop() -> None:
        nonlocal application_stop_requested, collector, collector_thread, system_failure_handled
        while not health_stop.wait(1.0):
            effective_authority = authority.effective
            materialize_behavior_snapshots(maximum=100)
            adaptive_result = reconcile_adaptive_aggregation(maximum=100)
            if adaptive_result is not None and (
                adaptive_result.get("merged")
                or adaptive_result.get("rejected")
                or adaptive_result.get("errors")
                or (adaptive_result.get("promotions") or {}).get("created")
            ):
                runtime.event(
                    logger_name="caretaker.adaptive",
                    severity=30 if adaptive_result.get("rejected") or adaptive_result.get("errors") else 20,
                    channel=LogChannel.CARETAKER_INTERNAL,
                    message="Supervisor reconciled adaptive worker observations",
                    fields={
                        "merged": adaptive_result.get("merged", 0),
                        "duplicates": adaptive_result.get("duplicates", 0),
                        "rejected": adaptive_result.get("rejected", 0),
                        "errors": adaptive_result.get("errors", []),
                        "promotion_requests_created": (
                            adaptive_result.get("promotions") or {}
                        ).get("created", 0),
                        "pending": adaptive_result.get("pending", 0),
                        "authority_policy_generation": effective_authority.generation,
                        "authority_policy_fingerprint": effective_authority.fingerprint,
                    },
                )
            if unix_socket_exists(runtime_control_socket):
                try:
                    automatic_response = control_request(
                        runtime_control_socket,
                        {"command": "behavior-collection-auto-cycle"},
                    )
                    for cycle in automatic_response.get("cycles", ()):
                        for promotion in cycle.get("promoted", ()):
                            runtime.event(
                                logger_name="caretaker.behavior",
                                severity=20,
                                channel=LogChannel.GUARD,
                                message="Automatic behavior collection promotion",
                                fields={
                                    "target_id": promotion.get("target_id"),
                                    "generation_id": promotion.get("generation_id"),
                                    "requested_by": promotion.get("requested_by"),
                                    "reason": promotion.get("reason"),
                                    "authority_policy_generation": authority.effective.generation,
                                    "authority_policy_fingerprint": authority.effective.fingerprint,
                                },
                            )
                        for outcome in cycle.get("outcomes", ()):
                            target_id = str(outcome.get("target_id") or "").strip()
                            if not target_id:
                                continue
                            generation_id = str(outcome.get("generation_id") or "").strip()
                            outcome_state = str(outcome.get("outcome") or "FAILED").strip().upper()
                            _emit_behavior_collection_audit(
                                runtime,
                                request={
                                    "scope": "function",
                                    "subject": target_id,
                                    "requested_by": "caretaker:auto",
                                    "reason": "automatic coverage backlog promotion",
                                    "requested_generation": generation_id,
                                },
                                capture={
                                    "collection_request": {
                                        "scope": "function",
                                        "subject": target_id,
                                        "requested_by": "caretaker:auto",
                                        "reason": "automatic coverage backlog promotion",
                                        "requested_generation": generation_id,
                                        "observed_generation": generation_id,
                                        "outcome": outcome_state,
                                        "snapshot_id": outcome.get("snapshot_id"),
                                    }
                                },
                                actor_id="application-supervisor",
                                actor_type="supervisor",
                            )
                except OSError:
                    pass
            current_leases = {
                str(lease.lease_id): lease for lease in effective_authority.runtime_leases
            }
            now_utc = datetime.now(timezone.utc)
            for lease_id, previous_lease in tuple(authority_lease_holder.items()):
                if lease_id not in current_leases and previous_lease.expires_at <= now_utc:
                    runtime.event(
                        logger_name="caretaker.authority",
                        severity=20,
                        channel=LogChannel.CARETAKER_INTERNAL,
                        message="Temporary authority policy lease expired",
                        fields={
                            "lease_id": lease_id,
                            "authority_id": previous_lease.authority_id,
                            "requested_by": previous_lease.requested_by,
                            "reason": previous_lease.reason,
                            "expires_at": previous_lease.expires_at.isoformat(),
                        },
                    )
            authority_lease_holder.clear()
            authority_lease_holder.update(current_leases)
            if effective_authority.generation != authority_generation_holder["generation"]:
                runtime.refresh_authority_policy()
                authority_generation_holder["generation"] = effective_authority.generation
                if unix_socket_exists(runtime_control_socket):
                    try:
                        control_request(
                            runtime_control_socket,
                            {
                                "command": "policy-authority-update",
                                "snapshot": effective_authority.snapshot_dict(),
                            },
                        )
                    except OSError:
                        pass
                runtime.event(
                    logger_name="caretaker.authority",
                    severity=20,
                    channel=LogChannel.CARETAKER_INTERNAL,
                    message="Authority policy generation changed",
                    fields={
                        "generation": effective_authority.generation,
                        "fingerprint": effective_authority.fingerprint,
                        "assurance": effective_authority.overall_assurance,
                    },
                )
            runtime_match, _ = runtime_authority_match()
            previous_match = authority_runtime_match_holder["match"]
            if runtime_match is False and unix_socket_exists(runtime_control_socket):
                try:
                    control_request(
                        runtime_control_socket,
                        {
                            "command": "policy-authority-update",
                            "snapshot": effective_authority.snapshot_dict(),
                        },
                    )
                except OSError:
                    pass
            if runtime_match is not None and runtime_match != previous_match:
                authority_runtime_match_holder["match"] = runtime_match
                runtime.event(
                    logger_name="caretaker.authority",
                    severity=50 if not runtime_match else 20,
                    channel=LogChannel.CARETAKER_INTERNAL,
                    message=(
                        "Application authority policy fingerprint does not match supervisor"
                        if not runtime_match
                        else "Application authority policy fingerprint matches supervisor"
                    ),
                    fields={
                        "runtime_matches_supervisor": runtime_match,
                        "authority_generation": effective_authority.generation,
                        "authority_fingerprint": effective_authority.fingerprint,
                    },
                )
            elif runtime_match is None:
                authority_runtime_match_holder["match"] = None

            supervisor.workers.heartbeat(supervisor.supervisor_health.worker_id, state=WorkerState.HEALTHY)
            if runtime.sink._thread.is_alive():
                state = WorkerState.DEGRADED if runtime.sink.last_error else WorkerState.HEALTHY
                supervisor.workers.heartbeat(
                    writer_health.worker_id,
                    state=state,
                    queue_depth=runtime.sink._queue.qsize(),
                )
            else:
                handle_internal_worker_failure(
                    writer_health,
                    error_fingerprint=(
                        type(runtime.sink.last_error).__name__
                        if runtime.sink.last_error
                        else "writer-thread-stopped"
                    ),
                )
            if server_thread.is_alive():
                supervisor.workers.heartbeat(event_health.worker_id, state=WorkerState.HEALTHY)
            else:
                handle_internal_worker_failure(
                    event_health,
                    error_fingerprint="event-server-stopped",
                )
            if control_thread.is_alive():
                supervisor.workers.heartbeat(control_health.worker_id, state=WorkerState.HEALTHY)
            else:
                handle_internal_worker_failure(
                    control_health,
                    error_fingerprint="control-server-stopped",
                )
            if system_health is not None and collector_thread is not None:
                if collector_thread.is_alive():
                    system_failure_handled = False
                    supervisor.workers.heartbeat(system_health.worker_id, state=WorkerState.HEALTHY)
                elif not system_failure_handled:
                    failed_worker = supervisor.workers.mark_failed(
                        system_health.worker_id,
                        error_fingerprint="system-collector-stopped",
                    )
                    restart_policy = runtime.active_policy.worker_restart
                    if child.poll() is not None:
                        restart_policy = replace(
                            restart_policy,
                            enabled=False,
                        )
                    failure_result = supervisor.handle_worker_failure(
                        failed_worker,
                        policy=restart_policy,
                        create_incident=record_worker_failure,
                        restart_worker=restart_system_collector,
                        disable_component=disable_system_collector,
                    )
                    system_failure_handled = True
                    if failure_result.get("action") == "RESTARTED":
                        runtime.event(
                            logger_name="caretaker.watchdog",
                            severity=30,
                            channel=LogChannel.CARETAKER_INTERNAL,
                            message="Restarted failed Caretaker system collector",
                            fields={
                                "worker_id": str(system_health.worker_id),
                                "restart_count": failure_result["restart"]["restart_count"],
                                "backoff_seconds": (
                                    failure_result["restart"].get("backoff_seconds")
                                    if isinstance(failure_result.get("restart"), dict)
                                    else None
                                ),
                            },
                        )
                    elif (
                        failure_result.get("action") == WorkerFailureAction.STOP_APPLICATION.name
                        and not application_stop_requested
                    ):
                        application_stop_requested = True
                        shutdown = failure_result.get("action_result")
                        runtime.event(
                            logger_name="caretaker.watchdog",
                            severity=50,
                            channel=LogChannel.EMERGENCY,
                            message="System collector restart policy exhausted; stopping application boundary",
                            fields={
                                "worker_id": str(system_health.worker_id),
                                "shutdown_reason": "system_collector_restart_exhausted",
                                "shutdown": shutdown,
                            },
                        )

    health_thread = threading.Thread(target=health_loop, name="caretaker-health-monitor", daemon=True)
    health_thread.start()
    try:
        return child.wait()
    finally:
        health_stop.set()
        health_thread.join(timeout=3)
        materialize_behavior_snapshots(maximum=10_000)
        if collector:
            collector.stop()
        if collector_thread:
            collector_thread.join(timeout=10)
        control.stop()
        server.stop()
        supervisor.watchdog.stop()
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
