from __future__ import annotations

import dataclasses
import os
import threading
import traceback
import weakref
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .authority import AuthorityPolicyError, get_authority_runtime_context
from .control_plane import SignalSeverity
from .evidence.identity import identify_module


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            field.name: _jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, (UUID, Path)):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    if callable(value):
        return f"{getattr(value, '__module__', '')}.{getattr(value, '__qualname__', repr(value))}"
    return value


def _request_value(request: dict[str, Any], key: str) -> str | None:
    value = request.get(key)
    if value in (None, ""):
        return None
    return str(value)


def _bounded_message(exception: BaseException, limit: int = 2048) -> str:
    message = str(exception)
    return message if len(message) <= limit else message[: limit - 3] + "..."


def _emit_unsupervised_behavior_collection_audit(
    *,
    request: dict[str, Any],
    capture: Any,
    actor_id: str,
) -> None:
    """Audit a local collection while leaving supervised ownership unchanged."""
    from .logging.handler import get_runtime

    runtime = get_runtime()
    if runtime is None or getattr(runtime, "supervised", False):
        # A supervised child must not write or submit this event. Its parent
        # supervisor emits the authoritative record after receiving the result.
        return
    from .run import _emit_behavior_collection_audit

    _emit_behavior_collection_audit(
        runtime,
        request=request,
        capture=capture if isinstance(capture, dict) else None,
        actor_id=actor_id,
        actor_type="caretaker",
    )


def control_failure_response(
    request: dict[str, Any],
    credentials: tuple[int, int, int],
    exception: BaseException,
    *,
    include_debug: bool = False,
) -> dict[str, Any]:
    """Build a stable JSON diagnostic for a failed runtime-control operation.

    This helper deliberately does not persist evidence itself. The bootstrap
    socket boundary owns persistence so direct registry callers keep their
    existing exception semantics.
    """
    command = str(request.get("command", "")).strip().lower() or "<missing>"

    if isinstance(exception, AuthorityPolicyError):
        failure_domain = "POLICY"
        failure_kind = "policy-rejection"
        event_name = "caretaker.operator.policy_rejected"
        severity = 30
        decision = "rejected"
    elif isinstance(exception, (ValueError, KeyError)):
        failure_domain = "CONTROL_PLANE"
        failure_kind = "request-rejected"
        event_name = "caretaker.operator.request_rejected"
        severity = 30
        decision = "rejected"
    else:
        failure_domain = "CARETAKER_INTERNAL"
        failure_kind = "internal-exception"
        event_name = "caretaker.internal.operation.failed"
        severity = 40
        decision = "failed"

    authority = get_authority_runtime_context().effective
    message = _bounded_message(exception)
    error: dict[str, Any] = {
        "diagnostic_id": str(uuid4()),
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "event": event_name,
        "severity": severity,
        "failure_domain": failure_domain,
        "failure_kind": failure_kind,
        "component": "operator.runtime",
        "operation": command,
        "stage": "control-request",
        "outcome": "failed",
        "decision": decision,
        "reason": message,
        "exception_type": type(exception).__name__,
        "exception_module": type(exception).__module__,
        "message": message,
        "target_id": _request_value(request, "target"),
        "call_id": _request_value(request, "call_id"),
        "incident_id": _request_value(request, "incident_id"),
        "episode_id": _request_value(request, "episode_id"),
        "attempt_id": _request_value(request, "attempt_id"),
        "candidate_id": _request_value(request, "candidate_id"),
        "authority_policy_generation": authority.generation,
        "authority_policy_fingerprint": authority.fingerprint,
        "authority_policy_assurance": authority.overall_assurance,
        "authority_policy_violation_count": len(authority.violations),
        "peer_pid": credentials[0],
        "peer_uid": credentials[1],
        "peer_gid": credentials[2],
        "retryable": False,
        "diagnostic_persisted": False,
    }
    if include_debug:
        rendered_traceback = "".join(
            traceback.format_exception(
                type(exception), exception, exception.__traceback__
            )
        )
        error["debug"] = {
            "traceback": rendered_traceback[-8192:],
            "request_keys": sorted(str(key) for key in request),
        }
    return {"ok": False, "error": error}


_SEVERITY_RANK = {
    SignalSeverity.INFO: 0,
    SignalSeverity.LOW: 1,
    SignalSeverity.MEDIUM: 2,
    SignalSeverity.HIGH: 3,
    SignalSeverity.CRITICAL: 4,
}


class OperatorRuntimeRegistry:
    """Process-local registry used by the Caretaker operator console.

    The registry intentionally holds weak references. Creating a RepairEngine or
    GuardEngine makes it observable by the local control plane without changing
    ownership or lifetime of the application objects.
    """

    def __init__(self) -> None:
        self._repair_engines: weakref.WeakSet[Any] = weakref.WeakSet()
        self._guard_engines: weakref.WeakSet[Any] = weakref.WeakSet()
        self._lock = threading.RLock()

    def register_repair_engine(self, engine: Any) -> None:
        with self._lock:
            self._repair_engines.add(engine)

    def register_guard_engine(self, engine: Any) -> None:
        with self._lock:
            self._guard_engines.add(engine)

    def repair_engines(self) -> tuple[Any, ...]:
        with self._lock:
            return tuple(self._repair_engines)

    def guard_engines(self) -> tuple[Any, ...]:
        with self._lock:
            return tuple(self._guard_engines)

    def _repair_engine_for_target(self, target_id: str) -> Any:
        for engine in self.repair_engines():
            if engine.registry.find(target_id) is not None:
                return engine
        raise KeyError(f"No Repair target registered as {target_id!r}")

    def _guard_engine_for_target(self, target_id: str) -> Any:
        for engine in self.guard_engines():
            if target_id in engine.registered_target_ids():
                return engine
        repair = self._repair_engine_for_target(target_id)
        if repair.guard is not None:
            return repair.guard
        raise KeyError(f"No Guard target registered as {target_id!r}")

    def status(self) -> dict[str, Any]:
        repairs = self.repair_engines()
        guards = self.guard_engines()
        active_incidents: list[dict[str, Any]] = []
        validations: list[dict[str, Any]] = []
        pending = []
        targets: set[str] = set()
        degraded: set[str] = set()

        for engine in repairs:
            targets.update(target.target_id for target in engine.registry.all())
            activity = engine.runtime_activity()
            active_incidents.extend(activity["active_incidents"])
            validations.extend(activity["active_validations"])
            pending.extend(engine.pending_approvals())

        recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        recent_signals = []
        for guard in guards:
            targets.update(guard.registered_target_ids())
            recent_signals.extend(
                signal
                for signal in guard.control_plane.signals
                if signal.occurred_at >= recent_cutoff
            )
            if guard.missing_logging_capabilities:
                degraded.update(
                    f"guard:{capability.name.lower()}"
                    for capability in guard.missing_logging_capabilities
                )

        alert = max(
            (signal.severity for signal in recent_signals),
            key=lambda severity: _SEVERITY_RANK[severity],
            default=None,
        )
        alert_name = alert.name if alert is not None else "NONE"

        if validations:
            current = "VALIDATING"
        elif active_incidents:
            current = "INCIDENT_ACTIVE"
        elif pending:
            current = "AWAITING_APPROVAL"
        elif alert is not None and _SEVERITY_RANK[alert] >= _SEVERITY_RANK[SignalSeverity.HIGH]:
            current = "ALERT"
        elif degraded:
            current = "DEGRADED"
        else:
            current = "HEALTHY"

        authority = get_authority_runtime_context().effective
        return {
            "pid": os.getpid(),
            "current_status": current,
            "alert_level": alert_name,
            "active_incident_count": len(active_incidents),
            "active_incidents": active_incidents,
            "validation_count": len(validations),
            "validating_functions": sorted(
                {str(item.get("target_id")) for item in validations if item.get("target_id")}
            ),
            "active_validations": validations,
            "pending_approval_count": len(pending),
            "target_count": len(targets),
            "degraded_components": sorted(degraded),
            "repair_engine_count": len(repairs),
            "guard_engine_count": len(guards),
            "authority_policy": {
                "generation": authority.generation,
                "fingerprint": authority.fingerprint,
                "overall_assurance": authority.overall_assurance,
                "violations": len(authority.violations),
                "layers": authority.layer_status(),
            },
        }

    def targets(self) -> list[dict[str, Any]]:
        # Imported lazily because adaptive instrumentation publishes into the
        # operator registry and therefore already depends on this module.
        from .adaptive import get_adaptive_state

        result: dict[str, dict[str, Any]] = {}
        for engine in self.repair_engines():
            for target in engine.registry.all():
                version = target.slot.load()
                adaptive = dict(get_adaptive_state(target.target_id) or {})
                result[target.target_id] = {
                    "target_id": target.target_id,
                    "display_name": target.display_name,
                    "module": target.source.module_name,
                    "qualified_name": target.source.qualified_name,
                    "repair_mode": target.policy.mode.name,
                    "repair_authority": target.policy.authority.name,
                    "integrity_class": target.integrity_class.name,
                    "slot_role": target.slot.role.name,
                    "function_version": version.number,
                    "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                    "repair_in_progress": target.slot.state.name == "REPAIRING",
                    "guard_enabled": target.policy.guard.enabled,
                    "observation_level": adaptive.get("level"),
                    "lifecycle_stage": adaptive.get("stage"),
                    "lifecycle_label": adaptive.get("stage_label"),
                    "escalation_reason": adaptive.get("promotion_reason"),
                }
        for guard in self.guard_engines():
            for target_id in guard.registered_target_ids():
                adaptive = dict(get_adaptive_state(target_id) or {})
                result.setdefault(
                    target_id,
                    {
                        "target_id": target_id,
                        "display_name": target_id,
                        "repair_mode": None,
                        "repair_authority": None,
                        "integrity_class": None,
                        "slot_role": "DEPENDENCY_BOUNDARY" if adaptive else None,
                        "function_version": None,
                        "candidate_id": None,
                        "repair_in_progress": False,
                        "guard_enabled": True,
                        "observation_level": adaptive.get("level"),
                        "lifecycle_stage": adaptive.get("stage"),
                        "lifecycle_label": adaptive.get("stage_label"),
                        "escalation_reason": adaptive.get("promotion_reason"),
                    },
                )
        return [result[key] for key in sorted(result)]

    def target_state(self, target_id: str) -> dict[str, Any]:
        engine = self._repair_engine_for_target(target_id)
        target = engine.registry.get(target_id)
        return {
            "target_id": target_id,
            "slot": _jsonable(target.slot.snapshot()),
            "support": _jsonable(target.support),
            "registered_cases": _jsonable(target.registered_cases),
            "tags": sorted(target.tags),
        }

    def target_policy(self, target_id: str) -> dict[str, Any]:
        engine = self._repair_engine_for_target(target_id)
        target = engine.registry.get(target_id)
        return {"target_id": target_id, "policy": _jsonable(target.policy)}

    def _module_behavior_capture(self, subject: str, calls: int) -> dict[str, Any]:
        children = []
        for guard in self.guard_engines():
            for candidate_target in guard.registered_target_ids():
                capture = guard.behavior_capture(candidate_target, calls=calls)
                if capture.get("subject", {}).get("module_name") == subject:
                    children.append(capture)
        identity = identify_module(subject)
        kind_counts: dict[str, int] = {}
        network: set[str] = set()
        filesystem: set[str] = set()
        subprocesses: set[str] = set()
        imports: set[str] = set()
        dynamic: set[str] = set()
        calls_total = 0
        events_total = 0
        for child in children:
            profile = child.get("profile", {})
            calls_total += int(profile.get("call_count") or 0)
            events_total += int(profile.get("event_count") or 0)
            for key, value in dict(profile.get("event_kind_counts") or {}).items():
                kind_counts[str(key)] = kind_counts.get(str(key), 0) + int(value)
            network.update(map(str, profile.get("network_destinations") or ()))
            filesystem.update(map(str, profile.get("filesystem_roots") or ()))
            subprocesses.update(map(str, profile.get("subprocesses") or ()))
            imports.update(map(str, profile.get("imports") or ()))
            dynamic.update(map(str, profile.get("dynamic_code_operations") or ()))
        return {
            "scope": "module",
            "subject_key": f"module:{subject}",
            "subject": {
                "module_name": subject,
                "qualified_name": None,
                "source_path": identity.source_path,
            },
            "code_hash": identity.source_hash,
            "code_hash_kind": "module-source-sha256",
            "profile": {
                "window_count": 0,
                "call_count": calls_total,
                "event_count": events_total,
                "event_kind_counts": kind_counts,
                "network_destinations": sorted(network),
                "filesystem_roots": sorted(filesystem),
                "subprocesses": sorted(subprocesses),
                "imports": sorted(imports),
                "dynamic_code_operations": sorted(dynamic),
            },
            "children": children,
        }

    def handle_request(
        self,
        request: dict[str, Any],
        credentials: tuple[int, int, int],
    ) -> dict[str, Any]:
        command = str(request.get("command", "")).strip().lower()
        target_id = str(request.get("target", "")).strip() or None
        limit = max(1, min(int(request.get("limit", 50)), 500))

        if command == "status":
            from .adaptive import adaptive_aggregation_status
            return {
                "ok": True,
                **self.status(),
                "adaptive_aggregation": list(adaptive_aggregation_status()),
                "peer_pid": credentials[0],
            }
        if command == "adaptive-aggregation-context":
            from .adaptive import adaptive_aggregation_status
            contexts = [
                dict(item)
                for item in adaptive_aggregation_status()
                if item.get("enabled")
            ]
            return {
                "ok": True,
                "contexts": contexts[:limit],
                "context_count": len(contexts),
                "bounded": len(contexts) > limit,
            }
        if command == "targets":
            return {"ok": True, "targets": self.targets()}
        if command == "target-state":
            if not target_id:
                raise ValueError("target-state requires target")
            return {"ok": True, "state": self.target_state(target_id)}
        if command == "target-policy":
            if not target_id:
                raise ValueError("target-policy requires target")
            return {"ok": True, "policy": self.target_policy(target_id)}

        if command == "policy-authority-update":
            snapshot = request.get("snapshot")
            if not isinstance(snapshot, dict):
                raise ValueError("policy-authority-update requires snapshot object")
            context = get_authority_runtime_context()
            previous = context.effective

            def refresh_components(effective_policy: Any) -> None:
                for engine in self.repair_engines():
                    engine.refresh_authority_policy()
                for guard in self.guard_engines():
                    refresh = getattr(guard, "refresh_authority_policy", None)
                    if refresh is not None:
                        refresh()
                from .adaptive import refresh_adaptive_authority_policy
                refresh_adaptive_authority_policy()
                from .logging.handler import get_runtime as get_logging_runtime
                logging_runtime = get_logging_runtime()
                if logging_runtime is not None and hasattr(logging_runtime, "apply_authority_policy"):
                    logging_runtime.apply_authority_policy(effective_policy)

            try:
                effective = context.update_from_snapshot(snapshot)
                refresh_components(effective)
            except Exception:
                context.update_from_snapshot(previous.snapshot_dict())
                try:
                    refresh_components(previous)
                except Exception:
                    # The supervisor will detect the fingerprint mismatch and report
                    # runtime policy assurance as invalid if rollback reconciliation fails.
                    pass
                raise
            return {
                "ok": True,
                "generation": effective.generation,
                "fingerprint": effective.fingerprint,
                "overall_assurance": effective.overall_assurance,
            }

        if command == "policy-authority-status":
            effective = get_authority_runtime_context().effective
            return {"ok": True, **effective.snapshot_dict()}

        if command == "behavior-capture":
            scope = str(request.get("scope") or "function").strip().lower()
            subject = str(request.get("subject") or target_id or "").strip()
            calls = max(1, min(int(request.get("calls", 50)), 1000))
            requested_by = str(request.get("requested_by") or f"uid:{credentials[1]}").strip()
            reason = str(request.get("reason") or "operator-requested behavior capture").strip()
            priority = int(request.get("priority", 100))
            deadline = request.get("deadline")
            requested_generation = request.get("requested_generation")
            if not subject:
                raise ValueError("behavior-capture requires subject")
            if scope == "function":
                guard = self._guard_engine_for_target(subject)
                capture = _jsonable(
                    guard.schedule_behavior_collection(
                        scope=scope,
                        subject=subject,
                        calls=calls,
                        requested_by=requested_by,
                        reason=reason,
                        priority=priority,
                        deadline=deadline,
                        requested_generation=requested_generation,
                        operation=lambda: guard.behavior_capture(subject, calls=calls),
                    )
                )
                _emit_unsupervised_behavior_collection_audit(
                    request=request,
                    capture=capture,
                    actor_id=requested_by,
                )
                return {
                    "ok": True,
                    "capture": capture,
                }
            if scope != "module":
                raise ValueError("behavior-capture scope must be function or module")
            scheduler_guard = next(
                (
                    guard
                    for guard in self.guard_engines()
                    if guard.behavior_collection_scheduler is not None
                ),
                None,
            )
            operation = lambda: self._module_behavior_capture(subject, calls)
            capture = (
                scheduler_guard.schedule_behavior_collection(
                    scope=scope,
                    subject=subject,
                    calls=calls,
                    requested_by=requested_by,
                    reason=reason,
                    priority=priority,
                    deadline=deadline,
                    requested_generation=requested_generation,
                    operation=operation,
                )
                if scheduler_guard is not None
                else operation()
            )
            capture = _jsonable(capture)
            _emit_unsupervised_behavior_collection_audit(
                request=request,
                capture=capture,
                actor_id=requested_by,
            )
            return {"ok": True, "capture": capture}

        if command == "behavior-collection-status":
            collections = []
            for guard in self.guard_engines():
                status = guard.behavior_collection_status()
                status["requests"] = list(guard.behavior_collection_requests(limit=100))
                status["backlog"] = guard.behavior_collection_backlog(limit=500)
                collections.append(
                    {
                        "guard": guard.__class__.__name__,
                        **status,
                    }
                )
            return {"ok": True, "collections": collections}

        if command == "behavior-collection-auto-cycle":
            cycles = [guard.automatic_behavior_collection_cycle() for guard in self.guard_engines()]
            for cycle in cycles:
                for outcome in cycle.get("outcomes", ()):
                    target_id = str(outcome.get("target_id") or "").strip()
                    if not target_id:
                        continue
                    generation_id = str(outcome.get("generation_id") or "").strip()
                    _emit_unsupervised_behavior_collection_audit(
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
                                "outcome": outcome.get("outcome"),
                                "snapshot_id": outcome.get("snapshot_id"),
                            }
                        },
                        actor_id="caretaker:auto",
                    )
            return {"ok": True, "cycles": [_jsonable(item) for item in cycles]}

        if command == "behavior-collection-cancel":
            request_id = str(request.get("request_id") or "").strip()
            if not request_id:
                raise ValueError("behavior-collection-cancel requires request_id")
            reason = str(request.get("reason") or "operator cancelled collection").strip()
            for guard in self.guard_engines():
                try:
                    cancelled = guard.cancel_behavior_collection(request_id, reason=reason)
                except (FileNotFoundError, ValueError):
                    continue
                return {"ok": True, "request": _jsonable(cancelled)}
            raise KeyError(f"No behavior collection request found for {request_id}")

        if command == "behavior-collection-promote":
            if not target_id:
                raise ValueError("behavior-collection-promote requires target")
            requested_by = str(request.get("requested_by") or f"uid:{credentials[1]}").strip()
            reason = str(request.get("reason") or "operator-requested Behavior promotion").strip()
            for guard in self.guard_engines():
                try:
                    promotion = guard.promote_behavior_target(
                        target_id,
                        requested_by=requested_by,
                        reason=reason,
                    )
                except (FileNotFoundError, KeyError, PermissionError, ValueError):
                    continue
                return {"ok": True, "promotion": _jsonable(promotion)}
            raise KeyError(f"No eligible Guard target found for {target_id}")

        if command in {
            "guard-summary",
            "guard-events",
            "guard-deviations",
            "guard-sensitive-file-network-sequences",
            "guard-inspections",
            "guard-baseline-accept",
            "guard-assess",
        }:
            if not target_id:
                raise ValueError(f"{command} requires target")
            guard = self._guard_engine_for_target(target_id)
            if command == "guard-summary":
                return {"ok": True, "target": target_id, "summary": _jsonable(guard.recent_summary(target_id))}
            if command == "guard-events":
                return {
                    "ok": True,
                    "target": target_id,
                    "events": _jsonable(guard.recent_events(target_id, limit=limit)),
                }
            if command == "guard-deviations":
                return {
                    "ok": True,
                    "target": target_id,
                    "deviations": _jsonable(guard.recent_deviations(target_id, limit=limit)),
                }
            if command == "guard-sensitive-file-network-sequences":
                return {
                    "ok": True,
                    "target": target_id,
                    "sequences": _jsonable(
                        guard.sensitive_file_network_sequences(
                            target_id,
                            limit=limit,
                            window_seconds=float(request.get("window_seconds", 60.0)),
                        )
                    ),
                    "evidence_only": True,
                    "absence_claim": False,
                }
            if command == "guard-inspections":
                return {
                    "ok": True,
                    "target": target_id,
                    "inspections": _jsonable(guard.recent_target_inspections(target_id, limit=limit)),
                }
            if command == "guard-baseline-accept":
                return {"ok": True, "target": target_id, "baseline": _jsonable(guard.accept_baseline(target_id))}
            if guard.provider is None or not guard.policy.llm_review.enabled:
                return {
                    "ok": True,
                    "target": target_id,
                    "assessment": None,
                    "available": False,
                    "reason": "Guard LLM assessment is not configured for this runtime",
                }
            assessment = guard.assess_target(target_id)
            return {
                "ok": True,
                "target": target_id,
                "assessment": _jsonable(assessment),
                "available": assessment is not None,
            }

        if command == "guard-decisions":
            decisions = []
            for guard in self.guard_engines():
                decisions.extend(guard.decisions)
            decisions.sort(key=lambda item: item.created_at)
            return {"ok": True, "decisions": _jsonable(decisions[-limit:])}

        if command == "repair-events":
            events = []
            engines = (
                (self._repair_engine_for_target(target_id),)
                if target_id
                else self.repair_engines()
            )
            for engine in engines:
                events.extend(engine.store.recent_events(target_id, limit=limit))
            events.sort(key=lambda item: item.timestamp)
            return {"ok": True, "target": target_id, "events": _jsonable(events[-limit:])}

        if command == "repair-approvals":
            approvals = []
            for engine in self.repair_engines():
                approvals.extend(engine.pending_approvals())
            return {"ok": True, "approvals": _jsonable(approvals)}

        if command == "repair-recovery-plan":
            engines = (
                (self._repair_engine_for_target(target_id),)
                if target_id
                else self.repair_engines()
            )
            return {
                "ok": True,
                "target": target_id,
                "plans": [
                    _jsonable(engine.recovery_plan(target_id=target_id))
                    for engine in engines
                ],
            }

        if command == "repair-recovery-apply":
            if request.get("confirm") is not True:
                raise ValueError(
                    "repair-recovery-apply requires confirm=true; it records rollback decisions only"
                )
            engines = (
                (self._repair_engine_for_target(target_id),)
                if target_id
                else self.repair_engines()
            )
            results = []
            for engine in engines:
                plan = engine.recovery_plan(target_id=target_id)
                result = engine.apply_recovery_plan(plan)
                results.append({
                    "target": target_id,
                    "plan": plan,
                    "result": result,
                })
            return {
                "ok": True,
                "target": target_id,
                "plans": results,
                "actions_dispatched": False,
                "automatic_reactivation": False,
                "source_evidence_modified": False,
            }

        if command in {"repair-approve", "repair-reject"}:
            episode_id = UUID(str(request["episode_id"]))
            engine = next(
                (
                    item
                    for item in self.repair_engines()
                    if any(pending.episode_id == episode_id for pending in item.pending_approvals())
                ),
                None,
            )
            if engine is None:
                raise KeyError(f"No pending Repair approval for episode {episode_id}")
            if command == "repair-approve":
                activated = engine.approve_repair(episode_id)
                return {
                    "ok": True,
                    "episode_id": str(episode_id),
                    "activated_version": activated.number,
                }
            reason = str(request.get("reason") or "operator rejected candidate")
            engine.reject_repair(episode_id, reason)
            return {"ok": True, "episode_id": str(episode_id), "reason": reason}

        return control_failure_response(
            request, credentials, ValueError(f"unsupported runtime command: {command!r}")
        )


_RUNTIME_REGISTRY = OperatorRuntimeRegistry()


def get_operator_runtime_registry() -> OperatorRuntimeRegistry:
    return _RUNTIME_REGISTRY


def register_repair_engine(engine: Any) -> None:
    _RUNTIME_REGISTRY.register_repair_engine(engine)


def register_guard_engine(engine: Any) -> None:
    _RUNTIME_REGISTRY.register_guard_engine(engine)
