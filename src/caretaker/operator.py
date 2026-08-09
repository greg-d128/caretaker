from __future__ import annotations

import dataclasses
import os
import threading
import weakref
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from .authority import get_authority_runtime_context
from .control_plane import SignalSeverity


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
        result: dict[str, dict[str, Any]] = {}
        for engine in self.repair_engines():
            for target in engine.registry.all():
                version = target.slot.load()
                result[target.target_id] = {
                    "target_id": target.target_id,
                    "display_name": target.display_name,
                    "module": target.source.module_name,
                    "qualified_name": target.source.qualified_name,
                    "repair_mode": target.policy.mode.name,
                    "repair_authority": target.policy.authority.name,
                    "integrity_class": target.integrity_class.name,
                    "function_version": version.number,
                    "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                    "repair_in_progress": target.slot.state.name == "REPAIRING",
                    "guard_enabled": target.policy.guard.enabled,
                }
        for guard in self.guard_engines():
            for target_id in guard.registered_target_ids():
                result.setdefault(
                    target_id,
                    {
                        "target_id": target_id,
                        "display_name": target_id,
                        "repair_mode": None,
                        "repair_authority": None,
                        "integrity_class": None,
                        "function_version": None,
                        "candidate_id": None,
                        "repair_in_progress": False,
                        "guard_enabled": True,
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

    def handle_request(
        self,
        request: dict[str, Any],
        credentials: tuple[int, int, int],
    ) -> dict[str, Any]:
        command = str(request.get("command", "")).strip().lower()
        target_id = str(request.get("target", "")).strip() or None
        limit = max(1, min(int(request.get("limit", 50)), 500))

        if command == "status":
            return {"ok": True, **self.status(), "peer_pid": credentials[0]}
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

        if command in {
            "guard-summary",
            "guard-events",
            "guard-deviations",
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
            events.sort(key=lambda item: item.created_at)
            return {"ok": True, "target": target_id, "events": _jsonable(events[-limit:])}

        if command == "repair-approvals":
            approvals = []
            for engine in self.repair_engines():
                approvals.extend(engine.pending_approvals())
            return {"ok": True, "approvals": _jsonable(approvals)}

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

        return {"ok": False, "error": f"unsupported runtime command: {command!r}"}


_RUNTIME_REGISTRY = OperatorRuntimeRegistry()


def get_operator_runtime_registry() -> OperatorRuntimeRegistry:
    return _RUNTIME_REGISTRY


def register_repair_engine(engine: Any) -> None:
    _RUNTIME_REGISTRY.register_repair_engine(engine)


def register_guard_engine(engine: Any) -> None:
    _RUNTIME_REGISTRY.register_guard_engine(engine)
