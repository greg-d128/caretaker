from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum, auto
from threading import RLock
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID, uuid4

from .evidence.models import CodeIdentity


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SignalDomain(Enum):
    FAILURE = auto()
    BEHAVIOR = auto()
    INTEGRITY = auto()
    IMPORT = auto()
    INTERNAL = auto()


class SignalSeverity(Enum):
    INFO = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class RuntimeActionKind(Enum):
    RECORD = auto()
    ALERT = auto()
    ESCALATE_INSTRUMENTATION = auto()
    INTERROGATE_LOGS = auto()
    OPEN_REPAIR_EPISODE = auto()
    REJECT_REPAIR_CANDIDATE = auto()
    ROLLBACK_REPAIR = auto()
    ALLOW_IMPORT = auto()
    DENY_IMPORT = auto()
    SUBSTITUTE_MODULE = auto()
    QUARANTINE_MODULE = auto()
    RESTART_WITH_MODULE_ROUTE = auto()
    TERMINATE_PROCESS = auto()


@dataclass(frozen=True, slots=True)
class ActionLineage:
    root_signal_id: UUID
    parent_action_id: UUID | None = None
    depth: int = 0
    participating_components: tuple[str, ...] = ()
    repair_episode_ids: tuple[UUID, ...] = ()
    deviation_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True)
class RuntimeSignal:
    signal_id: UUID
    occurred_at: datetime
    domain: SignalDomain
    kind: str
    severity: SignalSeverity
    run_id: UUID
    call_id: UUID | None
    target_id: str | None
    module_identity: CodeIdentity | None
    evidence_refs: tuple[UUID, ...]
    source_component: str
    requires_immediate_decision: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)
    lineage: ActionLineage | None = None

    @classmethod
    def create(
        cls,
        *,
        domain: SignalDomain,
        kind: str,
        severity: SignalSeverity,
        run_id: UUID,
        source_component: str,
        call_id: UUID | None = None,
        target_id: str | None = None,
        module_identity: CodeIdentity | None = None,
        evidence_refs: tuple[UUID, ...] = (),
        requires_immediate_decision: bool = False,
        attributes: Mapping[str, Any] | None = None,
        lineage: ActionLineage | None = None,
    ) -> "RuntimeSignal":
        signal_id = uuid4()
        return cls(
            signal_id=signal_id,
            occurred_at=utcnow(),
            domain=domain,
            kind=kind,
            severity=severity,
            run_id=run_id,
            call_id=call_id,
            target_id=target_id,
            module_identity=module_identity,
            evidence_refs=evidence_refs,
            source_component=source_component,
            requires_immediate_decision=requires_immediate_decision,
            attributes=attributes or {},
            lineage=lineage or ActionLineage(root_signal_id=signal_id),
        )


@dataclass(frozen=True, slots=True)
class RuntimeDecision:
    decision_id: UUID
    signal_id: UUID
    actions: tuple[RuntimeActionKind, ...]
    reason: str
    policy_id: str
    created_at: datetime
    selected_module_variant_id: str | None = None
    requires_human_review: bool = False
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeAction:
    action_id: UUID
    decision_id: UUID
    signal_id: UUID
    kind: RuntimeActionKind
    created_at: datetime
    reason: str
    lineage: ActionLineage
    attributes: Mapping[str, Any] = field(default_factory=dict)


class RuntimePolicyEngine(Protocol):
    def evaluate(self, signal: RuntimeSignal, context: Mapping[str, Any]) -> RuntimeDecision: ...


class DefaultRuntimePolicyEngine:
    """Conservative default policy.

    Deterministic integrity/import denials take precedence. Behavioral signals
    alert and escalate by default; they do not terminate execution solely from
    an LLM or statistical assessment.
    """

    policy_id = "caretaker-default-control-v1"

    def evaluate(self, signal: RuntimeSignal, context: Mapping[str, Any]) -> RuntimeDecision:
        actions: tuple[RuntimeActionKind, ...]
        human_review = False
        if signal.domain is SignalDomain.INTEGRITY and signal.severity in {
            SignalSeverity.HIGH,
            SignalSeverity.CRITICAL,
        }:
            actions = (RuntimeActionKind.ALERT, RuntimeActionKind.DENY_IMPORT)
        elif signal.domain is SignalDomain.IMPORT and signal.attributes.get("quarantined"):
            fallback = signal.attributes.get("fallback_variant_id")
            actions = (
                (RuntimeActionKind.SUBSTITUTE_MODULE,)
                if fallback
                else (RuntimeActionKind.DENY_IMPORT,)
            )
        elif signal.domain is SignalDomain.BEHAVIOR:
            requested = str(signal.attributes.get("requested_action", ""))
            if requested == "ROLLBACK_ACTIVE_CANDIDATE":
                actions = (RuntimeActionKind.ALERT, RuntimeActionKind.ROLLBACK_REPAIR)
            elif requested == "OPEN_REPAIR_EPISODE":
                actions = (RuntimeActionKind.ALERT, RuntimeActionKind.OPEN_REPAIR_EPISODE)
            elif requested == "QUARANTINE_TARGET":
                actions = (RuntimeActionKind.ALERT, RuntimeActionKind.QUARANTINE_MODULE)
            elif requested == "ALERT":
                actions = (RuntimeActionKind.ALERT,)
            elif signal.severity in {SignalSeverity.HIGH, SignalSeverity.CRITICAL}:
                actions = (
                    RuntimeActionKind.ALERT,
                    RuntimeActionKind.ESCALATE_INSTRUMENTATION,
                )
                human_review = True
            else:
                actions = (RuntimeActionKind.RECORD,)
        elif signal.domain is SignalDomain.FAILURE:
            actions = (RuntimeActionKind.RECORD, RuntimeActionKind.OPEN_REPAIR_EPISODE)
        elif signal.domain is SignalDomain.INTERNAL:
            actions = (RuntimeActionKind.ALERT,)
            human_review = signal.severity in {SignalSeverity.HIGH, SignalSeverity.CRITICAL}
        else:
            actions = (RuntimeActionKind.RECORD,)
        return RuntimeDecision(
            decision_id=uuid4(),
            signal_id=signal.signal_id,
            actions=actions,
            reason=f"Default policy for {signal.domain.name}:{signal.kind}",
            policy_id=self.policy_id,
            created_at=utcnow(),
            selected_module_variant_id=signal.attributes.get("fallback_variant_id"),
            requires_human_review=human_review,
        )


ActionHandler = Callable[[RuntimeAction, RuntimeSignal], None]


@dataclass(frozen=True, slots=True)
class RuntimeInteractionPolicy:
    maximum_action_depth: int = 4
    duplicate_window_seconds: float = 30.0
    minimum_internal_change_interval_seconds: float = 30.0
    maximum_scope_actions_per_window: int = 3
    scope_action_window_seconds: float = 300.0



class RuntimeControlPlane:
    def __init__(
        self,
        *,
        policy_engine: RuntimePolicyEngine | None = None,
        maximum_action_depth: int = 4,
        interaction_policy: RuntimeInteractionPolicy | None = None,
    ) -> None:
        self.policy_engine = policy_engine or DefaultRuntimePolicyEngine()
        self.interaction_policy = interaction_policy or RuntimeInteractionPolicy(maximum_action_depth=maximum_action_depth)
        self.maximum_action_depth = self.interaction_policy.maximum_action_depth
        self.signals: list[RuntimeSignal] = []
        self.decisions: list[RuntimeDecision] = []
        self.actions: list[RuntimeAction] = []
        self._handlers: dict[RuntimeActionKind, list[ActionHandler]] = {}
        self._seen: dict[tuple[str, str | None, str | None], datetime] = {}
        self._scope_action_history: dict[tuple[str | None, RuntimeActionKind], list[datetime]] = {}
        self._lock = RLock()

    def register_handler(self, kind: RuntimeActionKind, handler: ActionHandler) -> None:
        with self._lock:
            self._handlers.setdefault(kind, []).append(handler)

    def submit(
        self,
        signal: RuntimeSignal,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> RuntimeDecision:
        lineage = signal.lineage or ActionLineage(root_signal_id=signal.signal_id)
        if lineage.depth > self.maximum_action_depth:
            return RuntimeDecision(
                decision_id=uuid4(),
                signal_id=signal.signal_id,
                actions=(RuntimeActionKind.RECORD,),
                reason="Maximum cross-subsystem action depth exceeded",
                policy_id="loop-suppression",
                created_at=utcnow(),
            )
        dedupe_key = (signal.kind, signal.target_id, signal.module_identity.logical_name if signal.module_identity else None)
        now = utcnow()
        with self._lock:
            self.signals.append(signal)
            previous = self._seen.get(dedupe_key)
            duplicate = bool(
                previous is not None
                and (now - previous).total_seconds() < self.interaction_policy.duplicate_window_seconds
                and not signal.requires_immediate_decision
            )
            self._seen[dedupe_key] = now
            cutoff = now - timedelta(seconds=self.interaction_policy.duplicate_window_seconds)
            self._seen = {key: seen_at for key, seen_at in self._seen.items() if seen_at >= cutoff}
        work_decision = self._work_in_progress_decision(signal, context or {})
        if work_decision is not None:
            decision = work_decision
        elif duplicate:
            decision = RuntimeDecision(
                decision_id=uuid4(),
                signal_id=signal.signal_id,
                actions=(RuntimeActionKind.RECORD,),
                reason="Duplicate non-immediate signal suppressed",
                policy_id="deduplication",
                created_at=utcnow(),
            )
        else:
            decision = self.policy_engine.evaluate(signal, context or {})
        with self._lock:
            self.decisions.append(decision)
        for kind in decision.actions:
            if self._rate_limited(signal.target_id, kind, signal.domain):
                kind = RuntimeActionKind.RECORD
            action = RuntimeAction(
                action_id=uuid4(),
                decision_id=decision.decision_id,
                signal_id=signal.signal_id,
                kind=kind,
                created_at=utcnow(),
                reason=decision.reason,
                lineage=ActionLineage(
                    root_signal_id=lineage.root_signal_id,
                    parent_action_id=lineage.parent_action_id,
                    depth=lineage.depth + 1,
                    participating_components=lineage.participating_components + (signal.source_component,),
                    repair_episode_ids=lineage.repair_episode_ids,
                    deviation_ids=lineage.deviation_ids,
                ),
                attributes=decision.attributes,
            )
            with self._lock:
                self.actions.append(action)
                handlers = tuple(self._handlers.get(kind, ()))
            for handler in handlers:
                handler(action, signal)
        return decision

    def _work_in_progress_decision(
        self,
        signal: RuntimeSignal,
        context: Mapping[str, Any],
    ) -> RuntimeDecision | None:
        registry = context.get("work_registry")
        if registry is None or signal.target_id is None:
            return None
        try:
            overlapping = registry.overlapping(signal.target_id)
        except Exception:
            return None
        if not overlapping:
            return None
        observed = signal.attributes.get("observed_code_fingerprint")
        expected = {
            fingerprint
            for work in overlapping
            for scope, fingerprint in work.expected_code_fingerprints.items()
            if scope == signal.target_id or signal.target_id.startswith(scope + ".")
        }
        if observed is not None and observed in expected:
            return RuntimeDecision(
                decision_id=uuid4(), signal_id=signal.signal_id,
                actions=(RuntimeActionKind.RECORD,),
                reason="Observed change matches active Caretaker work in progress",
                policy_id="active-work-correlation", created_at=utcnow(),
                attributes={"work_ids": [str(work.work_id) for work in overlapping]},
            )
        return RuntimeDecision(
            decision_id=uuid4(), signal_id=signal.signal_id,
            actions=(RuntimeActionKind.ALERT, RuntimeActionKind.INTERROGATE_LOGS),
            reason="Observed change overlaps active work but does not match its expected fingerprint",
            policy_id="active-work-conflict", created_at=utcnow(),
            requires_human_review=True,
            attributes={"work_ids": [str(work.work_id) for work in overlapping]},
        )

    def _rate_limited(
        self,
        target_id: str | None,
        kind: RuntimeActionKind,
        domain: SignalDomain,
    ) -> bool:
        if kind not in {
            RuntimeActionKind.OPEN_REPAIR_EPISODE,
            RuntimeActionKind.ROLLBACK_REPAIR,
            RuntimeActionKind.QUARANTINE_MODULE,
            RuntimeActionKind.RESTART_WITH_MODULE_ROUTE,
        }:
            return False
        now = utcnow()
        key = (target_id, kind)
        cutoff = now - timedelta(seconds=self.interaction_policy.scope_action_window_seconds)
        with self._lock:
            history = [item for item in self._scope_action_history.get(key, ()) if item >= cutoff]
            if domain is SignalDomain.INTERNAL and history:
                if (now - history[-1]).total_seconds() < self.interaction_policy.minimum_internal_change_interval_seconds:
                    self._scope_action_history[key] = history
                    return True
            if len(history) >= self.interaction_policy.maximum_scope_actions_per_window:
                self._scope_action_history[key] = history
                return True
            history.append(now)
            self._scope_action_history[key] = history
        return False
