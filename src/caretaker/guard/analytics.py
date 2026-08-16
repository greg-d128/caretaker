from __future__ import annotations

import ast
import hashlib
import json
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
import os
from typing import Iterable
from uuid import UUID, uuid4

from ..evidence.models import (
    BehaviorEvent,
    BehaviorEventKind,
    BehaviorWindow,
    CodeIdentity,
    MetricSummary,
    ResourceIdentity,
    ResourceSummary,
    utcnow,
)
from ..evidence.store import EvidenceStore
from .models import (
    BaselineState,
    BehaviorBaseline,
    BehaviorDeviation,
    BehavioralCandidateScore,
    BehaviorProfile,
    BehaviorProfileSummary,
    DeviationCategory,
    EvidenceSummary,
)
from .policy import AggregationPolicy, BaselinePolicy, DeviationPolicy


def _subject_key(identity: CodeIdentity) -> str:
    return "|".join(
        (
            identity.distribution_name or "",
            identity.distribution_version or "",
            identity.module_name,
            identity.qualified_name or "",
            identity.source_hash or "",
            identity.bytecode_hash or "",
        )
    )


def _filesystem_root(value: str) -> str:
    path = Path(value)
    parts = path.parts
    if not parts:
        return value
    if path.is_absolute():
        return str(Path(*parts[: min(3, len(parts))]))
    return str(Path(*parts[: min(2, len(parts))]))


@dataclass
class _WindowAccumulator:
    subject: CodeIdentity
    started_at: datetime
    events: list[BehaviorEvent] = field(default_factory=list)
    call_ids: set[UUID] = field(default_factory=set)


class BehaviorAggregator:
    def __init__(
        self,
        store: EvidenceStore,
        policy: AggregationPolicy | None = None,
    ) -> None:
        self.store = store
        self.policy = policy or AggregationPolicy()
        self._active: dict[str, _WindowAccumulator] = {}
        self._lock = threading.RLock()

    def consume(self, event: BehaviorEvent) -> BehaviorWindow | None:
        key = _subject_key(event.code_identity)
        with self._lock:
            accumulator = self._active.get(key)
            if accumulator is None:
                accumulator = _WindowAccumulator(event.code_identity, event.occurred_at)
                self._active[key] = accumulator
            accumulator.events.append(event)
            if event.call_id is not None:
                accumulator.call_ids.add(event.call_id)
            elapsed = (event.occurred_at - accumulator.started_at).total_seconds()
            should_close = (
                len(accumulator.events) >= self.policy.close_after_events
                or len(accumulator.call_ids) >= self.policy.close_after_calls
                or elapsed >= self.policy.close_after_seconds
            )
        if should_close:
            return self.close_window(event.code_identity)
        return None

    def close_window(self, subject: CodeIdentity) -> BehaviorWindow | None:
        key = _subject_key(subject)
        with self._lock:
            accumulator = self._active.pop(key, None)
        if accumulator is None or not accumulator.events:
            return None
        events = tuple(accumulator.events)
        kind_counts = Counter(event.event_kind.name for event in events)
        resource_events: dict[tuple[str, str, str | None, bool], list[BehaviorEvent]] = defaultdict(list)
        durations = [event.duration_seconds for event in events if event.duration_seconds is not None]
        for event in events:
            if event.resource is not None:
                resource = event.resource
                if resource.kind in {"file", "directory"}:
                    resource = ResourceIdentity(
                        kind=resource.kind,
                        value=_filesystem_root(resource.value),
                        category=resource.category,
                        sensitive=resource.sensitive,
                    )
                resource_events[(resource.kind, resource.value, resource.category, resource.sensitive)].append(event)
        resources = tuple(
            ResourceSummary(
                resource=ResourceIdentity(kind=kind, value=value, category=category, sensitive=sensitive),
                count=len(matches),
                first_seen=min(item.occurred_at for item in matches),
                last_seen=max(item.occurred_at for item in matches),
            )
            for (kind, value, category, sensitive), matches in sorted(resource_events.items())
        )
        metrics = {
            "events_per_call": MetricSummary(
                count=len(events),
                minimum=(len(events) / max(1, len(accumulator.call_ids))),
                maximum=(len(events) / max(1, len(accumulator.call_ids))),
                mean=(len(events) / max(1, len(accumulator.call_ids))),
                total=float(len(events)),
            )
        }
        if durations:
            metrics["duration_seconds"] = MetricSummary(
                count=len(durations),
                minimum=min(durations),
                maximum=max(durations),
                mean=sum(durations) / len(durations),
                total=sum(durations),
            )
        window = BehaviorWindow(
            window_id=uuid4(),
            subject=subject,
            started_at=accumulator.started_at,
            completed_at=max(event.occurred_at for event in events),
            call_count=len(accumulator.call_ids),
            event_count=len(events),
            metrics=metrics,
            resources=resources,
            event_kind_counts=dict(kind_counts),
            representative_event_ids=tuple(
                event.event_id for event in events[: self.policy.representative_events]
            ),
        )
        self.store.record_behavior_window(window)
        return window


class BaselineManager:
    def __init__(self, policy: BaselinePolicy | None = None) -> None:
        self.policy = policy or BaselinePolicy()
        self._windows: dict[str, list[BehaviorWindow]] = defaultdict(list)
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._lock = threading.RLock()

    def observe(self, window: BehaviorWindow) -> BehaviorBaseline | None:
        key = _subject_key(window.subject)
        with self._lock:
            self._windows[key].append(window)
            existing = self._baselines.get(key)
            if existing is not None and existing.state is BaselineState.ACCEPTED:
                return existing
            if len(self._windows[key]) < self.policy.minimum_windows:
                return None
            if existing is None and not self.policy.automatic_candidate_creation:
                # Preserve the observations so an operator can still materialize and
                # accept a baseline explicitly, but do not silently create a policy
                # artifact when automatic candidate creation is disabled.
                return None
            accepted_at = existing.accepted_at if existing else None
            state = BaselineState.CANDIDATE if existing is None else existing.state
            if self.policy.automatic_acceptance and state is not BaselineState.ACCEPTED:
                state = BaselineState.ACCEPTED
                accepted_at = utcnow()
            baseline = BehaviorBaseline(
                baseline_id=existing.baseline_id if existing else uuid4(),
                subject=window.subject,
                workload_label=self.policy.workload_label,
                environment_fingerprint=self.policy.environment_fingerprint,
                created_at=existing.created_at if existing else utcnow(),
                accepted_at=accepted_at,
                observations=len(self._windows[key]),
                profile=self._profile(self._windows[key]),
                state=state,
            )
            self._baselines[key] = baseline
            return baseline

    def accept(self, subject: CodeIdentity) -> BehaviorBaseline:
        key = _subject_key(subject)
        with self._lock:
            existing = self._baselines.get(key)
            if existing is None:
                windows = self._windows.get(key, [])
                if not windows:
                    raise KeyError(f"No observed windows for {subject.logical_name}")
                existing = BehaviorBaseline(
                    baseline_id=uuid4(),
                    subject=subject,
                    workload_label=self.policy.workload_label,
                    environment_fingerprint=self.policy.environment_fingerprint,
                    created_at=utcnow(),
                    accepted_at=None,
                    observations=len(windows),
                    profile=self._profile(windows),
                    state=BaselineState.CANDIDATE,
                )
            accepted = replace(existing, accepted_at=utcnow(), state=BaselineState.ACCEPTED)
            self._baselines[key] = accepted
            return accepted

    def restore(self, baseline: BehaviorBaseline) -> BehaviorBaseline:
        """Hydrate a previously accepted immutable baseline without replaying events."""
        if baseline.state is not BaselineState.ACCEPTED:
            raise ValueError("Only accepted Guard baselines may be restored")
        key = _subject_key(baseline.subject)
        with self._lock:
            self._baselines[key] = baseline
            self._windows.pop(key, None)
        return baseline

    def get(self, subject: CodeIdentity) -> BehaviorBaseline | None:
        with self._lock:
            return self._baselines.get(_subject_key(subject))

    def summary(self, subject: CodeIdentity) -> BehaviorProfileSummary | None:
        baseline = self.get(subject)
        if baseline is None:
            return None
        profile = baseline.profile
        return BehaviorProfileSummary(
            subject=subject,
            window_count=baseline.observations,
            call_count=profile.call_count,
            event_count=profile.event_count,
            event_kind_counts=profile.event_kind_counts,
            network_destinations=profile.network_destinations,
            filesystem_roots=profile.filesystem_roots,
            subprocesses=profile.subprocesses,
            imports=profile.imports,
            dynamic_code_operations=profile.dynamic_code_operations,
        )

    @staticmethod
    def window_summary(window: BehaviorWindow) -> BehaviorProfileSummary:
        profile = BaselineManager._profile((window,))
        return BehaviorProfileSummary(
            subject=window.subject,
            window_count=1,
            call_count=window.call_count,
            event_count=window.event_count,
            event_kind_counts=profile.event_kind_counts,
            network_destinations=profile.network_destinations,
            filesystem_roots=profile.filesystem_roots,
            subprocesses=profile.subprocesses,
            imports=profile.imports,
            dynamic_code_operations=profile.dynamic_code_operations,
        )

    @staticmethod
    def _profile(windows: Iterable[BehaviorWindow]) -> BehaviorProfile:
        kind_counts: Counter[str] = Counter()
        resources: Counter[str] = Counter()
        network: set[str] = set()
        filesystem: set[str] = set()
        subprocesses: set[str] = set()
        imports: set[str] = set()
        dynamic: set[str] = set()
        call_count = 0
        event_count = 0
        for window in windows:
            kind_counts.update(window.event_kind_counts)
            call_count += window.call_count
            event_count += window.event_count
            for summary in window.resources:
                key = f"{summary.resource.kind}:{summary.resource.value}"
                resources[key] += summary.count
                if summary.resource.kind == "network":
                    network.add(summary.resource.value)
                elif summary.resource.kind in {"file", "directory"}:
                    filesystem.add(summary.resource.value)
                elif summary.resource.kind == "subprocess":
                    subprocesses.add(summary.resource.value)
                elif summary.resource.kind == "import":
                    imports.add(summary.resource.value)
                elif summary.resource.kind == "dynamic-code":
                    dynamic.add(summary.resource.value)
        return BehaviorProfile(
            event_kind_counts=dict(kind_counts),
            resource_counts=dict(resources),
            call_count=call_count,
            event_count=event_count,
            network_destinations=tuple(sorted(network)),
            filesystem_roots=tuple(sorted(filesystem)),
            subprocesses=tuple(sorted(subprocesses)),
            imports=tuple(sorted(imports)),
            dynamic_code_operations=tuple(sorted(dynamic)),
        )


class DeviationDetector:
    def __init__(self, policy: DeviationPolicy | None = None) -> None:
        self.policy = policy or DeviationPolicy()

    def compare(
        self,
        baseline: BehaviorBaseline,
        observed: BehaviorWindow,
    ) -> tuple[BehaviorDeviation, ...]:
        observed_profile = BaselineManager._profile((observed,))
        expected = baseline.profile
        deviations: list[BehaviorDeviation] = []
        deviations.extend(
            self._new_set_deviations(
                baseline,
                observed,
                DeviationCategory.NEW_NETWORK_DESTINATION,
                "network destination",
                set(expected.network_destinations),
                set(observed_profile.network_destinations),
                sensitivity=85.0,
            )
        )
        deviations.extend(self._explicit_policy_violations(baseline, observed, observed_profile))
        deviations.extend(
            self._new_set_deviations(
                baseline,
                observed,
                DeviationCategory.NEW_FILESYSTEM_ROOT,
                "filesystem root",
                set(expected.filesystem_roots),
                set(observed_profile.filesystem_roots),
                sensitivity=70.0,
            )
        )
        deviations.extend(
            self._new_set_deviations(
                baseline,
                observed,
                DeviationCategory.NEW_SUBPROCESS,
                "subprocess",
                set(expected.subprocesses),
                set(observed_profile.subprocesses),
                sensitivity=95.0,
            )
        )
        deviations.extend(
            self._new_set_deviations(
                baseline,
                observed,
                DeviationCategory.NEW_IMPORT,
                "import",
                set(expected.imports),
                set(observed_profile.imports),
                sensitivity=45.0,
            )
        )
        deviations.extend(
            self._new_set_deviations(
                baseline,
                observed,
                DeviationCategory.NEW_DYNAMIC_CODE,
                "dynamic code operation",
                set(expected.dynamic_code_operations),
                set(observed_profile.dynamic_code_operations),
                sensitivity=100.0,
            )
        )
        expected_rate = expected.event_count / max(1, expected.call_count)
        observed_rate = observed.event_count / max(1, observed.call_count)
        if expected_rate > 0 and observed_rate > expected_rate * self.policy.maximum_rate_multiplier:
            multiplier = observed_rate / expected_rate
            deviations.append(
                self._deviation(
                    baseline,
                    observed,
                    DeviationCategory.RATE_INCREASE,
                    expected=EvidenceSummary("events per call", {"rate": expected_rate}),
                    observed_summary=EvidenceSummary("events per call", {"rate": observed_rate, "multiplier": multiplier}),
                    novelty=40.0,
                    magnitude=min(100.0, 20.0 * multiplier),
                    sensitivity=50.0,
                    explanation=f"Behavior event rate increased {multiplier:.1f}x",
                )
            )
        return tuple(deviations)

    def _explicit_policy_violations(
        self,
        baseline: BehaviorBaseline,
        observed: BehaviorWindow,
        observed_profile: BehaviorProfile,
    ) -> list[BehaviorDeviation]:
        expected = baseline.profile
        result: list[BehaviorDeviation] = []

        network = set(observed_profile.network_destinations)
        if self.policy.network_allowlist:
            allowed = set(self.policy.network_allowlist)
            for value in sorted(network - allowed):
                result.append(self._policy_violation(
                    baseline, observed, "network destination", value,
                    f"network allowlist {sorted(allowed)!r}",
                ))
        elif self.policy.deny_new_network_capability:
            for value in sorted(network - set(expected.network_destinations)):
                result.append(self._policy_violation(
                    baseline, observed, "network destination", value,
                    "new network capabilities are denied",
                ))

        subprocesses = set(observed_profile.subprocesses)
        if self.policy.subprocess_allowlist:
            allowed = set(self.policy.subprocess_allowlist)
            for value in sorted(subprocesses - allowed):
                result.append(self._policy_violation(
                    baseline, observed, "subprocess", value,
                    f"subprocess allowlist {sorted(allowed)!r}",
                ))
        elif self.policy.deny_new_subprocess_capability:
            for value in sorted(subprocesses - set(expected.subprocesses)):
                result.append(self._policy_violation(
                    baseline, observed, "subprocess", value,
                    "new subprocess capabilities are denied",
                ))

        if self.policy.filesystem_roots:
            allowed_roots = tuple(os.path.abspath(os.path.expanduser(item)) for item in self.policy.filesystem_roots)
            for value in sorted(observed_profile.filesystem_roots):
                observed_path = os.path.abspath(os.path.expanduser(value))
                if not any(
                    observed_path == root or observed_path.startswith(root.rstrip(os.sep) + os.sep)
                    for root in allowed_roots
                ):
                    result.append(self._policy_violation(
                        baseline, observed, "filesystem root", value,
                        f"filesystem roots {list(self.policy.filesystem_roots)!r}",
                    ))
        return result

    def _policy_violation(
        self,
        baseline: BehaviorBaseline,
        observed: BehaviorWindow,
        label: str,
        value: str,
        rule: str,
    ) -> BehaviorDeviation:
        return self._deviation(
            baseline,
            observed,
            DeviationCategory.EXPLICIT_POLICY_VIOLATION,
            expected=EvidenceSummary("deterministic Guard policy", {"rule": rule}),
            observed_summary=EvidenceSummary(f"prohibited {label}", {"value": value}),
            novelty=100.0,
            magnitude=100.0,
            sensitivity=100.0,
            explanation=f"Explicit Guard policy violation: {label} {value!r} violates {rule}",
        )

    def _new_set_deviations(
        self,
        baseline: BehaviorBaseline,
        observed: BehaviorWindow,
        category: DeviationCategory,
        label: str,
        expected_values: set[str],
        observed_values: set[str],
        *,
        sensitivity: float,
    ) -> list[BehaviorDeviation]:
        result: list[BehaviorDeviation] = []
        for value in sorted(observed_values - expected_values):
            result.append(
                self._deviation(
                    baseline,
                    observed,
                    category,
                    expected=EvidenceSummary(f"known {label}s", {"values": sorted(expected_values)}),
                    observed_summary=EvidenceSummary(f"new {label}", {"value": value}),
                    novelty=100.0,
                    magnitude=70.0,
                    sensitivity=sensitivity,
                    explanation=f"Observed new {label}: {value}",
                )
            )
        return result

    def _deviation(
        self,
        baseline: BehaviorBaseline,
        window: BehaviorWindow,
        category: DeviationCategory,
        *,
        expected: EvidenceSummary,
        observed_summary: EvidenceSummary,
        novelty: float,
        magnitude: float,
        sensitivity: float,
        explanation: str,
    ) -> BehaviorDeviation:
        confidence = 90.0
        persistence = 50.0
        significance = (
            novelty * 0.30
            + magnitude * 0.20
            + sensitivity * 0.25
            + confidence * 0.15
            + persistence * 0.10
        )
        return BehaviorDeviation(
            deviation_id=uuid4(),
            baseline_id=baseline.baseline_id,
            observation_window_id=window.window_id,
            subject=window.subject,
            category=category,
            expected=expected,
            observed=observed_summary,
            novelty_score=novelty,
            magnitude_score=magnitude,
            sensitivity_score=sensitivity,
            confidence_score=confidence,
            persistence_score=persistence,
            significance_score=significance,
            explanation=explanation,
            supporting_event_ids=window.representative_event_ids,
        )


class StaticCandidateBehaviorAnalyzer(ast.NodeVisitor):
    _NETWORK_NAMES = {"socket", "requests", "urllib", "httpx", "aiohttp", "urlopen"}
    _FILESYSTEM_NAMES = {"open", "Path", "listdir", "scandir", "walk", "glob", "rglob"}
    _SUBPROCESS_NAMES = {"subprocess", "Popen", "run", "system", "spawn", "fork"}
    _DYNAMIC_NAMES = {"eval", "exec", "compile", "__import__", "import_module"}

    def __init__(self) -> None:
        self.capabilities: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        self.capabilities.add("import")
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            if root in self._NETWORK_NAMES:
                self.capabilities.add("network")
            if root == "subprocess":
                self.capabilities.add("subprocess")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.capabilities.add("import")
        root = (node.module or "").split(".", 1)[0]
        if root in self._NETWORK_NAMES:
            self.capabilities.add("network")
        if root == "subprocess":
            self.capabilities.add("subprocess")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node.func)
        parts = set(name.split("."))
        if parts & self._NETWORK_NAMES:
            self.capabilities.add("network")
        if parts & self._FILESYSTEM_NAMES:
            self.capabilities.add("filesystem")
        if parts & self._SUBPROCESS_NAMES:
            self.capabilities.add("subprocess")
        if parts & self._DYNAMIC_NAMES:
            self.capabilities.add("dynamic-code")
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = StaticCandidateBehaviorAnalyzer._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @classmethod
    def evaluate(
        cls,
        source: str,
        *,
        baseline: BehaviorProfileSummary | None,
        allow_new_capabilities: bool,
        candidate_id: UUID | None = None,
    ) -> BehavioralCandidateScore:
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return BehavioralCandidateScore(
                candidate_id=candidate_id,
                baseline_compatibility=0.0,
                new_capability_risk=100.0,
                prohibited_operation_count=1,
                unexplained_deviation_count=1,
                eligible=False,
                rejection_reasons=(f"Candidate source did not parse: {exc}",),
            )
        analyzer = cls()
        analyzer.visit(tree)
        baseline_capabilities: set[str] = set()
        if baseline is not None:
            if baseline.network_destinations:
                baseline_capabilities.add("network")
            if baseline.filesystem_roots:
                baseline_capabilities.add("filesystem")
            if baseline.subprocesses:
                baseline_capabilities.add("subprocess")
            if baseline.dynamic_code_operations:
                baseline_capabilities.add("dynamic-code")
            if baseline.imports:
                baseline_capabilities.add("import")
        new = analyzer.capabilities - baseline_capabilities
        prohibited = set()
        if "dynamic-code" in analyzer.capabilities:
            prohibited.add("dynamic-code")
        if not allow_new_capabilities:
            prohibited.update(new)
        reasons = tuple(f"Candidate introduces {capability} capability" for capability in sorted(prohibited))
        return BehavioralCandidateScore(
            candidate_id=candidate_id,
            baseline_compatibility=max(0.0, 100.0 - 25.0 * len(new)),
            new_capability_risk=min(100.0, 30.0 * len(new) + 40.0 * ("dynamic-code" in analyzer.capabilities)),
            prohibited_operation_count=len(prohibited),
            unexplained_deviation_count=len(new),
            eligible=not prohibited,
            rejection_reasons=reasons,
            detected_capabilities=tuple(sorted(analyzer.capabilities)),
        )


def evidence_hash(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=repr).encode("utf-8")).hexdigest()
