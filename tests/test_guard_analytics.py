from __future__ import annotations

from dataclasses import replace
import os
import threading

import pytest
from uuid import uuid4

from caretaker.evidence import (
    BehaviorEvent,
    BehaviorEventKind,
    EventOutcome,
    InMemoryEvidenceStore,
    ResourceIdentity,
    identify_function,
)
from caretaker.guard.analytics import BaselineManager, BehaviorAggregator, DeviationDetector
from caretaker.guard.models import BaselineState, DeviationCategory
from caretaker.guard.policy import AggregationPolicy, BaselinePolicy, DeviationPolicy
from caretaker.domain import ValueSnapshot
from tests.guard_targets import stable


def _event(resource: ResourceIdentity, *, call_id=None) -> BehaviorEvent:
    return BehaviorEvent.create(
        event_kind=(
            BehaviorEventKind.NETWORK_CONNECT
            if resource.kind == "network"
            else BehaviorEventKind.FILE_OPEN
        ),
        operation="test",
        code_identity=identify_function(stable),
        run_id=uuid4(),
        call_id=call_id or uuid4(),
        target_id="tests.guard_targets:stable",
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        resource=resource,
        outcome=EventOutcome.SUCCEEDED,
    )


def _return_event(category: str, shape: str, *, call_id=None) -> BehaviorEvent:
    return BehaviorEvent.create(
        event_kind=BehaviorEventKind.FUNCTION_CALL,
        operation="function.call.completed",
        code_identity=identify_function(stable),
        run_id=uuid4(),
        call_id=call_id or uuid4(),
        target_id="tests.guard_targets:stable",
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        attributes={
            "return_category": ValueSnapshot(
                type_name="caretaker.return-category",
                representation=category,
            ),
            "return_shape": ValueSnapshot(
                type_name="caretaker.return-shape",
                representation=shape,
            ),
        },
        outcome=EventOutcome.SUCCEEDED,
    )


def test_baseline_and_deviation_detection_highlight_new_resources() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
    )
    baselines = BaselineManager(BaselinePolicy(minimum_windows=1))
    detector = DeviationDetector(DeviationPolicy(significance_threshold=0))

    baseline_window = aggregator.consume(_event(ResourceIdentity("network", "api.example:443")))
    assert baseline_window is not None
    candidate = baselines.observe(baseline_window)
    assert candidate is not None and candidate.state is BaselineState.CANDIDATE
    accepted = baselines.accept(baseline_window.subject)

    observed = aggregator.consume(_event(ResourceIdentity("network", "unexpected.example:443")))
    assert observed is not None
    deviations = detector.compare(accepted, observed)

    assert any(item.category is DeviationCategory.NEW_NETWORK_DESTINATION for item in deviations)
    assert max(item.significance_score for item in deviations) > 60


def test_baseline_policy_can_disable_automatic_candidate_creation() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
    )
    baselines = BaselineManager(
        BaselinePolicy(minimum_windows=1, automatic_candidate_creation=False)
    )
    window = aggregator.consume(_event(ResourceIdentity("network", "api.example:443")))
    assert window is not None
    assert baselines.observe(window) is None

    accepted = baselines.accept(window.subject)
    assert accepted.state is BaselineState.ACCEPTED


def test_baseline_policy_can_automatically_accept_materialized_candidate() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
    )
    baselines = BaselineManager(
        BaselinePolicy(
            minimum_windows=1,
            automatic_candidate_creation=True,
            automatic_acceptance=True,
        )
    )
    window = aggregator.consume(_event(ResourceIdentity("network", "api.example:443")))
    assert window is not None
    baseline = baselines.observe(window)
    assert baseline is not None
    assert baseline.state is BaselineState.ACCEPTED
    assert baseline.accepted_at is not None


def test_explicit_network_allowlist_violation_is_deterministic() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
    )
    baselines = BaselineManager(BaselinePolicy(minimum_windows=1))
    detector = DeviationDetector(
        DeviationPolicy(
            significance_threshold=0,
            network_allowlist=("api.example:443",),
        )
    )
    baseline_window = aggregator.consume(_event(ResourceIdentity("network", "api.example:443")))
    assert baseline_window is not None
    baselines.observe(baseline_window)
    accepted = baselines.accept(baseline_window.subject)

    observed = aggregator.consume(_event(ResourceIdentity("network", "evil.example:443")))
    assert observed is not None
    deviations = detector.compare(accepted, observed)

    violation = next(
        item for item in deviations
        if item.category is DeviationCategory.EXPLICIT_POLICY_VIOLATION
    )
    assert violation.observed.values["value"] == "evil.example:443"


def test_deny_new_network_capability_creates_explicit_violation() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
    )
    baselines = BaselineManager(BaselinePolicy(minimum_windows=1))
    detector = DeviationDetector(
        DeviationPolicy(significance_threshold=0, deny_new_network_capability=True)
    )
    baseline_window = aggregator.consume(_event(ResourceIdentity("network", "api.example:443")))
    assert baseline_window is not None
    baselines.observe(baseline_window)
    accepted = baselines.accept(baseline_window.subject)
    observed = aggregator.consume(_event(ResourceIdentity("network", "new.example:443")))
    assert observed is not None

    assert any(
        item.category is DeviationCategory.EXPLICIT_POLICY_VIOLATION
        for item in detector.compare(accepted, observed)
    )


def test_return_novelty_is_policy_gated_and_requires_repeated_observations() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=2, close_after_calls=2, close_after_seconds=999),
    )
    baselines = BaselineManager(BaselinePolicy(minimum_windows=1))
    detector = DeviationDetector(
        DeviationPolicy(
            significance_threshold=0,
            detect_return_novelty=True,
            minimum_return_novelty_success_samples=2,
            minimum_new_return_observations=2,
        )
    )

    baseline_window = None
    for _ in range(2):
        baseline_window = aggregator.consume(_return_event("integer:builtins.int", "scalar"))
    assert baseline_window is not None
    assert baseline_window.return_observations_available is True
    accepted = baselines.observe(baseline_window)
    assert accepted is not None
    accepted = baselines.accept(baseline_window.subject)
    assert accepted.profile.success_count == 2

    observed_window = None
    for _ in range(2):
        observed_window = aggregator.consume(_return_event("text:builtins.str", "text:length-small"))
    assert observed_window is not None
    deviations = detector.compare(accepted, observed_window)
    novelty = [
        item
        for item in deviations
        if item.category is DeviationCategory.OUTPUT_BEHAVIOR_CHANGE
    ]
    assert len(novelty) == 2
    assert {item.observed.values["value"] for item in novelty} == {
        "text:builtins.str",
        "text:length-small",
    }

    single_observation = aggregator.consume(
        _return_event("bytes:builtins.bytes", "bytes:length-small")
    )
    assert single_observation is None
    single_observation = aggregator.consume(
        _return_event("integer:builtins.int", "scalar")
    )
    assert single_observation is not None
    assert not any(
        item.category is DeviationCategory.OUTPUT_BEHAVIOR_CHANGE
        for item in detector.compare(accepted, single_observation)
    )


def test_duration_distribution_shift_is_deterministic() -> None:
    store = InMemoryEvidenceStore()
    aggregator = BehaviorAggregator(
        store,
        AggregationPolicy(close_after_events=1, close_after_calls=1, close_after_seconds=999),
    )
    baselines = BaselineManager(BaselinePolicy(minimum_windows=1))
    detector = DeviationDetector(
        DeviationPolicy(
            significance_threshold=0,
            maximum_duration_p95_multiplier=2.0,
            minimum_duration_samples=20,
        )
    )
    baseline_event = BehaviorEvent.create(
        event_kind=BehaviorEventKind.FUNCTION_CALL,
        operation="function.call.completed",
        code_identity=identify_function(stable),
        run_id=uuid4(),
        call_id=uuid4(),
        target_id="tests.guard_targets:stable",
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        duration_seconds=0.01,
        outcome=EventOutcome.SUCCEEDED,
    )
    baseline_window = aggregator.consume(baseline_event)
    assert baseline_window is not None
    baselines.observe(baseline_window)
    accepted = baselines.accept(baseline_window.subject)
    accepted = replace(
        accepted,
        profile=replace(
            accepted.profile,
            statistics={
                "duration_seconds": {
                    "count": 100,
                    "average": 0.005,
                    "p95": 0.01,
                }
            },
        ),
    )
    observed_event = replace(baseline_event, event_id=uuid4(), call_id=uuid4(), duration_seconds=0.05)
    observed = aggregator.consume(observed_event)
    assert observed is not None

    deviation = next(
        item
        for item in detector.compare(accepted, observed)
        if item.category is DeviationCategory.TIMING_DISTRIBUTION_CHANGE
    )
    assert deviation.observed.values["multiplier_vs_p95"] == pytest.approx(5.0)
