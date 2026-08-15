from __future__ import annotations

import os
import threading
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
