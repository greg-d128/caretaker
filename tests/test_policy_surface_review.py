from __future__ import annotations

from dataclasses import replace

import pytest

from caretaker.adaptive import LightweightPolicy, validate_lightweight_policy
from caretaker.guard.policy import (
    GuardPolicy,
    GuardPolicyConfigurationError,
    BehaviorSnapshotPolicy,
    PeriodicInspectionPolicy,
    RetentionPolicy as GuardRetentionPolicy,
    validate_guard_policy,
)
from caretaker.logging.policy import OperatorLoggingPolicy, validate_operator_logging_policy
from caretaker.policy import RepairPolicy, PolicyConfigurationError, validate_policy
from caretaker.policy_semantics import (
    RESERVED_SETTINGS,
    REVIEWED_POLICY_SURFACE_HASH,
    current_policy_surface_hash,
    policy_surface_review_status,
)
from caretaker.system.policy import SystemCollectionPolicy, validate_system_policy


def test_policy_dataclass_surface_matches_explicit_review_hash():
    assert current_policy_surface_hash() == REVIEWED_POLICY_SURFACE_HASH
    status = policy_surface_review_status()
    assert status["matches_review"] is True
    assert status["review_generation"] >= 1


def test_default_public_policies_are_executable_not_reserved_promises(tmp_path):
    validate_policy(RepairPolicy())
    validate_guard_policy(GuardPolicy())
    validate_operator_logging_policy(
        OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="truth")
    )
    validate_system_policy(SystemCollectionPolicy())
    validate_lightweight_policy(LightweightPolicy())


def test_reserved_repair_promises_fail_explicitly():
    policy = RepairPolicy()
    with pytest.raises(PolicyConfigurationError, match="previous_incidents"):
        validate_policy(replace(policy, context=replace(policy.context, previous_incidents=2)))
    with pytest.raises(PolicyConfigurationError, match="structural_review_after_repairs"):
        validate_policy(replace(policy, limits=replace(policy.limits, structural_review_after_repairs=5)))
    with pytest.raises(PolicyConfigurationError, match="regression replay"):
        validate_policy(
            replace(
                policy,
                stability=replace(policy.stability, require_regression_replay_before_reactivation=True),
            )
        )


def test_reserved_guard_retention_and_periodic_behavior_controls_fail_explicitly():
    policy = GuardPolicy()
    with pytest.raises(GuardPolicyConfigurationError, match="raw-event pruning"):
        validate_guard_policy(replace(policy, retention=GuardRetentionPolicy(raw_event_seconds=60.0)))

    target = policy.targets[0] if policy.targets else None
    if target is None:
        from caretaker.guard.policy import GuardTargetPolicy
        target = GuardTargetPolicy(module_pattern="example")
    with pytest.raises(GuardPolicyConfigurationError, match="compare_behavior"):
        validate_guard_policy(
            replace(
                policy,
                targets=(replace(target, periodic=PeriodicInspectionPolicy(compare_behavior=True)),),
            )
        )


def test_randomized_behavior_snapshot_bounds_are_validated():
    policy = GuardPolicy()
    with pytest.raises(GuardPolicyConfigurationError, match="at least the minimum"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(
                    BehaviorSnapshotPolicy(),
                    randomized_epoch_min_samples=10,
                    randomized_epoch_max_samples=9,
                ),
            )
        )


def test_behavior_collection_scheduler_limits_are_validated():
    policy = GuardPolicy()
    with pytest.raises(GuardPolicyConfigurationError, match="collection_max_pending"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(policy.snapshots, collection_max_pending=0),
            )
        )
    with pytest.raises(GuardPolicyConfigurationError, match="collection_max_calls"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(policy.snapshots, collection_max_calls=1001),
            )
        )
    with pytest.raises(GuardPolicyConfigurationError, match="collection_auto_max_promoted"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(policy.snapshots, collection_auto_max_promoted=0),
            )
        )
    with pytest.raises(GuardPolicyConfigurationError, match="collection_auto_max_waiting"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(policy.snapshots, collection_auto_max_waiting=0),
            )
        )
    with pytest.raises(GuardPolicyConfigurationError, match="collection_soft_budget"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(
                    policy.snapshots,
                    collection_soft_budget_seconds_per_minute=10.0,
                    collection_hard_budget_seconds_per_minute=5.0,
                ),
            )
        )
    with pytest.raises(GuardPolicyConfigurationError, match="maximum_return_shapes"):
        validate_guard_policy(
            replace(
                policy,
                snapshots=replace(policy.snapshots, maximum_return_shapes=0),
            )
        )


def test_reserved_setting_catalog_covers_known_deferred_controls():
    expected = {
        "repair.context.previous_incidents",
        "guard.collectors.function_calls",
        "guard.retention.raw_event_seconds",
        "logging.baseline.enabled",
        "logging.metrics.enabled",
        "system.selector.include_same_cgroup",
    }
    assert expected <= set(RESERVED_SETTINGS)
