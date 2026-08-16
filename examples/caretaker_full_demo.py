"""Comprehensive single-decorator Caretaker example.

The purpose of this example is to show how the existing subsystem policy
objects compose behind one @caretaker boundary.  It intentionally does not
create a second "CaretakerPolicy" abstraction.
"""

from collections.abc import Mapping
from typing import Any

from caretaker import (
    ActivationPolicy,
    CandidateGuardPolicy,
    CandidateSelectionPolicy,
    ContextPolicy,
    ExceptionTrigger,
    GuardBinding,
    IntegrityClass,
    IntegrityRepairPolicy,
    LoggingBinding,
    ObservationPolicy,
    RepairAuthority,
    RepairEngine,
    RepairLimits,
    RepairMode,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    ScoringPolicy,
    StabilityPolicy,
    StatePolicy,
    StaticRepairProvider,
    TimeoutTrigger,
    ValidationPolicy,
    caretaker,
)


def mask_sensitive(
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> tuple[tuple[Any, ...], Mapping[str, Any]]:
    """Remove the example API key before evidence leaves the call boundary."""
    masked = dict(kwargs)
    if "api_key" in masked:
        masked["api_key"] = "<masked>"
    return args, masked


# A deterministic empty provider is sufficient for this configuration example.
# A real application would inject its normal RepairProvider.
engine = RepairEngine(provider=StaticRepairProvider(()))

policy = RepairPolicy(
    # Repair triggers.
    triggers=(
        ExceptionTrigger(),
        TimeoutTrigger(seconds=2.0, mode="soft"),
    ),

    # Call-state capture and retry semantics.
    state=StatePolicy(
        capture_arguments=True,
        capture_failure_locals=True,
        snapshot_arguments=True,
        detect_mutations=True,
        include_diff_in_incident=True,
        restore_for_validation=True,
        restore_before_retry=True,
    ),
    retry=RetryPolicy(
        max_attempts=1,
        safety=ReplaySafety.IDEMPOTENT,
        require_successful_state_restore=True,
        retry_original_exception_only=True,
        backoff_seconds=0.0,
    ),

    # Candidate validation and post-activation observation.
    validation=ValidationPolicy(
        require_ast_parse=True,
        require_compilation=True,
        preserve_name=True,
        preserve_signature=True,
        preserve_callable_kind=True,
        run_registered_tests=True,
        run_generated_tests=False,
        isolate_validation=True,
        validation_timeout_seconds=30.0,
        allow_imports=False,
    ),
    observation=ObservationPolicy(
        initial_successful_executions=3,
        long_term_successful_executions=100,
        long_term_minimum_duration_seconds=3600.0,
        probation_failure_budget=0,
        long_term_maximum_failures=1,
        long_term_failure_rate=0.001,
        rollback_during_probation=True,
        rollback_after_acceptance=False,
    ),

    # Existing Repair candidate-selection and activation controls.
    selection=CandidateSelectionPolicy(
        minimum_total_score=75.0,
        maximum_candidates_to_evaluate=5,
    ),
    scoring=ScoringPolicy(),
    activation=ActivationPolicy(
        activate_in_memory=True,
        rollback_on_retry_failure=True,
    ),
    context=ContextPolicy(
        include_source=True,
        include_traceback=True,
        include_state_diff=True,
        previous_calls=3,
        maximum_log_records=200,
        send_argument_values=False,
        send_local_values=False,
    ),
    limits=RepairLimits(
        maximum_repair_depth=1,
        maximum_candidates_per_incident=5,
        maximum_repairs_per_target=5,
        cooldown_seconds=60.0,
    ),
    stability=StabilityPolicy(
        detect_oscillation=True,
        prevent_reactivation_of_failed_version=True,
    ),

    # Integrity restrictions remain part of the existing RepairPolicy.
    integrity=IntegrityRepairPolicy(
        allow_protected_automatic_repair=False,
    ),

    # Logging evidence requested for this target.
    logging=LoggingBinding(
        enabled=True,
        capture_calls=True,
        capture_exceptions=True,
        capture_timing=True,
        capture_arguments=True,
    ),

    # Guard observation requested for this target.
    guard=GuardBinding(
        enabled=True,
        observe_network=True,
        observe_filesystem=True,
        observe_subprocesses=True,
        observe_imports=True,
        include_guard_context_in_repair=True,
        validate_candidate_behavior=True,
        monitor_during_probation=True,
    ),
    candidate_guard=CandidateGuardPolicy(
        compare_to_original_baseline=True,
        allow_new_capabilities=False,
        maximum_new_network_destinations=0,
        maximum_new_filesystem_roots=0,
        maximum_new_subprocesses=0,
        rollback_on_significant_deviation=True,
    ),

    # Overall Repair mode and operator authority.
    mode=RepairMode.AUTOMATIC,
    authority=RepairAuthority.REQUIRE_OPERATOR_APPROVAL,
    enabled=True,
)


@caretaker(
    policy=policy,
    engine=engine,
    target_id="example.fetch_remote_record",
    tags=frozenset({"example", "network"}),
    integrity_class=IntegrityClass.ORDINARY,
    mask=mask_sensitive,
)
def fetch_remote_record(record_id: int, *, api_key: str) -> dict[str, Any]:
    """Ordinary application code behind one Caretaker instrumentation boundary."""
    return {
        "record_id": record_id,
        "status": "ok",
    }
