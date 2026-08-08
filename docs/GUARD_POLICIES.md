# Guard policies

## `GuardPolicy`

```python
GuardPolicy(
    mode=GuardMode.AUDIT,
    collectors=CollectorPolicy(),
    attribution=AttributionPolicy(),
    sampling=SamplingPolicy(),
    aggregation=AggregationPolicy(),
    baseline=BaselinePolicy(),
    deviations=DeviationPolicy(),
    llm_review=LLMReviewPolicy(),
    actions=GuardActionPolicy(),
    retention=RetentionPolicy(),
    targets=(),
)
```

## Collection

`CollectorPolicy` controls audit-hook categories. Disable categories that are irrelevant to reduce overhead and retained data.

Typical categories:

- imports;
- network and DNS;
- filesystem operations;
- directory enumeration;
- subprocesses;
- dynamic code operations.

Audit callbacks are intentionally small and send normalized events to a sink.

## Attribution

`AttributionPolicy` controls bounded stack inspection and identification of the likely initiator and low-level executor. Attribution is probabilistic for callbacks, background threads, executor pools, subprocesses, and native extensions.

## Sampling and aggregation

`SamplingPolicy` and `AggregationPolicy` control overhead. High-value novelty events should normally be retained even when routine known events are sampled.

Useful strategies include:

- always retain first-seen resources;
- aggregate repeated known activity;
- sample complete stacks;
- rate-limit forensic evidence;
- retain bounded representative events.

## Baselines

`BaselinePolicy` defines the minimum evidence required to create and accept a baseline. Acceptance must remain explicit.

A baseline should normally be scoped by:

- exact `CodeIdentity`;
- workload label;
- relevant environment fingerprint;
- known-good integrity state.

## Deviations

`DeviationPolicy` defines significance thresholds and relative-rate changes. Deterministic deviation categories include:

- new network destination;
- new filesystem root;
- new subprocess;
- new import;
- new dynamic code;
- significant rate increase/decrease;
- load-time side effect;
- runtime code change;
- dependency change;
- explicit policy violation.

## LLM review

`LLMReviewPolicy` enables bounded advisory assessment after deterministic extraction. It should define thresholds for when review is useful and limits on evidence volume.

## Actions

`GuardActionPolicy` maps deviations and assessment severity to actions. Deterministic policy violations may deny or quarantine. Statistical or LLM-only concerns should normally alert, escalate instrumentation, or require review.

## Periodic target policy

```python
GuardTargetPolicy(
    module_pattern="vendor_sdk.*",
    function_patterns=("vendor_sdk.Client.send",),
    inspection_level=InspectionLevel.PERIODIC,
    periodic=PeriodicInspectionPolicy(
        enabled=True,
        interval_seconds=600,
        execution_window=100,
        verify_source_hash=True,
        verify_runtime_fingerprints=True,
        compare_behavior=True,
        escalate_on_change=True,
    ),
)
```

## Decorator Guard binding

```python
GuardBinding(
    enabled=True,
    observe_network=True,
    observe_filesystem=True,
    observe_subprocesses=True,
    observe_imports=True,
    baseline_name="invoice-processing-v1",
    include_guard_context_in_repair=True,
    validate_candidate_behavior=True,
    monitor_during_probation=True,
    deviation_action=GuardDeviationAction.OPEN_REPAIR_EPISODE,
)
```

## Candidate behavior policy

```python
CandidateGuardPolicy(
    compare_to_original_baseline=True,
    allow_new_capabilities=False,
    maximum_new_network_destinations=0,
    maximum_new_filesystem_roots=0,
    maximum_new_subprocesses=0,
    rollback_on_significant_deviation=True,
)
```

A candidate may be functionally correct but behaviorally ineligible.


## Repair-target Guard binding

`GuardBinding(enabled=True)` enables call correlation and runtime code inspection for the target. It does **not** implicitly enable network, filesystem, subprocess, or import observation. Those resource categories must be selected individually. `observed_resource_categories` exposes the selected resource categories for status/reporting code.

Guard deviations attached through `RepairPolicy.guard` now alert by default. Opening a Repair episode from a Guard deviation requires the explicit `GuardDeviationAction.OPEN_REPAIR_EPISODE` setting.
