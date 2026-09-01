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

`SamplingPolicy` and `AggregationPolicy` control overhead. Sampling decisions are made
**before** Guard performs code attribution, stack construction, value snapshots, or
`BehaviorEvent` creation. Disabled audit categories are discarded even earlier.

`event_sample_rate` controls routine event retention. `CollectorPolicy.unattributed_events`
controls whether process-wide audit events without an active Caretaker target context are
eligible for collection at all. Set it to `False` for adaptive/lightweight deployments
where explicit sampled target calls should define the observation boundary; this check
happens before attribution and stack construction. Leave it enabled only when deliberate
process-wide Guard visibility is desired.

`always_capture_novel_resources` allows the first retained occurrence of a resource
identity to bypass the routine sampling probability so a low event rate does not hide
new files/network destinations/subprocesses.
`stack_sample_rate` independently controls whether a retained event receives a full
stack summary. `maximum_events_per_second` is a hard per-collector processing cap and
is applied before expensive normalization.

Useful strategies include:

- always retain first-seen resources;
- aggregate repeated known activity;
- sample complete stacks independently from event sampling;
- rate-limit forensic evidence before normalization;
- retain bounded representative events.

Guard's in-process event, deviation, assessment, and decision histories are bounded
operational caches. Durable evidence belongs to the configured `EvidenceStore`; keeping
Guard enabled for a long-running process therefore does not make these convenience
histories grow without limit.

## Baselines

`BaselinePolicy` defines the minimum evidence required to create and accept a baseline.
Candidate creation is automatic only when `automatic_candidate_creation=True`.
Acceptance is explicit by default; `automatic_acceptance=True` is a deliberate policy
choice and causes a materialized candidate to become accepted immediately.

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
- newly observed return category or structural return shape (opt-in; requires
  enough successful samples and repeated observations);
- explicit policy violation.

Set `DeviationPolicy.detect_return_novelty=True` to enable the live return
novelty signal. Caretaker compares only the bounded return categories and
shapes recorded for the same accepted Guard generation. Both the accepted
baseline and observed window must contain the configured minimum number of
successful, explicitly captured returns, and a new value must be observed at
least `minimum_new_return_observations` times. The resulting
`OUTPUT_BEHAVIOR_CHANGE` is evidence for the normal Guard action policy; it is
not proof of failure and cannot grant Repair or other authority.

Periodic behavior comparison also supports target-local controls for its
evidence-only duration analysis:

- `duration_distribution_minimum_samples` requires that many duration samples
  in both compatible snapshots (default `20`; bounded to `2..1000000`);
- `duration_distribution_sigma_threshold` controls the mean/spread signal in
  standard-error units (default `3.0`; bounded to finite `0..100`).

These settings affect only comparison evidence and the existing opt-in periodic
change signal. They do not accept a baseline, modify policy, or grant Repair
authority. Dynamic console administration of these settings remains future
work.

## LLM review

`LLMReviewPolicy` enables bounded advisory assessment after deterministic extraction. It defines thresholds for when review is useful and limits on evidence volume. Its `usage` policy defaults to six requests per minute and one concurrent request. Excess requests are rejected explicitly; they are not queued from a Guard hook. A rejected advisory request cannot change Guard, Repair, policy, authority, or Incident Capsule state.

## Actions

`GuardActionPolicy` maps deviations and assessment severity to control-plane actions.
CPython audit-hook observation is post-event telemetry, not a pre-operation sandbox; a
Guard decision must not be described as having prevented an operation that already
occurred. Deterministic policy violations may trigger quarantine, rollback, repair, or
other configured responses. Statistical or LLM-only concerns should normally alert,
escalate instrumentation, or require review.

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

The numeric limits are enforced when an application supplies a bounded Guard
behavior capture for the candidate. Counts are the distinct observed resources
not present in the current baseline. An incomplete capture cannot satisfy a
configured limit when the candidate uses that resource category; it is reported
as a rejected, unverified candidate rather than being treated as zero activity.
Without a capture, the score reports the resource budget as `NOT_ASSESSED` and
the existing coarse capability gate remains in effect. A candidate may be
functionally correct but behaviorally ineligible.


## Repair-target Guard binding

`GuardBinding(enabled=True)` enables call correlation and runtime code inspection for the target. It does **not** implicitly enable network, filesystem, subprocess, or import observation. Those resource categories must be selected individually. `observed_resource_categories` exposes the selected resource categories for status/reporting code.

Guard deviations attached through `RepairPolicy.guard` now alert by default. Opening a Repair episode from a Guard deviation requires the explicit `GuardDeviationAction.OPEN_REPAIR_EPISODE` setting.
