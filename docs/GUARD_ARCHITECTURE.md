# Guard architecture

Guard records and compares observable runtime behavior. It does not claim to determine malicious intent or contain arbitrary hostile code.

## Pipeline

```text
collect
    → attribute
    → normalize
    → aggregate
    → build candidate baseline
    → explicit acceptance
    → detect deviations
    → score significance
    → optional LLM assessment
    → runtime-control decision
    → alert, instrument, repair, quarantine, route, or restart
```

## Evidence types

### `CodeIdentity`

Identifies an exact implementation using distribution, version, module, qualified name, source path and hash, bytecode hash, native-extension flag, and optional integrity-manifest identity.

### `BehaviorEvent`

Represents one normalized operation. Events may record imports, network operations, file access, directory scans, subprocesses, dynamic code, logs, or function-call boundaries.

### `BehaviorWindow`

Aggregates a bounded interval of events into counts, rates, resource sets, and representative samples. Duration windows retain compact numeric summaries; persisted behavior snapshots can compare their bounded mean, variance, and quantiles without retaining raw duration observations.

### `RuntimeInspection`

Captures a module or function's current identity and differences from load time and the previous inspection.

### `BehaviorBaseline`

Represents explicitly accepted behavior for one exact code identity, workload label, and optional environment fingerprint.

### `BehaviorDeviation`

Keeps expected and observed evidence plus separate novelty, magnitude, sensitivity, confidence, persistence, and total significance scores.

Snapshot and periodic comparison reports may include a three-sigma duration
distribution signal when compatible samples are sufficient. This is bounded,
read-only evidence and never accepts a baseline, changes policy, or grants
Repair authority.

## Guard engine

`GuardEngine` coordinates:

- `AuditEventCollector`
- `DependencyCollector`
- `BehaviorAggregator`
- `BaselineManager`
- `DeviationDetector`
- `RuntimeInspector`
- `PeriodicInspector`
- `CaretakerModuleFinder`
- `GuardHookManager`
- optional `BehaviorAssessmentProvider`
- `RuntimeControlPlane`

## Operating modes

- `DISABLED`
- `LEARN`
- `AUDIT`
- `RESEARCH`
- `FORENSIC`
- `ENFORCE`

Mode is a policy statement, not a security guarantee. For example, `ENFORCE` can deny operations represented by supported hooks, but it cannot prevent an unknown native bypass merely because the enum is named enforce.

## Baseline lifecycle

```text
CANDIDATE
    → OBSERVING
    → REVIEW_REQUIRED
    → ACCEPTED
    → SUPERSEDED or REJECTED
```

Guard does not automatically absorb new behavior into an accepted baseline. This is intended to reduce gradual baseline poisoning.

## Bidirectional Repair integration

Guard may:

- supply evidence to a repair request;
- reject a candidate that introduces a prohibited capability;
- monitor candidate probation;
- roll back a candidate after a significant deviation;
- open a repair episode when application-owned behavior appears defective.

Repair may:

- request a recent behavior summary;
- request temporary research/forensic instrumentation;
- register the active `FunctionSlot` implementation for inspection;
- ask Guard to assess candidate source and probation behavior.

## Scope selection

Guard should generally observe selected packages, modules, and repair targets rather than every event in the interpreter.

Scope can be selected by:

- `GuardPolicy.targets` module patterns;
- function patterns;
- a repair target's `GuardBinding`;
- temporary `InstrumentationLease` records;
- event-triggered escalation.
