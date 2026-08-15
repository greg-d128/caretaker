# Caretaker future work

This document records intentionally incomplete, deferred, or proposed Caretaker capabilities. An item listed here is not an implicit security guarantee and must not be treated as implemented until it has code, policy semantics, tests, and documentation.

Last reviewed: 2026-08-15

## Status vocabulary

- **Design direction agreed**: the intended architecture is sufficiently defined for implementation.
- **Proposal pending decision**: alternatives are documented, but an implementation choice has not been approved.
- **Explicitly deferred**: intentionally omitted from the current test/research scope.
- **General future work**: desirable work that has not yet been scheduled or designed in detail.

## Deployment-authorized behavior snapshot signing

**Status: Design direction agreed; implementation pending.**

Behavior snapshots currently have content hashing but are not authenticated artifacts. Snapshot signing should reuse the secure runtime event-signing infrastructure rather than introduce an independent private-key mechanism.

### Signing service

Introduce one supervisor-owned `RuntimeArtifactSigner` abstraction used for event-segment manifests, behavior snapshots, behavior archives, and other runtime-derived artifacts that require authenticity.

The signer should support domain-separated signatures so a valid signature for one artifact type cannot be replayed as another artifact type. The signed payload should include an explicit artifact kind and schema version.

Signing selection:

1. If an external runtime signing authority is configured, snapshots use that external signer and identity.
2. If no external authority is configured and ephemeral runtime signing is enabled, snapshots use the current ephemeral key-evolution identity and key epoch.
3. If signing is required by policy and the required signer is unavailable, Caretaker must follow the configured failure action. It must not silently substitute a weaker signing identity.

Caretaker should continue to avoid directly exposing deployment/private signing-key material to application code. An external authority may be implemented by a signer process, HSM/service adapter, or another narrow signing interface that owns the private key outside the behavior-snapshot store.

### Signing identity journal

Runtime signing identity information is important enough to have an independent append-only log with independent retention.

The signing-identity stream should record at least:

- runtime signing identity creation;
- public key or external public identity;
- public-key fingerprint;
- signing algorithm;
- key epoch;
- first artifact/event sequence covered by the identity;
- old-key-signed transitions to replacement ephemeral public keys;
- external anchor references;
- signer closure/termination where available.

The identity stream should use the existing framed/hash-chained event machinery where practical, but its retention policy must be independent of ordinary application logs. Its retention must be at least as long as any retained artifact that depends on it for verification unless the required identity records are copied into that artifact's archive.

For ephemeral signing, the first public identity is self-recorded unless an external anchor exists. The key-transition chain proves continuity from that retained starting identity, but does not by itself prevent wholesale replacement of both the artifact corpus and its initial self-recorded identity by an attacker with equivalent storage authority. External anchoring remains the stronger assurance mode.

### Snapshot signature envelope

A signed behavior snapshot should bind at least:

- snapshot ID;
- canonical content hash;
- snapshot sequence for the subject;
- previous sealed snapshot hash when one exists;
- target/module identity;
- code identity/hash;
- behavior-generation key;
- monitoring-configuration fingerprint;
- statistics schema version;
- effective policy fingerprint;
- effective authority fingerprint;
- signing identity ID;
- key epoch or external signer generation;
- signature creation time.

Snapshot verification derives the reported signature state from cryptographic verification. A stored text label such as `SIGNED` is never authoritative by itself.

Behavior archives should contain the identity/key-transition records required to verify archived ephemeral signatures, or contain durable references to an external authority that remains independently resolvable.

## Guard baseline reconstruction after restart

**Status: Design direction proposed; implementation pending.**

An accepted Guard baseline should survive process restart without replaying the entire raw behavior-event history.

### Core objects

Use four related but distinct concepts:

1. **Behavior generation key**: defines which observations are statistically compatible.
2. **Active behavior snapshot**: updateable statistical accumulator for one behavior generation.
3. **Sealed behavior snapshot**: immutable, hashed, and signed materialization of an active snapshot.
4. **Accepted Guard baseline**: immutable acceptance record that references a sealed snapshot.

An accepted baseline must never be updated in place by later observations. New observations update the current active snapshot. This preserves the existing Guard property that observed behavior does not automatically become trusted behavior.

### Behavior generation key

At minimum, the generation key should contain:

- logical target/module identity;
- code identity/hash;
- monitoring-configuration fingerprint;
- behavior statistics schema version.

Optional configured dimensions can include:

- workload/population label;
- environment fingerprint;
- application release identity.

A monitoring-configuration fingerprint should include settings that change what observations mean, such as enabled collectors, observation categories, configured sampling policy, attribution behavior, resource normalization/redaction behavior, and statistics target/schema.

### Startup reconstruction

When Guard registers a target after startup:

1. Resolve the current target and compute its code identity.
2. Compute the current monitoring-configuration fingerprint and behavior generation key.
3. Query the evidence store for the newest accepted Guard baseline with an exact compatible generation key.
4. Load the referenced sealed behavior snapshot.
5. Verify its content hash and required signature/identity chain before using it as a baseline.
6. Hydrate `BaselineManager` directly from the verified baseline instead of relearning it from raw events.
7. Query for the latest active-snapshot checkpoint for the same generation key.
8. If the checkpoint is compatible, restore its statistical accumulators and continue updating them.
9. If the checkpoint belongs to an older generation, retain/seal it as the previous generation and create a new active accumulator.
10. If no compatible accepted baseline exists, begin candidate baseline learning for the current generation.

If baseline verification fails, policy decides whether Guard continues without an accepted baseline, enters a degraded state, requires operator action, or prevents an operation that explicitly requires an accepted baseline.

### Evidence-store changes

The evidence store should gain indexed operations similar to:

- `latest_accepted_guard_baseline(generation_key)`;
- `behavior_snapshot(snapshot_id)`;
- `latest_active_behavior_checkpoint(generation_key)`;
- `store_active_behavior_checkpoint(state)`;
- `seal_behavior_snapshot(state, reason)`.

SQLite rows should expose the generation key and state as indexed columns rather than requiring a full JSON scan.

Raw behavior windows remain useful evidence and debugging material, but restart reconstruction should not require replaying them.

## Behavior statistics and automatic snapshot materialization

**Status: Design direction proposed; implementation pending.**

Behavior statistics should be continuously updateable while a behavior generation remains compatible. The design should resemble database statistics collection: bounded representative sampling and compact statistical summaries rather than indefinite retention of every observation.

### Compatibility and rotation

A behavior generation becomes incompatible when either of the following materially changes:

- target code identity; or
- configured monitoring semantics.

Configured monitoring semantics include the set/depth of collectors and the sampling/normalization rules that determine what the statistics represent.

When the generation changes:

1. stop updating the current active snapshot;
2. materialize any final checkpoint;
3. seal and sign the old snapshot if it has useful observations;
4. retain it in snapshot storage;
5. start a fresh active snapshot for the new generation.

A runtime transition from LIGHTWEIGHT to BEHAVIOR under the same configured adaptive policy does not itself invalidate the generation. Instead, samples are stratified by instrumentation level and sampling regime. This avoids continuously rotating snapshots merely because adaptive observation became more intense while still preventing sparse and dense samples from being silently treated as identical populations.

If the configured LIGHTWEIGHT/BEHAVIOR sampling rates, collector capabilities, or normalization rules change, the monitoring fingerprint changes and the active snapshot rotates.

### Statistical model

For each numeric metric, keep cheap exact online statistics where possible:

- count;
- minimum;
- maximum;
- sum;
- arithmetic mean;
- variance and standard deviation using a numerically stable online algorithm;
- success/failure counts and rates where applicable.

Examples include:

- call duration;
- events per sampled call;
- filesystem events per sampled call;
- network events per sampled call;
- subprocess events per sampled call;
- exception/validation-failure rate.

For distribution shape, maintain a bounded representative reservoir controlled by a statistics-target policy. Quantiles are computed from the bounded sample when a checkpoint or sealed snapshot is materialized.

Required reported percentiles should include at least:

- p10;
- p50 / median;
- p90;
- p95;
- p99 when sample size is sufficient.

The reservoir should use a true streaming reservoir-sampling algorithm so memory consumption remains fixed as the execution population grows. The statistics target controls the level of detail, analogous to a database statistics target.

A later implementation may substitute a mergeable quantile sketch if supervisor-level multiprocess aggregation requires efficient merging. The persisted statistics schema should therefore identify the algorithm/version used rather than assume reservoir sampling forever.

### Histograms and categorical behavior

At materialization time, numeric reservoir values can also produce equal-population histogram bounds. This makes visual comparison of distribution shape easier than percentiles alone.

Categorical/resource behavior should maintain bounded frequency information, such as:

- most common event kinds;
- most common network destinations;
- most common filesystem roots;
- most common subprocess identities;
- most common imports/dynamic-code operations;
- total observed category count;
- distinct resource count;
- overflow/truncation indicators.

Security-sensitive novelty detection must not mistake truncation for proof that a resource has never appeared. If complete resource identity retention exceeds the configured snapshot limit, the snapshot must explicitly mark coverage as incomplete and Guard must not make an absence-based security claim from only the top-frequency list.

### Sampling provenance

Every active/sealed snapshot should record:

- total executions represented;
- sampled executions;
- sampled execution count by instrumentation level;
- configured sampling interval/rate for each level;
- observation period start/end;
- number of process-local populations represented when known;
- statistics target/reservoir size;
- statistics algorithm/schema version;
- collector/monitoring fingerprint;
- code identity;
- policy fingerprint;
- authority fingerprint.

Comparisons should use normalized rates and distributions rather than raw totals when sampling densities differ.

### Automatic materialization

Sampling and snapshot materialization are separate operations. A sampled execution updates the active accumulator; it does not create and sign a complete snapshot.

Policy should allow sealing/materialization on:

- behavior-generation invalidation;
- a configured number of accumulated samples;
- maximum active-snapshot age;
- explicit operator request;
- pre-repair evidence completion;
- repair activation;
- post-repair validation transition;
- long-term repair acceptance;
- controlled shutdown.

A periodic checkpoint of the active accumulator may be unsigned or locally integrity-protected according to policy, but an accepted Guard baseline must reference a sealed snapshot that satisfies the required signing policy.

## Supervisor-owned multiprocess adaptive aggregation

**Status: Explicitly deferred to future work.**

Adaptive exception/timing counters and repair-evidence gates are currently process-local/persisted without a supervisor-owned atomic aggregation model. Multiple application workers can therefore observe the same target generation independently.

Future design should move authoritative adaptive counters to the supervisor while keeping process-local hot paths inexpensive. Workers should batch threshold observations to the supervisor, which owns:

- target/generation identity;
- application-wide counter merging;
- promotion state;
- evidence-gate progress;
- policy-generation transitions;
- checkpointing;
- cross-process sampling provenance.

The design must explicitly define whether each threshold is process-local, application-wide, or workload/population scoped. This work is intentionally deferred until the single-process lifecycle and behavior-statistics model are stable.

## Import-hook dependency instrumentation

**Status: General future work.**

`instrument_dependencies()` can wrap imported module attributes, but references captured earlier with `from module import function` cannot be replaced retroactively.

A future import-aware facility should allow instrumentation intent to be registered before application imports. When a selected dependency module loads, Caretaker can wrap configured functions before ordinary application modules capture references.

This should remain explicit and policy-controlled. Caretaker should not globally instrument every import by default.

## Container validation backend

**Status: Proposal pending decision.**

The existing validation subprocess is a process-isolation mechanism, not a hostile-code sandbox. A stronger backend should preserve the existing validation contract while allowing policy to require a minimum isolation capability.

### Backend contract

Introduce a backend interface conceptually similar to:

- `capabilities()` reports effective isolation features;
- `prepare(validation_bundle)` creates the isolated environment;
- `run(request, limits)` executes deterministic validation;
- `collect()` returns validation evidence and effective isolation metadata;
- `destroy()` reliably removes the environment.

The validation result must record the backend and actual isolation properties that were applied. Policy should compare required capabilities with actual capabilities rather than trust only a backend name.

### Proposed isolation levels

- **PROCESS**: current subprocess validation. Fast and portable, but not a hostile-code security boundary.
- **CONTAINER**: rootless container with explicit restrictions and no host control socket exposure.
- **VM_OR_EXTERNAL**: reserved for a future stronger isolation backend.

A deployment policy may require a minimum isolation level. If the requirement cannot be satisfied, Caretaker should become proposal-only or follow another explicit failure action. It must not silently downgrade isolation.

### Recommended first implementation

The recommended first container adapter is rootless Podman on Linux. A Docker-rootless adapter can follow as a compatibility backend using the same `ValidationBackend` contract.

Default container restrictions should include:

- rootless/user-namespace execution;
- no network unless explicitly enabled/allowlisted by policy;
- read-only root filesystem where practical;
- read-only source and dependency inputs;
- isolated writable temporary workspace;
- no host Docker/Podman socket mounted into the validator;
- all unnecessary Linux capabilities dropped;
- `no-new-privileges`;
- seccomp enabled;
- bounded CPU, memory, PID count, output size, file size, and wall-clock time;
- explicit environment-variable allowlist;
- no implicit access to Caretaker signing keys, authority files, evidence stores, control sockets, or application secrets.

Validation should use an explicit **validation bundle** rather than exposing the entire application host filesystem. The bundle can contain the candidate, required source/module material, deterministic test/replay input, dependency/release metadata, and validation policy. The result records the container image digest/runtime identity, mounts, network mode, resource limits, and security-profile fingerprints used during validation.

A container still shares the host kernel and must not be described as equivalent to a VM boundary. High-assurance policy should eventually be able to require `VM_OR_EXTERNAL` instead of `CONTAINER`.

### Decision still required

Before implementation, choose whether the initial supported runtime is:

1. Podman only, keeping the implementation small;
2. Podman plus Docker through a common CLI adapter from the start; or
3. a generic OCI abstraction with more implementation complexity.

The current recommendation is option 1: implement and harden rootless Podman first, then add Docker compatibility after the evidence/isolation contract is stable.

## Runtime repair graduation to source/repository workflow

**Status: Explicitly deferred.**

Caretaker currently treats accepted repair as a runtime experiment. Automatic conversion of an accepted runtime replacement into a source-tree patch, commit, pull request, or deployment artifact is intentionally omitted.

This omission is deliberate:

- it keeps the research/test environment safer;
- it avoids granting Caretaker repository-write authority;
- it simplifies deterministic repair testing;
- it maintains a clean boundary between runtime recovery and software-development workflow.

Future work may export a signed review bundle containing a unified diff, original/replacement hashes, incident/evidence references, policy and authority fingerprints, validation results, and short/long-term acceptance evidence. Applying that bundle to a repository remains a separate authorized workflow.

## Other logging and storage work

**Status: General future work.**

- Extract the writer, attachment store, and system collector into independently restartable worker processes while preserving the current IPC and evidence contracts.
- Add external `LogSink` implementations and reliable store-and-forward delivery to independent log collection systems.
- Evaluate a formal forward-secure signature construction beyond epoch key evolution.
- Add Zstandard and MessagePack as optional codecs without changing the standard-library default.
- Add attachment checkpoint binding at every event-segment rotation, not only final graceful closure.
- Add distributed multi-host ordering and clock-quality evidence.
- Add index migrations and faster columnar analytical exports.

## Other system evidence and metrics work

**Status: General future work.**

- Integrate the advanced lightweight system-metrics provider through `MetricsProvider`.
- Add specialized parsers for collected `/proc` and `/sys` bodies.
- Add process-scoped performance tracing that does not require privilege escalation.
- Add cgroup-aware application process selection.
- Correlate system cycles with Guard windows, calls, incidents, and baseline units of work.

## Other baselines and analysis work

**Status: General future work.**

- Automated operator-owned periodic baseline generation and acceptance workflows.
- Same-period prior-year and rolling annual comparison orchestration where workloads justify it.
- Richer distribution-shift, seasonality, and workload-normalization analysis.
- HTML and static-site reports for baseline change and root-cause evidence.
- Persistent log-template identities and cross-version template evolution.
- Causal graph construction that retains supporting and contradicting evidence.

## Other Guard work

**Status: General future work.**

- Wider audit-event normalization and platform-specific tests.
- Sensitive-file to outbound-network sequence analysis.
- Persistent aggregation rollups and database migrations.
- Full old-versus-new dependency environment runner.
- Native-extension and operating-system event attribution.

Adaptive instrumentation escalation is no longer listed as future work; its initial implementation now exists and should be evolved through the behavior-statistics and supervisor-aggregation work above.

## Other decorators and Repair work

**Status: General future work.**

- Descriptor-aware classmethod, staticmethod, and property support.
- Async functions, validators, retries, and event-loop hooks.
- Hard timeout modes using subprocess or cooperative cancellation.
- Custom transactional resources such as database savepoints and filesystem transactions.
- Per-call disable, diagnose, and approval contexts.
- Multiple Repair providers and historical model selection.
- Function-set, module, and package repair artifacts.

## Other stronger isolation and enforcement work

**Status: General future work.**

- Dedicated unprivileged validation worker.
- Landlock and namespace experiments outside the container backend.
- Native audit hooks installed before interpreter initialization.

## Other integrity work

**Status: General future work.**

- Verified import loader fully coupled to signed function fingerprints.
- Signed or externally witnessed accepted-baseline chronology.
- Fleet aggregation for probabilistic verification.
- Public transparency logs for releases, roots, baselines, and runtime identity anchors.

## Review rule for future capabilities

Before moving an item out of this document, the implementation should include:

1. explicit authority and policy semantics;
2. deterministic failure behavior;
3. persistence/restart semantics where applicable;
4. performance implications for the normal application path;
5. console/operator visibility;
6. tests proving that exposed policy settings change runtime behavior;
7. documentation of residual security limitations.
