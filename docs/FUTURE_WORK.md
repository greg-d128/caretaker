# Caretaker future work

This document records intentionally incomplete, deferred, or proposed Caretaker capabilities. An item listed here is not an implicit security guarantee and must not be treated as implemented until it has code, policy semantics, tests, and documentation.

Last reviewed: 2026-08-30

## Long-term roadmap and multi-scope research

The detailed long-term roadmap is maintained in
[`LONG_TERM_ROADMAP.md`](LONG_TERM_ROADMAP.md). It records proposed work for
testing infrastructure and failure corpora, bounded post-mortem Incident
Capsules, safe inspection and isolated replay, evidence-efficient performance,
resource budgets, adversarial invariants, compatibility/upgrade testing, and a
future Application/Host/Infrastructure Caretaker research model.

The roadmap is explicitly deferred design work. Application Caretaker remains
the current scope; Host and Infrastructure Caretakers must remain independently
installable, independently governed, and independently trusted. Cross-Caretaker
requests are evidence rather than authorization, and broader authority is gated
on demonstrated Application Caretaker maturity.

## Status vocabulary

- **Implemented in development tree**: code, policy semantics, tests, and documentation exist in the current development tree; retained here for review traceability until release.
- **Design direction agreed**: the intended architecture is sufficiently defined for implementation.
- **Proposal pending decision**: alternatives are documented, but an implementation choice has not been approved.
- **Explicitly deferred**: intentionally omitted from the current test/research scope.
- **General future work**: desirable work that has not yet been scheduled or designed in detail.

## Incident Capsules and operator side artifacts

**Status: Implemented in development tree for the initial bounded capture slice.**

Supervised runs can now create immutable, content-hashed, data-only Incident
Capsule revisions under the run data directory. The logging policy controls
capture level and resource limits. Capsules retain policy/authority references,
bounded incident state, side-artifact references, and a communication-history
list reserved for future communication records. The console can save its
current incident-focused view as a redacted `operator-view` side artifact.

The initial Explorer provides read-only capsule, revision, integrity,
side-artifact, and correlated persisted-timeline inspection. It can now request
isolated replay for an incident-linked bounded JSON fixture through the
supervisor, including bounded non-interactive replay across incident-linked
historical fixtures; replay results remain separate evidence and cannot modify
the capsule. Full policy-specific capture of every application state source,
communication approval, and delivery remain future work. Capsule viewing remains read-only
evidence inspection;
operator artifacts cannot authorize Repair, satisfy validation, modify policy,
close incidents, or expand Caretaker authority. See
[`INCIDENT_CAPSULES.md`](INCIDENT_CAPSULES.md) for the current contract.

## Policy-governed incident communications

**Status: Implemented in development tree for reviewable draft generation and local review records; delivery remains future work.**

During an incident, Caretaker already has or may accumulate useful context:
observed symptoms, evidence, affected targets, hypotheses, policy and integrity
state, attempted interventions, validation results, rollback outcomes, and
remaining uncertainty. The current communication facility turns that context
into bounded, audience-specific reviewable drafts so operators spend less time
reconstructing the same incident for different stakeholders. It does not
contact an external audience.

The implementation is a projection of one canonical incident state, not a
collection of independently generated stories. Every audience view preserves the same
underlying facts, timestamps, incident identity, evidence provenance, and
uncertainty while varying terminology, detail, emphasis, and permitted content.

### Audience policy

Communication policy defines named audience profiles. Deployments may
create their own profiles; possible built-in examples include:

- on-call operators and incident command;
- application and platform engineers;
- security and assurance teams;
- service owners and business leadership;
- customer support and account teams;
- internal users or affected customers;
- public status-page readers;
- legal, compliance, or regulatory reviewers.

An audience profile may control:

- permitted incident/evidence classifications and fields;
- required redaction and masking rules;
- technical depth, terminology, and maximum length;
- whether source, stack, host, dependency, customer, repair-candidate, or policy
  details may be included;
- whether hypotheses, rejected hypotheses, attempted repairs, validation gaps,
  or security indicators may be disclosed;
- required impact, scope, mitigation, next-update, ownership, and contact fields;
- draft triggers and minimum/maximum update cadence;
- whether distribution is internal, restricted, customer-facing, public, or
  regulated;
- required reviewer role and approval threshold;
- permitted export or delivery adapters.

The current implementation enforces audience section allowlists, bounded
output, redaction, explicit unknowns, provenance, review-required state, and
immutable approved/rejected local review records.
Audience policy constrains disclosure; it does not grant incident, Repair,
policy, or delivery authority. A communication request from another Caretaker,
application component, LLM, or external system is input, not authorization.

### Canonical incident communication model

A communication snapshot should be a bounded, versioned, data-only object bound
to at least:

- incident and communication IDs;
- audience profile ID/version/fingerprint;
- incident-state revision and evidence cutoff time;
- source evidence IDs/hashes and Incident Capsule reference when one exists;
- effective policy and authority generation/fingerprint;
- current impact and affected-scope assessment;
- confirmed observations, supported inferences, hypotheses, and unknowns kept as
  distinct categories;
- interventions proposed, attempted, rejected, activated, rolled back, or under
  observation;
- validation performed, validation omitted or unavailable, and residual risk;
- freshness, omissions, redactions, truncation, and degraded-evidence state;
- drafter/model identity and deterministic template/schema version;
- reviewer, approval, export, correction, and retraction history.

The model must not invent root cause, impact, recovery, safety, or ETA. If the
evidence does not establish a claim, the draft should say that it is unknown,
under investigation, inferred, or awaiting validation. A later correction must
link to the superseded communication rather than silently rewriting history.

### Drafting and delivery authority

Draft generation and message delivery must be separate actions.

- Drafting may be automatic when policy permits because it does not contact an
  external audience.
- External, customer, public, legal, or regulatory communication should require
  explicit authorized review by default.
- Policy may permit narrowly scoped automatic internal updates for named
  audiences and deterministic triggers.
- An LLM may tailor language but cannot select a broader audience, remove required
  caveats, weaken redaction, authorize delivery, or declare an incident resolved.
- Delivery adapters must be explicitly configured, narrowly scoped, authenticated,
  rate-limited, idempotent, and auditable. No generic webhook or messaging token
  should automatically become authority to publish every communication class.
- Adapter failure must retain the approved draft and report uncertain delivery;
  retries must not create duplicate or contradictory updates.

The initial implementation provides reviewable exports and console drafts.
Ticket, chat, email, paging, status-page, or regulatory
adapters can be added separately after their authentication, confidentiality,
idempotency, and failure semantics are defined.

### Security, privacy, and operational constraints

- Apply capture and redaction policy before LLM or template processing, not only
  before final rendering.
- Treat logs, exception text, customer data, proposed fixes, external replies,
  and prior communications as untrusted evidence and possible prompt-injection
  carriers.
- Prevent cross-audience leakage: an executive or public summary must not inherit
  fields allowed only in an operator or security view.
- Never expose secrets, private keys, credentials, raw sensitive values, or
  unapproved customer identifiers.
- Do not publish generated Repair source merely because a repair was attempted;
  communicate bounded status and evidence appropriate to the audience.
- Bind drafts to an evidence cutoff and show when the underlying incident has
  advanced since the draft was produced.
- Bound input context, output size, draft frequency, retained versions, provider
  calls, and delivery retries so communication cannot become a new incident.
- Preserve operator-authored changes and distinguish them from Caretaker-
  generated text.
- If evidence integrity, policy, authority, or redaction is degraded, fail closed
  for external delivery and state the degradation in internal drafts.

### Suggested lifecycle

```text
incident state changes
        |
        v
canonical communication snapshot
        |
        +--> operator/engineering projection
        +--> security projection
        +--> leadership/support projection
        `--> customer/public projection
                    |
                    v
             policy review gate
                    |
                    v
          export or delivery adapter
                    |
                    v
       receipt / failure / correction record
```

Useful triggers may include incident opened, impact changed, evidence materially
changed, mitigation attempted, Repair activated, validation failed, rollback
completed, service restored, long-term acceptance reached, and incident closed.
Time-based reminders may request an update without manufacturing new content.

### Validation and adversarial testing

Before this capability is described as implemented, tests should demonstrate:

- deterministic projection from one canonical incident state to multiple
  audience policies without factual contradiction;
- redaction and field-allowlist enforcement before and after language tailoring;
- explicit separation of confirmed fact, inference, hypothesis, and unknown;
- refusal to invent root cause, impact, resolution, or ETA;
- prompt-injection resistance across incident evidence and prior messages;
- stale-draft detection after incident-state or policy changes;
- reviewer/approval enforcement and prevention of unauthorized delivery;
- correction, supersession, retraction, idempotency, and duplicate suppression;
- bounded behavior during event storms, provider outage, adapter failure, and
  repeated delivery failure;
- no communication path can modify policy, approve Repair, satisfy validation,
  accept a baseline, close an incident, or expand Caretaker authority;
- exact provenance from rendered statements back to supporting evidence or an
  explicit operator-authored assertion.

Caretaker Validation should cover audience projection, schema, redaction,
approval, and adapter contracts. Caretaker Crucible should challenge cross-
audience leakage, prompt injection, forged evidence, stale drafts, unauthorized
dispatch, contradictory summaries, delivery replay, and pressure-induced
resource exhaustion.

## Known assurance debt in implemented features

**Status: Open security and correctness work.**

An "implemented" label in this document means that a usable research path exists; it does not mean that every assurance property around that path is complete. Strict expected-failure regression tests preserve the following known debts:


These debts are also executable documentation in `tests/test_validation_trust_boundary.py` and `tests/test_security_assurance_regressions.py`. They should remain strict expected failures until the corresponding boundary is implemented and the test passes normally.

### Validation transaction and protocol hardening

The parent now rejects missing, duplicate, unknown, malformed, non-finite, or
mismatched bound function-validation evidence before a candidate can be
eligible. The current worker envelope includes a protocol version and a
supervisor-generated transaction ID bound to the candidate artifact hash, base
code hash, target and callable contract, policy and authority fingerprints,
requested isolation, backend identity, and mandatory check set. Persisted repair
attempts retain the selected backend, isolation tier, and capability details.
Remaining work is to have external validators authenticate the result
envelope.

Registered cases that require domain types need explicit trusted codecs or fixture references; arbitrary object deserialization should not be part of the validator protocol.

### Independent operator authorization

Administrative commands support an optional independent authorization verifier.
`HMACControlAuthorizer` provides signed command envelopes with replay
protection, explicit action scope, expiry, and policy-generation binding. The
least-friction UID/GID mode remains available for local development; deployments
where application code and operators share an account should configure the
independent verifier or a separately controlled operator account.

### Non-overridable isolation

Policy may distinguish a hard, non-overridable minimum from a preferred tier
that an operator may override. The current required-isolation path is hard:
operator approval can retain the candidate for review but cannot activate it
without validation at the policy-required tier.

### VM capability attestation

The VM backend derives its reset-boundary and network claims from configured
restore/clone behavior, a live guest firewall/egress ruleset attestation, and
route checks in addition to the root-owned network-isolation marker. Remaining
VM assurance work includes independent host/upstream egress evidence, relevant
profile hashes, and guest image provenance; the guest ruleset digest and marker
must not be treated as complete end-to-end network attestation.

## Deployment-authorized behavior snapshot signing

**Status: Implemented in development tree.**

Behavior snapshots are authenticated runtime artifacts that reuse the secure runtime event-signing infrastructure rather than introducing an independent private-key mechanism.

### Signing service

The supervisor-owned runtime artifact signing service is shared by event-segment manifests, behavior snapshots, behavior archives, and other runtime-derived artifacts that require authenticity.

The signer uses domain-separated artifact payloads so a valid signature for one artifact type cannot be replayed as another artifact type. The signed payload should include an explicit artifact kind and schema version.

Signing selection:

1. If an external runtime signing authority is configured, snapshots use that external signer and identity.
2. If no external authority is configured and ephemeral runtime signing is enabled, snapshots use the current ephemeral key-evolution identity and key epoch.
3. If signing is required by policy and the required signer is unavailable, Caretaker must follow the configured failure action. It must not silently substitute a weaker signing identity.

Caretaker should continue to avoid directly exposing deployment/private signing-key material to application code. An external authority may be implemented by a signer process, HSM/service adapter, or another narrow signing interface that owns the private key outside the behavior-snapshot store.

### Signing identity journal

Runtime signing identity information is stored in an independent append-only hash-chained Signing Identity Journal with independent retention.

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

The identity journal is independently hash-chained and has retention policy independent of ordinary application logs. Its retention must be at least as long as any retained artifact that depends on it for verification unless the required identity records are copied into that artifact's archive.

For ephemeral signing, the first public identity is self-recorded unless an external anchor exists. The key-transition chain proves continuity from that retained starting identity, but does not by itself prevent wholesale replacement of both the artifact corpus and its initial self-recorded identity by an attacker with equivalent storage authority. External anchoring remains the stronger assurance mode.

### Snapshot signature envelope

The signed behavior snapshot envelope binds:

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

**Status: Implemented in development tree.**

An accepted Guard baseline survives process restart without replaying the entire raw behavior-event history.

### Core objects

Use four related but distinct concepts:

1. **Behavior generation key**: defines which observations are statistically compatible.
2. **Active behavior epoch**: the singular updateable statistical accumulator for one function generation.
3. **Sealed epoch snapshot**: immutable, hashed, and signed materialization of one exclusive sample range.
4. **Accepted Guard baseline**: immutable acceptance record that references a sealed snapshot.

An accepted baseline must never be updated in place by later observations. New
observations update the current active epoch. Closing it atomically installs a
disjoint successor, allowing several consumers to reference the same sealed range
without double-counting calls. This preserves the existing Guard property that
observed behavior does not automatically become trusted behavior.

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
7. Query for the latest active-epoch checkpoint for the same generation key.
8. If the checkpoint is compatible, restore its statistical accumulators and continue updating them.
9. If the checkpoint belongs to an older generation, retain/seal it as the previous generation and create a new active epoch.
10. If no compatible accepted baseline exists, begin candidate baseline learning for the current generation.

If baseline verification fails, policy decides whether Guard continues without an accepted baseline, enters a degraded state, requires operator action, or prevents an operation that explicitly requires an accepted baseline.

### Persistence implementation

The current implementation uses the dedicated behavior snapshot/baseline store and active-statistics checkpoint files as the restart index. Guard resolves the exact code hash and monitoring fingerprint, verifies the accepted baseline reference and sealed snapshot, and hydrates `BaselineManager` directly. Raw behavior windows remain evidence/debugging material and are not replayed during restart.

A future storage optimization may move the behavior-generation lookup into indexed SQLite columns so very large installations do not depend on filesystem metadata scans. This is an optimization, not a correctness dependency.

## Behavior statistics and automatic snapshot materialization

**Status: Implemented in development tree.**

Behavior statistics are continuously updateable while a behavior generation remains compatible. The design should resemble database statistics collection: bounded representative sampling and compact statistical summaries rather than indefinite retention of every observation.

### Compatibility and rotation

A behavior generation becomes incompatible when either of the following materially changes:

- target code identity; or
- configured monitoring semantics.

Configured monitoring semantics include the set/depth of collectors and the sampling/normalization rules that determine what the statistics represent.

When the generation changes:

1. atomically close the current active epoch;
2. record its epoch ID, ordinal, sample-sequence range, and observation boundaries;
3. materialize, seal, and sign the epoch if it has useful observations;
4. retain it in snapshot storage;
5. start a fresh active epoch for the new generation.

A runtime transition from LIGHTWEIGHT to BEHAVIOR under the same configured adaptive policy does not itself invalidate the generation. Instead, samples are stratified by instrumentation level and sampling regime. This avoids continuously rotating snapshots merely because adaptive observation became more intense while still preventing sparse and dense samples from being silently treated as identical populations.

If the configured LIGHTWEIGHT/BEHAVIOR sampling rates, collector capabilities,
or normalization rules change, the monitoring fingerprint changes and the active
epoch closes before the new generation begins.

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

Every active/sealed epoch should record:

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
- authority fingerprint;
- epoch ID and ordinal;
- first/last generation-scoped sample sequence;
- whether the epoch was closed atomically.

Comparisons should use normalized rates and distributions rather than raw totals when sampling densities differ.

### Automatic materialization

Sampling and snapshot materialization are separate operations. A sampled execution
updates the active epoch; it does not create and sign a complete snapshot. Manual
function capture closes the epoch rather than copying an overlapping view.

Policy should allow sealing/materialization on:

- behavior-generation invalidation;
- a configured number of accumulated samples;
- maximum active-epoch age;
- explicit operator request;
- pre-repair evidence completion;
- repair activation;
- post-repair validation transition;
- long-term repair acceptance;
- controlled shutdown.

A periodic checkpoint of the active epoch may be unsigned or locally
integrity-protected according to policy, but an accepted Guard baseline must
reference a sealed snapshot that satisfies the required signing policy.

### Randomized behavioral-regime snapshots

**Status: Implemented in development tree for opt-in randomized epoch boundaries; regime clustering and cross-population analysis remain future work.**

An optional collection mode now creates randomized, non-overlapping behavior
snapshot boundaries within an otherwise unchanged code and monitoring generation.
This is intended to reveal distinct runtime regimes—such as configuration-selected
implementations, workload classes, rare resource use, or behavior changed through
mutable global/dependency state—without falsely claiming that the function code
changed.

The mode should:

- select bounded epoch lengths from a policy-controlled uniform random
  distribution rather than always sealing at the same call count;
- keep every call in at most one epoch and preserve generation-scoped sample
  sequence ranges so randomized snapshots cannot double-count evidence;
- record the selection algorithm, parameters, effective random seed commitment,
  and reason for each boundary as sampling provenance;
- support optional application-supplied workload or behavior-regime labels without
  treating those labels as trusted proof of equivalence;
- retain unlabeled regime discovery using normalized event/resource rates,
  distributions, and novelty rather than requiring application cooperation;
- show regime/epoch coverage separately from generation-wide coverage so samples
  from observably different populations are not presented as one homogeneous
  profile;
- impose minimum useful sample counts and maximum epoch lengths; retention bounds,
  and supervisor backpressure to avoid floods of low-value artifacts;
- preserve rare/outlier epochs even when common regimes dominate the workload;
- compare discovered regimes both within one unchanged code generation and across
  code/monitoring generations; and
- never automatically promote a randomized snapshot to an accepted Guard baseline
  merely because it reached a sample target.

The current choice is policy-selectable reproducibility: a configured seed gives
deterministic boundary selection for controlled experiments, while the default
unset seed uses a system random source and stores only commitments. Regime
clustering, rare-regime preservation beyond bounded epoch partitioning, and
cross-process population analysis remain future design work. Randomized epochs
are evidence only and cannot automatically become an accepted Guard baseline.

## Operator-directed and coverage-complete behavior collection

**Status: Implemented in development tree for bounded operator-directed scheduling and explicit adaptive promotion; coverage-complete backlog orchestration remains future work.**

The console's bounded manual function and module capture records signed
collection provenance with each saved snapshot: request ID, authenticated
operator identity, reason, requested scope/subject/call count, effective
authority generation and fingerprint, observed generation/call count, completion
time, and capture outcome. This metadata is evidence only; it cannot change the
behavior generation, policy, authority, baseline, or Repair state. The initial
operator scheduler provides a durable bounded queue, active/pending limits,
priority/deadline ordering, restart recovery, cancellation state, and explicit
backpressure. Read-only generation-aware coverage-backlog discovery and console
visibility are now implemented; opt-in bounded automatic backlog promotion is
implemented, while application-wide measured overhead budgets remain future
work. Automatic promotion now separates bounded no-call waiting targets from
targets that have begun collecting calls, so a rare function does not consume
the same automatic collection slot as a hot function. The console reports both
counts. Fairness across hot and rare functions remains future work. The console
and operator control plane can also promote one
registered adaptive lightweight target into pre-repair Behavior. This request
is fixed to Behavior, records the operator reason and authority generation, and
cannot authorize Repair or alter policy.

The initial operator-directed promotion slice is implemented for one registered
adaptive target at a time. It supports investigation of a suspicious function
and records the target, reason, requesting operator, and effective authority
generation in the returned operation record and persists that provenance with
the adaptive state for restart inspection. Automatic cycles also persist a
captured/deferred/failed outcome when backlog coverage is reconciled. Promotion is an
evidence-collection request, not acceptance of the resulting behavior as a
trusted Guard baseline. Generation-aware promotion requests, requested
evidence targets or durations, and durable eventual outcomes remain part of
the broader coverage orchestration work.

Behavior collection must have an application-wide resource budget. A scheduler
should limit active high-cost collection using measured overhead as well as a
simple concurrency ceiling. It should account for call rate, observed collection
cost, sampling density, queue pressure, and application resource pressure. A rare
function that is armed and waiting for calls should not consume the same budget as
a hot function actively collecting evidence, and must not indefinitely block
other subjects that can make useful progress. Operator priority, audit deadlines,
fairness, cancellation, and backpressure should be explicit and visible in the
console.

Every eligible function generation that has never produced a useful behavioral
snapshot is now represented in a bounded, read-only coverage backlog. When
`collection_auto_promote` is enabled, the supervisor health cycle promotes a
bounded number of adaptive `armed_waiting` targets rather than promoting all
functions at startup. The console distinguishes queued, armed/waiting, actively
collecting, sufficiently covered, deferred, and failed collection states and
explains why a subject is in that state; stale/suspicious prioritization,
measured resource budgets, and fairness remain future work.

Sealed behavioral snapshots should inform later lightweight anomaly triggers.
Candidate signals include expected duration ranges, failure/return categories,
resource-event rates, and novelty thresholds, provided they are compatible with
the same subject generation and monitoring configuration. Snapshot-derived
thresholds remain evidence, not authority, and must retain provenance and
confidence/sample-size information.

The lightweight path may need a very small amount of initial statistical context
before a full snapshot exists, especially an expected runtime estimate. Whether
it should collect return categories, timing sketches, or other initial statistics
is an open performance decision. Any such collection must be fixed-cost, bounded,
sampled where appropriate, and measured against the goal that lightweight slots
remain extremely inexpensive. If useful signals cannot meet that budget, they
belong only in promoted Behavior collection.

### Return-type and return-shape learning review

**Status: Implemented in development tree for bounded type/category/shape evidence and an evidence-only comparison report; live novelty decisions remain unimplemented.**

The current contract is intentionally narrower than return learning:

- `@logged` may persist a bounded `repr(output)` when its `result` option or
  the effective logging policy enables result capture. The configured character
  limit applies, and the value remains evidence rather than an executable
  object.
- Repair result capture persists a bounded data-only record containing the
  runtime type name, representation, representation hash, truncation/redaction
  flags, and shallow object size. It records successful selected outputs only;
  an exception is represented by failure evidence, not by a fabricated result.
- Behavior statistics persist call counts, success/failure counts, durations,
  resource observations, event counts, bounded categories, and bounded
  non-value structural shapes for successful returns observed during Behavior
  collection. A category contains the concrete runtime type and a coarse builtin
  family; a shape contains only a safe scalar/container family and coarse length
  bucket, never an exact value.
- Annotations describe a declared contract and validators perform explicit
  policy checks. Neither is treated as an observed runtime distribution or as
  proof that a return is representative.

Consequently, `None`, unions, subclasses, iterators/generators, containers, and
application-defined objects can be represented by bounded type/family
categories and, where safe, structural shape buckets. Containers are not
recursively normalized and iterators are not consumed. Category and shape
bounds plus overflow indicators are retained with the generation and sample
counts, while the comparison report only identifies newly observed categories
or shapes when both snapshots are the same generation, the selected snapshot is
newer, and both have the minimum successful sample count. Incomplete tables and
incompatible snapshots are disclosed rather than treated as absence evidence.
Categories, shapes, and this report remain evidence only and do not affect Guard
deviations or Repair decisions.

Remaining novelty-design review must distinguish declared annotations and
validators from observed runtime types, structural shapes, bounded categorical
summaries, and exact values. It should determine:

- what is currently collected in LIGHTWEIGHT and BEHAVIOR modes;
- how `None`, unions, subclasses, iterators/generators, containers, large values,
  and application-defined objects are represented safely;
- how novelty is evaluated without treating a rare legitimate return as proof of
  failure;
- which generation, sample-size, freshness, and provenance constraints apply;
- how sensitive values are redacted and untrusted representations are bounded;
- how annotations, application validators, and learned observations disagree;
  and
- which return signals can be collected within the lightweight overhead budget.

The bounded category contract and comparison report are tested and are not an
unusual-return detector. A live detector must not be described as implemented
until its false-positive, freshness, generation, and policy semantics are defined
and tested.

## Supervisor-owned multiprocess adaptive aggregation

**Status: In progress in development tree for the durable worker-batch ledger and supervisor reconciliation; supervisor-authorized promotion remains future work.**

The first implementation slice is documented in
[`ADAPTIVE_AGGREGATION.md`](ADAPTIVE_AGGREGATION.md). A durable
`SupervisorAdaptiveAggregationStore` now accepts bounded worker observation
batches only when the supervisor supplies matching target-generation, policy,
and authority context. It merges application-wide counters, retains a bounded
threshold-event window, protects aggregate state with a content hash, rejects
stale context, records bounded worker provenance with idempotent batch handling,
reconciles enabled worker contexts during the supervisor health cycle, and
publishes per-batch delivery acknowledgements.

Adaptive exception/timing counters and repair-evidence gates are still process
local for live decisions. Multiple application workers therefore do not yet
share supervisor-authorized promotion state.

Future design should move authoritative adaptive counters to the supervisor while keeping process-local hot paths inexpensive. Workers should batch threshold observations to the supervisor, which owns:

- target/generation identity;
- application-wide counter merging;
- promotion state;
- evidence-gate progress;
- policy-generation transitions;
- checkpointing;
- cross-process sampling provenance.

The remaining implementation must explicitly define and enforce whether each
threshold is process-local, application-wide, or workload/population scoped. It
must consume worker acknowledgements where needed and move threshold evaluation
and promotion state without double-counting the existing single-process
lifecycle.

## Import-hook dependency instrumentation

**Status: Implemented in development tree for explicit pre-import module/function scopes.**

`instrument_dependencies()` can wrap imported module attributes, but references captured earlier with `from module import function` cannot be replaced retroactively. `install_dependency_import_hook()` now provides an explicit, scoped startup hook for named modules and `module:attribute` functions.

When a selected dependency module loads, Caretaker wraps configured functions before ordinary application modules capture references. The hook can be restored, and it never instruments unlisted imports. Broader import routing and already-loaded reference replacement remain future work.

This should remain explicit and policy-controlled. Caretaker should not globally instrument every import by default.

## Validation isolation backends

**Status: Implemented in development tree for PROCESS, rootless Podman CONTAINER, and Multipass VM. Docker and EXTERNAL adapters remain future work.**

Validation uses a common capability-based backend contract. Policy specifies a minimum isolation level rather than a product name:

- **PROCESS**: the existing subprocess worker; fast and portable, but not a hostile-code sandbox.
- **CONTAINER**: `RootlessPodmanValidationBackend`, which requires rootless Podman and a pre-provisioned local image. It uses no network, a read-only root filesystem, dropped capabilities, `no-new-privileges`, PID/CPU/memory limits, an isolated writable request/result directory, and read-only Caretaker/application inputs. It never pulls an image automatically.
- **VM**: `MultipassValidationBackend`, which uses a pre-provisioned guest with no host-directory mounts. Artifacts cross the boundary through `multipass transfer`. Normal mode can restore a configured clean snapshot before validation; suspicious scenarios can use a disposable clone of a stopped clean template and purge it afterward.
- **EXTERNAL**: reserved for a future dedicated remote/disposable validation service.

If a configured backend cannot meet `ValidationPolicy.minimum_isolation`, `backend_unavailable_action` controls whether repair fails, remains proposal-only, or enters an explicit operator-review workflow. Required isolation is non-overridable: approval can retain a proposal for review but cannot authorize activation without validation at the requested tier.

Multipass candidate validation is distinct from the existing whole-subject Multipass deployment documented in `ISOLATED_EXECUTION.md`. The built-in VM backend requires the validator guest to contain Caretaker/application dependencies, refuses host mounts, and by default requires a root-owned network-isolation provisioning marker before advertising guest network control.

Outstanding isolation work:

- Docker-rootless compatibility adapter using the same CONTAINER contract;
- EXTERNAL/remote validator backend;
- richer capability attestation (seccomp/profile hashes and image provenance; the guest firewall policy hash is now exposed);
- optional stronger VM technologies when a deployment requires them.

## Runtime repair graduation to source/repository workflow

**Status: Explicitly deferred.**

Caretaker currently treats accepted repair as a runtime experiment. Automatic conversion of an accepted runtime replacement into a source-tree patch, commit, pull request, or deployment artifact is intentionally omitted.

This omission is deliberate:

- it keeps the research/test environment safer;
- it avoids granting Caretaker repository-write authority;
- it simplifies deterministic repair testing;
- it maintains a clean boundary between runtime recovery and software-development workflow.

Future work may export a signed review bundle containing a unified diff, original/replacement hashes, incident/evidence references, policy and authority fingerprints, validation results, and short/long-term acceptance evidence. Applying that bundle to a repository remains a separate authorized workflow.

## Policy-controlled Repair rollout, mirroring, and shadow execution

**Status: Proposed future functionality pending detailed design.**

Caretaker currently supports candidate probation and a narrow
`PURE_FUNCTION` differential-execution mode. For explicitly confirmed pure
functions, that mode may run the previous and candidate implementations against
deep-copied arguments, compare their results, and select an appropriate return or
open another Repair episode. It is not a general traffic rollout, canary,
mirroring, or shadow-deployment system.

Future Repair should provide more operator and policy control over how a validated
candidate is introduced. Potential execution strategies include:

1. **Percentage canary routing**: execute either the deployed version or the
   candidate for a policy-selected share of eligible calls. The selected version
   supplies the authoritative result for that call.
2. **Sampled differential verification**: for a policy-selected share of calls,
   execute both versions in an isolation model appropriate to the function,
   compare results and permitted state effects, and return the result selected by
   explicit policy.
3. **Original-authoritative shadow mode**: continue returning only the deployed
   version's result while executing the candidate as non-authoritative shadow
   work. Candidate output, exceptions, timing, resource use, and Guard behavior
   become evidence but cannot affect the application result.
4. **Candidate-authoritative mirrored verification**: return the candidate result
   only after policy permits candidate authority, while running the previous
   version on selected calls as a comparison oracle and immediate fallback when
   its execution remains safe.
5. **Staged ramp**: progress through operator-defined percentages or observation
   stages, such as shadow, small canary, larger canary, full candidate traffic,
   initial acceptance, and long-term acceptance. Advancement may be manual or
   policy-driven; rollback remains independently governed.

### Proposed policy controls

A future rollout policy should be immutable, fingerprinted, authority-aware, and
recorded with every routing and comparison decision. It may include:

- execution strategy and which implementation is authoritative;
- candidate traffic percentage and dual-execution percentage;
- staged percentage schedule and whether advancement is manual or automatic;
- stable routing key, randomization method, committed seed, and eligibility
  rules;
- minimum calls and elapsed observation time at each stage;
- permitted failure, mismatch, latency, resource, and Guard-deviation budgets;
- comparator identity and version, equivalence semantics, and handling of
  inconclusive comparisons;
- return selection when one version fails, both fail, or both succeed but differ;
- maximum additional latency, CPU, memory, provider work, concurrency, and queued
  shadow executions;
- synchronous versus asynchronous shadow execution;
- timeout, cancellation, overload, and unavailable-isolation behavior;
- state-copy, transaction, sandbox, or application-provided isolation adapter;
- masking, retention, sampling, and signing requirements for comparative
  evidence;
- automatic pause, rollback, escalation, and operator-notification thresholds;
- whether a stage or percentage change requires signed authority or explicit
  operator acknowledgement.

Percentages must be bounded from 0 through 100 and have precise semantics. A
configured percentage should identify its population and time/window scope and
should not be described as exact across multiple processes unless a
supervisor-owned coordinator actually provides atomic application-wide routing.
Stable request, tenant, user, session, or workload routing may be necessary to
avoid exposing one unit of work to inconsistent versions. Routing keys may be
sensitive and must follow evidence masking policy.

### Safety and authority requirements

Running both implementations can duplicate database writes, messages, payments,
filesystem changes, network calls, locks, cache mutations, or other side effects.
Therefore:

- pure-function dual execution may remain the safest default;
- idempotent classification alone is not sufficient when two executions are
  concurrent or externally visible;
- side-effecting functions require an explicit application-provided transaction,
  state-copy, mock, sandbox, or shadow adapter that prevents candidate effects
  from escaping;
- asynchronous shadow work must not outlive its bounded incident/application
  context or gain access to stale mutable inputs without explicit policy;
- candidate execution must remain subject to the same Integrity, capability,
  validation, Guard, resource, policy-generation, and authority restrictions as
  ordinary Repair;
- shadow or canary status cannot grant activation authority, satisfy validation
  requirements retroactively, or permit a candidate to modify its governing
  policy;
- a comparison match is evidence of equivalence for the tested inputs and
  comparator, not proof of general correctness;
- the previous implementation is not automatically a correctness oracle and may
  itself be the failing version;
- failure to execute or observe the comparison path must be reported as missing
  evidence rather than counted as agreement.

The authoritative return must be selected before execution according to policy
and recorded in evidence. Caretaker must not silently switch which implementation
is authoritative after seeing a preferred output unless that exact fallback rule
is explicit, validated, and permitted by policy.

### Rollout evidence and operator control

Every rollout should bind evidence to:

- target and function generation;
- deployed and candidate source/code hashes;
- candidate, incident, attempt, validation, and rollout identities;
- effective policy and authority fingerprints/generations;
- execution strategy, stage, configured percentages, routing decision, and
  authoritative implementation;
- input/call identity using masked or stable-token form where required;
- comparator and isolation-adapter identities;
- output equivalence, exception, state-effect, timing, resource, and Guard
  observations for both versions;
- missing, late, cancelled, truncated, or degraded shadow evidence;
- stage advancement, pause, rollback, completion, and operator decisions.

The operator console should show current stage, actual observed routing counts,
coverage, confidence limitations, comparison mismatches, resource cost, Guard
findings, and the authority required for the next transition. Operators should be
able to pause, resume, change an authorized percentage, advance, roll back, or
terminate a rollout without granting arbitrary execution or policy-editing
capability.

### Persistence and multiprocess coordination

The design must define behavior across restart, worker loss, stale workers, and
policy changes. Until durable reconstruction exists, restart should fail safe to
deployed code rather than silently resume a candidate rollout.

Application-wide percentage guarantees require supervisor-owned coordination of
the target generation, routing counters, active stage, candidate identity,
policy generation, worker acknowledgements, comparison coverage, and rollback
state. A process-local implementation must label its percentages and results as
process-local and must not imply atomic fleet or application-wide rollout.

### Required tests before implementation is claimed

- deterministic boundary tests for 0%, 100%, and intermediate routing;
- stable-routing tests across repeated calls and declared routing scopes;
- statistical tolerance tests for randomized routing with recorded seeds;
- dual-execution return, exception, comparator, and state-effect matrices;
- proof that shadow results never become authoritative in
  original-authoritative mode;
- proof that candidate-authoritative mode cannot begin without required
  validation and authority;
- side-effect escape and duplicate-operation tests;
- overload, timeout, cancellation, and missing-shadow-evidence tests;
- stage advancement, pause, rollback, and flapping tests;
- policy/authority change and stale-candidate races at every rollout stage;
- worker loss, supervisor loss, restart, and multiprocess routing tests;
- Guard/Integrity precedence and candidate capability-expansion tests;
- evidence masking, retention, signature, and identity-binding tests;
- adversarial tests for routing manipulation, comparator manipulation, selective
  shadow evasion, and attempts to count unavailable comparisons as matches.

This functionality should remain application-scoped. It does not imply host,
infrastructure, source-control, package-publication, or deployment authority.

## Repair workflow restart and crash recovery

**Status: Design clarified; implementation unblocked but not complete.**

The default Repair engine, pending approvals, active work, repair-rate history, regression corpus, FunctionSlot replacements, and candidate observation lifecycle are process-local. Historical records may be written to logging or an explicitly supplied SQLite Repair store, but a new engine does not reconstruct an actionable workflow or reactivate a runtime replacement from those records.

The agreed recovery contract is one continuous repair transaction with explicit
milestones. The transaction scope is flexible while a repair is under
evaluation; once a repair is accepted, it is outside that transaction's
rollback scope and a later reversal requires a new incident. Approval is
checked at transaction start and remains valid through completion, subject to
authority expiry. Caretaker makes no guarantee about external effects.

The first application-scoped implementation must enforce these decisions:

- An interrupted or failed worker is treated as a rolled-back transaction. The
  failure envelope retains the partial queue, policy state, and milestone
  information needed for reconciliation. Its detail level is policy/debug
  controlled; critical evidence requires a complete individual post-mortem
  packet for each worker.
- Failure response is policy driven: preserve degraded operation, generate an
  incident, replace the worker, or shut down when required evidence cannot be
  preserved. Duplicate data must be identifiable and reconcilable; an
  unresolvable conflict produces a report containing both data sets.
- Authority and approval packets are immutable snapshots of the capabilities,
  policies, approvals, and other state required by a worker. A worker may use
  an authorized packet only until its authority expires. Approval copies are
  policy controlled, with a 60-minute default suggested for ordinary operation
  and shorter expiry allowed during a suggested change. A worker that fails to
  apply a transition by the deadline becomes failed or unauthorized and is
  deliberately replaced using the still-authorized prior policy where
  possible.
- A replacement worker must re-enter through an authorized packet. Probation
  and acceptance counters have policy defaults and per-target overrides;
  incomplete transactions must not double-count them. The supervisor remains
  a controller/checker: workers do the ordinary work, while the supervisor may
  sample evidence, inspect worker behavior, validate external evidence, spawn
  an additional comparison worker, or restart workers within policy.
- Supervisor time is authoritative with a bounded clock-drift allowance.
  Excessive skew is a failure. A supervisor failure loses the control plane;
  the application may continue only as policy permits and otherwise restarts.
  Clustered supervisor recovery and restarting the supervisor itself belong to
  the future Host Caretaker and higher scopes.

`RepairRecoveryPolicy` now carries the reviewed action vocabulary and default
packet lifetimes: 60 minutes for ordinary approval packets, 60 seconds for
suggested-change packets, and 30 seconds of permitted clock skew. The current
planner exposes those settings and rejects candidate reactivation after restart
because that execution path is not implemented. Recovery actions are currently
reported as `PLANNED_ONLY`; the deployed-code rollback remains the only runtime
behavior until supervisor lifecycle orchestration is implemented.

The remaining implementation work is to:

A first recovery inspection slice now exists as `RepairEngine.recovery_plan()`
and the runtime command `runtime-repair-recovery-plan`. It inventories durably
persisted incomplete attempts, reports their last milestone, and selects
deployed-code-only recovery without reactivating a candidate. An explicit
`apply_recovery_plan()` operation can idempotently record that rollback decision
without rewriting the interrupted attempt or its partial evidence. It does not
yet perform policy-selected replacement or shutdown actions.

- mark interrupted incidents, generations, attempts, and validations incomplete;
- reconstruct or deliberately stale pending approvals;
- verify candidate source and policy/authority bindings again after restart;
- recover probation and long-term observation state without double counting;
- persist milestone and failed-worker envelopes with policy-controlled detail;
- reconcile duplicate evidence and emit conflict reports;
- apply policy-selected degraded, incident, replacement, or shutdown actions;
- coordinate the same target across multiple application workers;
- decide whether an accepted runtime replacement may be reactivated at all;
- connect the recovery policy actions to supervisor worker and application
  lifecycle orchestration.

Until this exists, restart is a rollback to deployed application code, not continuation of an in-memory repair.

## Other logging and storage work

**Status: General future work.**

- Extract the writer, attachment store, and system collector into independently restartable worker processes while preserving the current IPC and evidence contracts.
- Add external `LogSink` implementations and reliable store-and-forward delivery to independent log collection systems.
- Evaluate a formal forward-secure signature construction beyond epoch key evolution.
- Add Zstandard and MessagePack as optional codecs without changing the standard-library default.
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

### General downstream application publication

**Status: Explicitly deferred beyond 0.6.0.**

Generalize the installed-wheel verification work into a supported publication
workflow for applications that package Caretaker. The current low-level manifest,
OpenPGP, rollback-state, authority-layer, and bootstrap APIs are reusable, but the
root schema and convenience publication verifier intentionally retain Caretaker's
three-identity A/B/C topology.

Future downstream tooling should provide:

- application-owned roots with configurable signer counts, role separation,
  thresholds, rotation, and revocation rather than Caretaker's fixed topology;
- installed-layout manifest generation for an application's own wheel/package;
- a conventional application publication bundle and offline signing workflow;
- a startup API that verifies both the Caretaker distribution and application
  distribution before importing application code;
- package-resource selection for application, deployment, and framework authority
  layers without requiring operators to discover internal filesystem paths;
- separate console assurance for Caretaker code, application code, policy authority,
  and runtime evidence; and
- integration guidance for independently anchored fingerprints, PyPI/Sigstore
  provenance, immutable deployment configuration, and rollback state.

Embedding a root and its fingerprints inside the same application artifact may
provide internal consistency but must never be described as independent initial
authentication of that artifact.

## Software supply-chain management roadmap

**Status: General future work.**

The current tree verifies Caretaker-style OpenPGP manifests and observes Python dependency identity/behavior. It does not yet implement the broader supply-chain lifecycle commonly associated with inventory, advisory monitoring, updating, and fleet incident response.

Potential future integrations include:

- SPDX and CycloneDX SBOM ingestion, generation, comparison, and policy evaluation;
- OSV/CVE and distribution/vendor advisory ingestion with freshness evidence;
- package-registry and release monitoring;
- lockfile, resolver, license, package-reputation, and dependency-confusion analysis;
- Sigstore, SLSA, in-toto, OCI image, and build-provenance verification;
- bounded dependency-upgrade proposal and compatibility-test workflows;
- signed rebuild/deployment handoff artifacts without granting the runtime repository authority;
- external incident notifications, webhooks, tickets, paging, and fleet remediation coordination.

Each integration requires an explicit source-of-truth, freshness model, offline/degraded behavior, authentication boundary, rate limit, evidence format, and operator authority model.

## Public release assurance

**Status: General future work.**

- Run CI on every supported Python version and on the Linux facilities required by Unix-socket and GnuPG integration tests.
- Publish a current verification report for each tagged release, including strict expected failures and environmental exclusions.
- Test wheels and source distributions outside the source tree.
- Define a reproducible release procedure that binds source revision, wheel/sdist hashes, manifests, and signatures.
- Add dependency review, constraints/lock inputs for release testing, and periodic vulnerability review.
- Maintain a supported-platform matrix and a private vulnerability-reporting path.

## Review rule for future capabilities

Before moving an item out of this document, the implementation should include:

1. explicit authority and policy semantics;
2. deterministic failure behavior;
3. persistence/restart semantics where applicable;
4. performance implications for the normal application path;
5. console/operator visibility;
6. tests proving that exposed policy settings change runtime behavior;
7. documentation of residual security limitations.

## Reserved policy semantics exposed for forward compatibility

**Status: Explicitly reserved and fail-closed.**

The policy-truthfulness pass intentionally leaves a small number of forward-looking settings in public dataclasses so profile/schema evolution does not require re-inventing their names. Their inactive defaults do not imply support, and validators reject values that would rely on the missing behavior. The machine-readable catalog is `caretaker.policy_semantics.RESERVED_SETTINGS`.

Major reserved groups include incident-history Repair context, structural-review scheduling, incident-window oscillation/replay, Guard environment/function-call collectors, durable time-based Guard retention, periodic behavior-comparison scheduling, numeric candidate resource budgets, segment-class-aware log retention, automatic logging-baseline orchestration, metrics-provider adapters, cgroup process discovery, and system-collector-driven Guard/mode degradation.

Before any reserved setting becomes active it must receive runtime semantics, authority/profile review, behavioral tests, migration documentation, and an updated reviewed policy-surface fingerprint.
