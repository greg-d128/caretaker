# Caretaker future work

This document records intentionally incomplete, deferred, or proposed Caretaker capabilities. An item listed here is not an implicit security guarantee and must not be treated as implemented until it has code, policy semantics, tests, and documentation.

Last reviewed: 2026-08-31

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

## Testing environments and failure corpus

**Status: Implemented in development tree for the metadata-only corpus, explicit trusted harness contract, bounded local observation store, deterministic outcome reports, trusted process execution, the repository application laboratory, and policy-gated Podman/VM runner contracts; live higher-isolation execution and broader observed scenario coverage remain environment-dependent or future work.**

The repository now contains a bounded, schema-validated failure scenario
manifest in [`examples/failure_corpus/manifest.json`](../examples/failure_corpus/manifest.json)
and the read-only `FailureCorpus` loader and explicit `FailureCorpusHarness`
documented in
[`FAILURE_CORPUS.md`](FAILURE_CORPUS.md). It provides reviewed expected
signals, policy actions, authority effects, and minimum isolation levels for a
small set of representative application-scoped failures. The manifest cannot
name or execute code, commands, URLs, or network actions.

Remaining work is to add repository-owned trusted test-harness mappings,
isolated launch/reset/destroy tooling, captured historical incident fixtures,
and broader observed-outcome coverage. The current harness requires
callers to supply runners and does not provide a sandbox or process lifecycle.
The harness has a policy gate with least-friction `PROCESS` as its default and
can fail closed when a configured `CONTAINER` or `VM` minimum is not met. An
explicit trusted process runner now provides per-invocation temporary-workspace
cleanup and process-group timeout handling; it is not a sandbox or substitute
for container/VM lifecycle tooling. An explicit rootless Podman runner now
provides the container-level contract when a pre-provisioned image is present;
an explicit Multipass runner now provides the separate-kernel request-transfer
contract when a pre-provisioned guest is present. Repository-owned oracle
mappings now cover the reviewed default manifest; real application runners and
capsule-linked fixtures are now supported. The repository also exercises the
process protocol against all reviewed mappings and provides a bounded
application laboratory for fifteen bounded process/container stimuli, while a curated
repository of captured real incidents, production-like applications, and
broader container/VM observed coverage remain future work.
The runner-selection CLI exposes the same policy boundary for repeatable local
or isolated runs without turning manifest data into an execution channel.
Beneath that interface, a repository-owned non-root application-laboratory
Podman image and reproducible Make target now provide the same ten stimuli at
the CONTAINER tier when a host has a working rootless runtime. Live container
execution and broader production-like application coverage remain required
before this priority can be considered complete.
Bounded observations can now be stored separately from the manifest, with a
content hash for corruption detection; that hash is not a substitute for
external authenticated shipping. Expected metadata must remain separate from actual evidence; loading or listing
a scenario must never run it or authorize an action.

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
bounded incident state, side-artifact references, and bounded communication
history records for locally generated drafts and operator review decisions.
The console can save its
current incident-focused view as a redacted `operator-view` side artifact.

The initial Explorer provides read-only capsule, revision, integrity,
side-artifact, and correlated persisted-timeline inspection. It can now request
isolated replay for an incident-linked bounded JSON fixture through the
supervisor, including bounded non-interactive replay across incident-linked
historical fixtures; replay results remain separate evidence and cannot modify
the capsule. Full policy-specific capture of every application state source,
external communication approval, and delivery remain future work. Capsule viewing remains read-only
evidence inspection;
operator artifacts cannot authorize Repair, satisfy validation, modify policy,
close incidents, or expand Caretaker authority. See
[`INCIDENT_CAPSULES.md`](INCIDENT_CAPSULES.md) for the current contract.

## Policy-governed incident communications

**Status: Implemented in development tree for reviewable draft generation, optional advisory LLM language tailoring, and local review records; delivery remains future work.**

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
The validation module now defines an optional Ed25519-authenticated result
envelope. A configured verifier pins the validator key ID and public-key
fingerprint, and required mode fails closed when the envelope is absent,
malformed, or invalid. The default local backends remain unsigned for least
friction; `ValidationPolicy.require_result_authentication` can make the
requirement explicit for a target. Remaining work is deployment provisioning
for independent validator identities, key rotation, revocation, and remote
transport/replay semantics; the transport-neutral EXTERNAL backend is
implemented.

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

**Status: Implemented in development tree for opt-in randomized epoch boundaries and bounded read-only cross-population comparison; regime clustering and automatic population discovery remain future work.**

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
unset seed uses a system random source and stores only commitments. A bounded,
read-only comparison helper now compares explicitly retained populations when
their code, generation, monitoring, policy, and authority contexts match; it
does not discover membership, cluster regimes, or merge baselines. Regime
clustering, rare-regime preservation beyond bounded epoch partitioning, and
cross-process or cross-host population analysis remain future design work.
Randomized epochs and population comparisons are evidence only and cannot
automatically become an accepted Guard baseline.

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
implemented. An opt-in signal-priority mode now schedules stale snapshots and
recent significant same-generation Guard deviations before ordinary backlog
entries, while retaining round-robin fairness within each priority tier. A
bounded logging-path overhead snapshot is also available through the
supervisor status response and the console, including queue, drop, and flush
wall-clock measurements; application-wide measured overhead budgets remain
future work. Automatic promotion now separates bounded no-call waiting targets from
targets that have begun collecting calls, so a rare function does not consume
the same automatic collection slot as a hot function. The console reports both
counts. Automatic promotion now uses a bounded, restart-safe round-robin
cursor so hot and rare functions do not remain tied to fixed target ordering;
measured scheduled-collection duration budgets are now optional and visible in
status. The console
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
trusted Guard baseline. Generation-aware collection requests now fail closed
when the resulting capture has a missing or different generation; the failed
capture remains bounded evidence with its mismatch reason. The same generation
binding is used by live behavior comparison. Backlog classification also
ignores queued or failed requests explicitly bound to an older generation, so
they cannot suppress current-generation coverage. Requested evidence targets
or durations and durable eventual outcomes remain part of the broader
coverage orchestration work.

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
explains why a subject is in that state; measured resource budgets remain future
work; explicit operator requests
continue to use their priority/deadline ordering.

The scheduler now provides an initial measured-cost boundary: optional soft and
hard wall-clock budgets can be configured per rolling minute. Completed
collection requests record bounded observed duration; the soft limit is exposed
as an advisory status, while the hard limit leaves queued work intact and
defers new claims until the window clears. Optional soft and hard observed-call
budgets provide the same boundary for call volume, and status reports rolling
observed call rate plus observed/requested sampling density. Queue pressure is
also reported as pending-request utilization, available slots, and a full or
available state; full queues retain the request and apply explicit
backpressure. The scheduler now exposes bounded per-subject recent collection
cost evidence in its resource-budget projection, including collection seconds,
observed and requested calls, sampling density, and average duration. Capture
responses also retain measured duration in their collection provenance. This
makes hot or expensive subjects visible to the operator without treating
telemetry as authority or silently changing automatic-promotion behavior. The
Behavior console now displays the aggregate recent collection seconds and
observed calls alongside queue and backlog state.
Host-resource-aware and density-aware enforcement remain future work. An
optional process-scoped RSS boundary now provides a fail-closed
application-process measurement when configured; host, cgroup, and
multi-process resource coordination remain future work.

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

**Status: Implemented in development tree for bounded type/category/shape evidence, an evidence-only comparison report, and an opt-in policy-gated live novelty signal.**

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
Categories, shapes, and this report remain evidence only by default. When the
explicit return-novelty deviation policy is enabled, repeated newly observed
categories or shapes can produce a normal `OUTPUT_BEHAVIOR_CHANGE` Guard
deviation after generation, sample-size, and freshness checks; the signal
still cannot grant authority or accept a Repair.

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

The bounded category contract, comparison report, and opt-in live detector are
tested. The detector requires an accepted same-generation baseline, explicit
return observations, minimum successful samples, and repeated new observations
to reduce false positives. It remains disabled by default and does not make
absence claims from incomplete tables.

## Supervisor-owned multiprocess adaptive aggregation

**Status: In progress in development tree for durable worker-batch aggregation and supervisor-authorized Behavior transition requests; Repair promotion, cross-host transport, and process orchestration remain future work.**

The first implementation slice is documented in
[`ADAPTIVE_AGGREGATION.md`](ADAPTIVE_AGGREGATION.md). A durable
`SupervisorAdaptiveAggregationStore` now accepts bounded worker observation
batches only when the supervisor supplies matching target-generation, policy,
and authority context. It merges application-wide counters, retains a bounded
threshold-event window, protects aggregate state with a content hash, rejects
stale context, records bounded worker provenance with idempotent batch handling,
reconciles enabled worker contexts during the supervisor health cycle, and
publishes per-batch delivery acknowledgements. It also retains complete
per-worker event-rate counters and emits bounded three-standard-deviation
distribution conflict reports when worker behavior materially differs.

Adaptive hot-path counters remain process local. The supervisor now evaluates
the application-wide exception/timing event window, owns the resulting Behavior
transition request state, and—after all required Behavior acknowledgements—can
record a proposal-only Repair evidence decision. Multiple workers can validate,
apply, and acknowledge the same exact-context request without each
independently promoting or double-counting the threshold.

Future design should continue moving authoritative adaptive counters and repair
evidence to the supervisor while keeping process-local hot paths inexpensive.
Workers should batch threshold observations to the supervisor, which owns:

- target/generation identity;
- application-wide counter merging;
- promotion state;
- evidence-gate progress;
- policy-generation transitions;
- checkpointing;
- cross-process sampling provenance.

The current staged policy path also records an explicit rollback for a
pre-acceptance `ADAPTIVE_POLICY_TRANSITION`. The authenticated rollback
operation releases its target-scoped runtime lease when possible, preserves the
original transition as immutable evidence, and prevents later acknowledgements
or retries from treating the staged policy as active. Once a transition is
`APPLIED`, it is accepted state and requires a new incident for correction.

Supervised application workers can submit bounded batches through the
output-only supervisor control socket. The supervisor re-normalizes each batch
and binds its worker PID to the authenticated Unix peer PID before writing the
same single-writer ledger. Unsupervised runs retain the direct local-ledger
default; an unavailable configured socket is a submission failure rather than
an implicit local fallback. Cross-host transport remains future work.

The remaining implementation must explicitly define and enforce whether each
threshold is process-local, application-wide, or workload/population scoped. It
now preserves an optional, explicitly declared aggregation scope as an
extended target identity and supports an application-owned per-call scope
resolver; it still needs policy and operator semantics for automatic discovery
or changing workload/population membership. It must move dynamic
threshold administration, cross-host transport, process lifecycle orchestration,
and additional resource-aware distribution reconciliation without
double-counting the existing single-process lifecycle. The initial
repair-evidence gate is proposal-only and is implemented in the current slice.
Retained archived batches can now be revalidated against a later policy
fingerprint through a bounded deployment-supplied validator; the resulting
records remain evidence only and do not rewrite aggregates or grant authority.
Worker submission loss is now policy controlled locally: `RETAIN` is the
least-loss default, while `DROP` and `REDUCE` are explicit bounded choices;
incident callbacks, parallel stores, and transport-level throttling remain
future integrations.
The supervisor also records delayed, context-bound threshold proposals as
proposal-only evidence. An authenticated control-plane operation now applies
an approved, effective proposal through a target-scoped runtime authority
lease, rolls back when the application rejects or fails to expose the changed
context, and records a post-application transition for worker verification.
An approved proposal can now be represented by a post-application
`ADAPTIVE_POLICY_TRANSITION` record that binds the prior proposal/review to the
new policy and authority fingerprints and requires exact worker
acknowledgements. This record verifies adoption; it does not apply policy or
grant authority. The Adaptive console now drafts new proposal-only changes;
editing an existing proposal still means creating a new immutable proposal.
Persistent acceptance beyond the bounded runtime lease is now implemented as
an opt-in, operator-authorized, signed deployment-handoff record. It remains
evidence only: it does not mutate the active authority stack or reapply policy
after restart. A deployment-owned installation callback now consumes that
handoff only with current target/generation/policy/authority context and must
acknowledge the exact policy fingerprint plus a deployment artifact hash.
Installation records are immutable and idempotent for completed handoffs;
`PENDING`, `INSTALLED`, `RECONCILED`, `REJECTED`, and `FAILED` outcomes remain evidence and
are never replayed automatically after restart. Remaining work is deployment-
specific worker/process orchestration; a deployment can now deliberately
reconcile a pending external installation without replaying its callback.
The current slice also records immutable
`PENDING`, `APPLIED`, `FAILED`, and `ROLLED_BACK`
lineage records with policy IDs/fingerprints, scope, effective/recorded times,
authority metadata, and worker acknowledgement counts. These records are
visible through the adaptive aggregation status response; they remain evidence
and do not replace the authority stack or make an adaptive actor authoritative.
The current slice also carries bounded timing-breach duration samples and
worker-supplied numeric resource samples, producing three-standard-deviation
evidence conflicts for materially different worker distributions. Automatic
host-resource collection and broader return-shape distributions remain future
work.
Transition deadlines are now policy-defined and stale-worker identities are
reported fail-closed; automatic replacement or unauthorized-worker lifecycle
orchestration remains future work.

Recovery action dispatch now has application-owned adapters for incident
creation and application shutdown. Both effects remain outside Caretaker's
authority: incident creation must acknowledge a durable incident identifier,
and shutdown must acknowledge that the application boundary was requested and
accepted. Missing, malformed, or failed acknowledgements remain rejected and
are retained as action-execution evidence. Remaining work is wiring these
adapters into each deployment's policy-selected lifecycle, then coordinating
their durable incident and shutdown records with multi-worker recovery.

## Import-hook dependency instrumentation

**Status: Implemented in development tree for explicit pre-import module/function scopes.**

`instrument_dependencies()` can wrap imported module attributes, but references captured earlier with `from module import function` cannot be replaced retroactively. `install_dependency_import_hook()` now provides an explicit, scoped startup hook for named modules and `module:attribute` functions.

When a selected dependency module loads, Caretaker wraps configured functions before ordinary application modules capture references. The hook can be restored, and it never instruments unlisted imports. Broader import routing and already-loaded reference replacement remain future work.

This should remain explicit and policy-controlled. Caretaker should not globally instrument every import by default.

## Validation isolation backends

**Status: Implemented in development tree for PROCESS, rootless Podman and Docker CONTAINER adapters, Multipass VM, and a transport-neutral authenticated EXTERNAL adapter; remote deployment assurance remains future work.**

Validation uses a common capability-based backend contract. Policy specifies a minimum isolation level rather than a product name:

- **PROCESS**: the existing subprocess worker; fast and portable, but not a hostile-code sandbox.
- **CONTAINER**: `RootlessPodmanValidationBackend`, which requires rootless Podman and a pre-provisioned local image. It uses no network, a read-only root filesystem, dropped capabilities, `no-new-privileges`, PID/CPU/memory limits, an isolated writable request/result directory, and read-only Caretaker/application inputs. It never pulls an image automatically.
- **CONTAINER**: `RootlessDockerValidationBackend` provides the same boundary through a rootless Docker daemon. It uses Docker-specific rootless detection and flags, requires a pre-provisioned local image, never pulls automatically, and does not use the Docker socket.
- **VM**: `MultipassValidationBackend`, which uses a pre-provisioned guest with no host-directory mounts. Artifacts cross the boundary through `multipass transfer`. Normal mode can restore a configured clean snapshot before validation; suspicious scenarios can use a disposable clone of a stopped clean template and purge it afterward.
- **EXTERNAL**: a caller-owned transport-neutral adapter for a dedicated
  remote/disposable validation service. It requires authenticated results by
  default but does not implement transport, isolation attestation, or key
  lifecycle.

If a configured backend cannot meet `ValidationPolicy.minimum_isolation`, `backend_unavailable_action` controls whether repair fails, remains proposal-only, or enters an explicit operator-review workflow. Required isolation is non-overridable: approval can retain a proposal for review but cannot authorize activation without validation at the requested tier.

Multipass candidate validation is distinct from the existing whole-subject Multipass deployment documented in `ISOLATED_EXECUTION.md`. The built-in VM backend requires the validator guest to contain Caretaker/application dependencies, refuses host mounts, and by default requires a root-owned network-isolation provisioning marker before advertising guest network control.

Outstanding isolation work:

- remote transport and validator-service lifecycle for the EXTERNAL adapter;
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

**Status: Design clarified; effect-aware contract, evidence gate, deterministic routing decision, and registry-aware FunctionSlot invocation bridge implemented; automatic application traffic orchestration remains future work.**

Caretaker currently supports candidate probation and a narrow
`PURE_FUNCTION` differential-execution mode. For explicitly confirmed pure
functions, that mode may run the previous and candidate implementations against
deep-copied arguments, compare their results, and select an appropriate return or
open another Repair episode. It is not a general traffic rollout, canary,
mirroring, or shadow-deployment system.

The application-scoped `RepairRolloutLedger` now provides the first authority
and lifecycle slice. It records immutable `PROPOSED`, `VALIDATED`, `SHADOW`,
`CANARY`, `ACTIVE`, `RETIRED`, and `REVOKED` state transitions in the Repair
store, preserves a transition hash chain, optionally attaches the configured
runtime signature, and emits a corresponding Repair event. An operator may
release a validated candidate as an explicitly labelled `field-repair`; that
record does not make the change a permanent deployment. Promotion to
`permanent-deployment` requires deployment authority and a deployment artifact
hash. Active revocation requires a new incident by default. These records do
not route traffic, activate a FunctionSlot, or grant authority on their own.

When an audit writer callback is supplied, each rollout transition also emits
the registered critical `REPAIR_ROLLOUT_TRANSITION` event with rollout and
transition scope, authority actor, policy fingerprints, lifecycle outcome, and
content/chain hashes. The callback remains output-only; it does not turn audit
input into a control channel.

The bounded `shadow_execute()` primitive now provides original-authoritative
candidate observation for an individual invocation. It keeps the deployed
result authoritative, copies inputs independently, and requires a verified
application-owned isolation adapter when the contract/evidence gate does not
permit unisolated duplicate execution. This remains an execution primitive,
not traffic routing or rollout activation.

The `decide_rollout_routing()` primitive now provides a deterministic,
scope-aware bucket decision for a single invocation. Shadow, canary, and active
field-repair stages have separate policy percentages; stale-policy, expired,
and terminal records fail closed. The result includes a routing-key digest and
decision hash, never the raw key. This is still an evidence/selection boundary,
not an invocation engine, FunctionSlot activation path, or supervisor-wide
coordinator. `execute_rollout()` now consumes that decision for caller-supplied
already-authorized callables and delegates sampled shadow work to the
original-authoritative primitive. FunctionSlot activation, application-specific
failure/fallback policy, and supervisor-wide coordination remain future work.
`execute_slot_rollout()` now adds strict binding to an installed FunctionSlot
candidate and its preceding deployed version without mutating slot state. When
the application supplies its `ObservationManager`, authoritative candidate
calls are recorded through the existing acceptance and rollback policy, while
shadow calls remain excluded. The supervised application also exposes a bounded,
read-only `repair-rollout-status` projection containing lifecycle records,
transition history, and integrity-checked execution summaries. Stale or
unavailable summaries remain visibly unresolved and cannot advance authority.

The first supervisor coordination slice is now implemented through
`RepairRolloutCoordinator`. An authenticated worker can acknowledge the exact
current rollout context and request a deterministic route only while its
acknowledgement matches the rollout's target, candidate, stage, policy,
authority, and effective routing-policy fingerprints. Acknowledgements are
durable, process-bound by the
supervised control plane, retained as stale evidence after a stage transition,
and explicitly do not grant authority or advance lifecycle state.
The same read-only coordination projection now includes an integrity-checked
summary of durable application-wide rollout execution evidence, while missing
or stale evidence is reported as unavailable rather than counted as progress.
The rollout invocation adapters can also consume this coordinator directly;
when supplied, execution requires a current worker acknowledgement and process
identity before routing. Direct process-local invocation remains available for
unsupervised runs.
The Rollouts console tab displays the current-versus-acknowledged worker counts
and readiness state alongside lifecycle and execution evidence. It now exposes
an authenticated, explicitly confirmed operator transition request for legal
next stages, requiring an operator reason and a separate incident UUID for
active revocation. Proposed rollouts cannot use the console to bypass
validation, readiness override is explicit, and the supervisor/ledger remain
authoritative. It also supports separate pause/resume controls over executable
stages: pause is fail-closed and readiness-free, resume requires readiness or
an explicit override, and a paused rollout cannot advance or become permanent
until resumed. Policy-authorized operator percentage changes are recorded as
same-stage transitions; increases require explicit policy permission and
readiness or an override. FunctionSlot activation, atomic fleet percentages,
and deployment-owned worker orchestration remain future work. A registry-aware
`RepairEngine.invoke_rollout()` bridge now resolves the rollout target on every
invocation and delegates to the strict slot binding. Its explicit
`bind_rollout()` convenience wrapper can resolve a current record and routing
key per application call; automatic replacement of existing decorated
application callables remains future work.
Optional `RolloutReadinessRequirements` now evaluates explicit evidence
thresholds for the next stage and reports each passing or failing check without
advancing the rollout. Thresholds remain disabled by default; staged authority,
atomic fleet counters, and deployment-owned worker orchestration remain future
work.
The supervised control plane now has an explicitly confirmed operator advance
request that uses those readiness results for promotion and preserves a
separate safety path for retirement or incident-backed revocation. A proposed
rollout still cannot be marked validated through that request without the
validation workflow.

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

The recovery API also provides fail-closed `validate_supervisor_time()` and
`validate_authority_expiry()` primitives. They make supervisor time
authoritative, report the measured skew, reject skew beyond the configured
tolerance, and reject packets at or after expiry. A bounded, canonical JSON
transport codec now carries and verifies packet integrity across an
application-owned transport. The local supervisor control socket also
provides process-bound register/refresh handoffs with an application-supplied
live context and bounded in-memory replay protection. Cross-host
authentication, shared-memory/queue adapters, durable replay state, and
multiprocess lifecycle orchestration remain future work.

The application worker registry now supports packet-aware admission and marks
an admitted worker unauthorized when its packet expires; restarting it clears
the packet and requires re-admission. It also creates a packet-verified,
single-use replacement request and admits a replacement only when the failed
worker, worker kind, exact context, packet integrity, and packet expiry all
match. The admitted worker retains the failed worker ID as bounded replacement
provenance. This is lifecycle enforcement inside the existing registry; OS
process spawning and replacement orchestration remain future work. The
application-owned local control socket now transports both initial/refresh
packets and the existing single-use replacement request; it binds each
registration to the authenticated Unix peer PID and returns the registry's
process-start identity. Shared-memory/queue and cross-host packet transport,
durable replay state, and deployment-specific process orchestration remain
future work.

The registry also supports `refresh_authorized()` for a live worker that needs
to reacquire an expiring approval packet. Refresh requires the worker to remain
authorized and unexpired, verifies the replacement packet against the current
target, generation, code, policy, capabilities, and supervisor context, and
preserves process identity and acceptance counters. A failed, stopping, or
expired worker cannot use refresh to regain authority; it must follow the
replacement admission path. Changing the authority snapshot does not itself
authorize a policy transition or reset acceptance state.

`WorkerAcceptancePolicy` now resolves conservative replacement-worker
probation and acceptance counters, with per-target overrides. Authorized
workers can be initialized in probation, advance one observation at a time, and
reach `ACCEPTED` or `FAILED` in the in-process registry. The default guideline
is 1,000 successful executions for each stage with no failures; these states
never grant authority or replace packet verification. An optional SQLite
acceptance ledger now checkpoints progress by exact target, generation, code,
and policy context, deduplicates observation IDs, and restores matching
progress after restart. A registered live worker can submit one bounded
observation at a time through the local supervisor control socket; the
supervisor binds the observation to the registered process and derives its
target and policy context. Cross-host transport and broader reconciliation
remain future lifecycle work.

The supervisor now exposes a policy decision boundary for failed workers. It
records bounded in-flight evidence immediately, supports incident capture, and
only counts a worker as restarted after a callback-owned replacement reports
success. Restart exhaustion selects the existing degraded, disable, or stop
action vocabulary. A replacement handler now also requires an application-owned
cleanup callback when a process starts but packet admission fails, and reports
missing or rejected cleanup explicitly rather than treating the process as a
successful replacement. Direct process spawning, cross-process replacement
packet distribution, and general policy-specific incident/shutdown
orchestration remain future work. The `ApplicationWorkerLifecycle` adapter now
connects application-owned initial launch and replacement callbacks to the
same packet, acceptance, and cleanup gates. The supervised writer, event-server,
control-server, and system-collector failure paths now create an initial Incident Capsule
immediately through the application-owned callback; process spawning remains a
deployment-specific future capability.
Workers may now provide bounded diagnostic context with heartbeat or
failure state. Standard failure envelopes omit that supplemental context;
`CARETAKER_DIAGNOSTIC_DEBUG=1` includes it as diagnostic evidence for controlled
diagnosis, including the last milestone, partial queue, and policy-state
snapshot when supplied. This does not persist a complete post-mortem packet or
authorize recovery, and the critical-evidence and durable recovery workflows
remain future work. The supervisor can now persist each handled failure
envelope as a data-only `WorkerFailureRecord`; the supervised runtime stores
these records in `<policy.directory>/repair.sqlite` before selecting a restart,
degraded, disable, or stop action. This is durable failure evidence, not a
complete individual post-mortem packet, and a persistence error is surfaced in
the action result rather than silently treated as success. The supervisor can
now accept an application-owned post-mortem collector for critical evidence.
`create_worker_postmortem_packet()` requires the worker identity, rollback
state, milestone, partial queue, and policy state, stores the packet with a
content hash, enforces a one-megabyte serialized bound, and records
`COMPLETE`, `INCOMPLETE`, or `INVALID` status on the individual failure record.
`verify_worker_postmortem_packet()` checks the stored structure, identity,
required evidence, size, and hash without granting authority. Missing or
malformed critical packets remain durable evidence of an incomplete
post-mortem; collection does not itself select or authorize recovery.
`reconcile_worker_postmortems(records, scope=...)` now provides the first
multi-worker reconciliation slice. It deduplicates exact packet hashes,
combines sufficiently sampled behavioral signatures with the agreed
three-standard-deviation comparison, and retains complete divergent or
non-comparable packets in deterministic, idempotent conflict reports. The
worker-failure intake now assigns a durable reconciliation scope from an
explicit scope, a transaction/incident context, or an isolated failure ID;
target identity alone is never used to merge failures. The supervisor and
public store helper group all persisted failures by that scope and partition
each scope by target identity, so one incident cannot combine evidence from
different targets. Conflict reports retain incomplete/invalid packet
references as well as valid packets.
This is evidence reconciliation only and does not merge policy, authority, or
recovery state.

The recovery planner now also resolves the configured interrupted-transaction
action into an explicit, durable policy decision. It records whether the
action is enabled, remains planned-only, falls back to deployed code, and
requires application orchestration. It still does not execute worker
replacement, application shutdown, or incident callbacks itself.

`RepairEngine.apply_recovery_plan()` may now receive an explicit application-
owned handler map for those actions. A handler must return
`{"accepted": true}` before its action is recorded as executed; missing,
rejected, or failed handlers remain visible in the durable recovery record.
The default call supplies no handlers and therefore performs no application
orchestration. The supervisor now provides a replacement-handler factory that
routes replacement admission through `WorkerRegistry.prepare_replacement()`
and `register_replacement()`. The application still owns process creation;
packet verification, expiry, exact context, and acceptance-state checks occur
before the handler can satisfy the recovery gate. Cross-process spawning and
fleet coordination remain future work. The direct worker-failure path also
provides `build_authorized_restart_callback()`, which accepts an application-
owned spawn result only after the replacement has been admitted with that
packet. A generic `started=true` callback cannot replace an already-authorized
worker.

The supervisor can now consume coordinated worker-failure evidence and select
the ordinary or critical-evidence recovery action per scope. Dispatch still
requires the application-owned handler acknowledgement and records execution
status without granting authority. A durable worker-failure recovery checkpoint
is written before dispatch and finalized afterward; repeated reconciliation
does not rerun a completed handler, and a pending checkpoint is surfaced for
deliberate handling. Deployment-specific durable incident,
replacement, and shutdown lifecycle integration remains future work.

The supervisor also exposes `handle_worker_failure_cohort()` for one
continuous transaction. The caller supplies all affected failed or
unauthorized workers and a bounded reconciliation scope; Caretaker persists
each rollback envelope and, when required, each complete post-mortem packet
before reconciling the cohort and selecting one policy action per target. This
prevents an early worker callback from causing a replacement or shutdown before
the remaining worker evidence has been collected. Application-owned handlers
still perform external incident, replacement, and shutdown effects, and the
cohort API does not grant authority or spawn processes.

The read-only `worker-failure-recovery-status` control command now provides a
bounded operator projection of persisted failure, conflict, and recovery
checkpoint state without returning packet payloads or exposing an action
endpoint. It is evidence visibility only; deployment-specific lifecycle
orchestration remains future work.

The supervisor can now issue a bounded, content-hashed
`ComparisonWorkerAssignment` under an existing authorized worker packet. An
application-owned worker may use that assignment to independently review
referenced evidence and return a bounded `ComparisonWorkerResult`. The
supervisor binds result acceptance to the registered worker's PID and process
start identity, exact target/policy/authority context, packet, assignment,
and result hashes. Assignment and result records are durable and visible as
read-only status; they are evidence only and cannot grant authority, change
policy, or select recovery. The application still owns process creation and
transport.

The supervisor can also compare a completed result's bounded
`behavior_signature` with peer signatures. Matching metric sets and sufficient
sample counts are combined with weighted distribution statistics; differences
beyond the configured three-standard-deviation threshold produce a retained
outlier report. Missing or insufficient signatures are reported as
`INCOMPLETE_EVIDENCE`, never as agreement. The comparison report is durable,
read-only evidence and does not select recovery or change policy. A bounded
supervisor reconciliation now consolidates multiple independently produced
reports when their assignment contexts match exactly; it retains conflicts and
incomplete coverage and does not average shared baselines. It can join that
result to a same-scope, target-bound worker post-mortem reconciliation as
evidence, without merging the two statistical summaries. Packet-level
post-mortem reconciliation now compares shared transaction context using
per-value hashes and retains context conflicts without combining statistics.
Deployment-wide orchestration remains future work.

### Recovery decisions recorded for the next implementation slice

The following decisions close the current recovery-design questions:

- A repair is one continuous transaction with explicit milestones. Its scope
  covers the work currently under evaluation and may remain flexible while the
  evaluation is active. Acceptance closes that rollback scope; reversing an
  accepted result requires a new incident and transaction. Approval is checked
  at transaction start and remains valid through completion, but never beyond
  authority expiry. Caretaker does not guarantee external effects.
- A failed worker is a rolled-back transaction. Its envelope includes the
  partial queue, policy state, and milestone context available before failure.
  Detail is controlled by policy and the diagnostic DEBUG setting. When the
  evidence is critical, every affected worker contributes a complete individual
  post-mortem packet; a partial packet is itself a recorded evidence failure.
- A replacement receives an immutable, supervisor-issued packet containing the
  full capability, policy, approval, target, generation, and code state it
  needs. Ordinary approval copies may live for 60 minutes by default; suggested
  changes may use a shorter expiry. Frequent approval changes cause workers to
  reacquire the packet rather than forcing high-frequency supervisor copies.
  A replacement is not active merely because a process started: it must verify
  and re-enter through an authorized packet, then satisfy policy-defined
  probation and acceptance counters. Defaults may be overridden per target.
- Supervisor time is authoritative, with bounded clock drift accepted. Excess
  skew is a worker failure. If only some workers apply a transition by its
  deadline, the stale workers are treated as failed or unauthorized and are
  deliberately replaced using the still-authorized prior policy where
  possible. A failed supervisor loses the application control plane; whether
  the application continues or restarts is policy driven. Application Caretaker
  does not elect a replacement supervisor or restart its own control plane;
  clustered supervisor recovery belongs to Host Caretaker and higher scopes.
- Evidence is retained across worker disagreement. A worker may combine partial
  streams only after checking that their distributions are sufficiently close
  (initially three standard deviations when the sample is large enough).
  Otherwise the difference remains investigation evidence, including possible
  environmental causes. Disk pressure, loss, backpressure, duplicate
  reconciliation, conflict reporting, and shutdown are all policy decisions.

The remaining implementation work is to:

A first recovery inspection slice now exists as `RepairEngine.recovery_plan()`
and the runtime command `runtime-repair-recovery-plan`. It inventories durably
persisted incomplete attempts, reports their last milestone, and projects the
linked incident, episode, candidate generation, and validation states that must
be treated as incomplete or not started. The console's Recovery tab can now
load this projection explicitly as bounded, read-only plan rows alongside
worker-failure evidence. An explicit `apply_recovery_plan()` operation can
idempotently record that rollback decision and those lifecycle states without
rewriting the interrupted attempt or its partial evidence. The projection is
deliberately not a mutation of the source records, and it does not yet perform
policy-selected replacement or shutdown actions.

The runtime command `runtime-repair-recovery-apply` now exposes that
acknowledgement operation with an explicit confirmation gate. It builds a fresh
target-scoped plan and records the result with no application-owned handlers,
so the command cannot reactivate candidates or dispatch replacement, incident,
or shutdown actions. The Recovery console can explicitly request this bounded
ledger mutation for a selected interrupted plan through the authenticated
control plane, while remaining read-only with respect to recovery execution.
Applying a plan now revalidates the persisted attempt identity, milestone,
outcome, and linked lifecycle evidence against the current store. A changed or
completed attempt, malformed lifecycle projection, or duplicate decision is
rejected as a stale plan; the source records remain immutable and no candidate
is reactivated.

For a target-scoped `RepairEngine.recovery_plan(target_id=...)`, the engine now
adds the currently registered source hash and supervisor authority generation
and fingerprint to the projection. A missing or changed policy snapshot still
keeps execution invalid; all live context must be revalidated before any
future continuation.

If an interrupted attempt or linked episode was awaiting operator approval,
the recovery projection records that approval as `STALE_AFTER_RESTART` and
retains the candidate reference for review. It does not reconstruct the
process-local approval or grant authority; continuation requires a new
transaction and fresh approval checks.

Persisted candidate observation records are now reconstructable through
`recover_candidate_observation_state()` and are included in each recovery-plan
decision. The projection counts each `observation_id` at most once, and both
the in-memory and SQLite Repair stores reject reuse of an observation ID with
different evidence. This restores evidence for probation and long-term review
without replaying calls or treating the projection as candidate activation;
continuation still requires live candidate, policy, and authority
revalidation. The Recovery console shows the bounded observation count and
success/failure split for each interrupted attempt, while retaining the full
projection for detail inspection. Automatic FunctionSlot reactivation remains
future work.

Applying a recovery plan now also writes immutable, content-addressed lifecycle
marks for the interrupted attempt and each linked incident, episode, generation,
validation, or stale-approval record. These marks are durable in both Repair
stores and are written before any application-owned recovery callback. They are
explicit recovery evidence, not mutations to source records and not authority
to continue or reactivate a candidate; repeated application is idempotent.

- verify the current candidate source and policy/authority bindings again after restart;
- recover probation and long-term observation state without double counting;
- collect complete individual post-mortem packets from every affected worker
  when critical evidence is required, with policy-controlled failure handling;
- connect the coordinated worker-failure intake and reconciliation result to
  deployment-specific incident, replacement, and shutdown orchestration;
- execute policy-selected degraded, incident, replacement, or shutdown actions;
- connect target-partitioned recovery decisions to deployment-specific worker
  lifecycle orchestration;
- decide whether an accepted runtime replacement may be reactivated at all;
- connect the recovery policy actions to supervisor worker and application
  lifecycle orchestration.

Until this exists, restart is a rollback to deployed application code, not continuation of an in-memory repair.

## Other logging and storage work

**Status: Implemented in development tree for the local hash-chained stream, optional per-event runtime signing, manifest-backed policy-controlled local segment rotation, a bounded synchronous output-only external sink with local store-and-forward, optional record-hash delivery acknowledgements, an optional HMAC-authenticated delivery adapter with schema-versioned key IDs and in-memory rotation/revocation, and a bounded durable replay receiver; external key provisioning, independent receiver security, and retention/deletion policy remain future work.**

- Extract the writer, attachment store, and system collector into independently restartable worker processes while preserving the current IPC and evidence contracts.
- Add external `LogSink` implementations and connect the audit sink boundary to
  independent log collection systems.
- The output-only `caretaker_audit.log` stream now has a versioned executable
  event registry, per-type examples, required-path checks, minimum-priority
  checks, and redaction rules described in
  [`AUDIT_EVENT_REGISTRY.md`](AUDIT_EVENT_REGISTRY.md). The current local
  slice emits startup, policy, authority-snapshot, worker-authority,
  supervisor-state, worker-failure, incident, audit-data-loss, policy-rejection,
  policy-supersession, audit-delivery-status, console-invocation,
  validation-decision, replacement, recovery-decision, shadow-execution,
  worker-postmortem-reconciliation, and rollout-routing, rollout-execution-outcome, and candidate-observation events and preserves a
  policy-controlled hash chain.
  Selected and non-interactive historical Incident Capsule replay attempts now
  also emit `INCIDENT_REPLAY_OUTCOME` records, including rejected and failed
  requests, with bounded scope and counts; replay output remains separate
  evidence and the event cannot modify a capsule or grant authority.
  Communication draft generation and operator review now emit bounded
  `INCIDENT_COMMUNICATION_DRAFTED` and `INCIDENT_COMMUNICATION_REVIEWED`
  records; both remain delivery-disabled and evidence-only.
  Meaningful supervisor adaptive-aggregation reconciliations now emit
  `ADAPTIVE_AGGREGATION_RECONCILED` records with bounded merge, rejection,
  conflict, pending, and promotion counts; these records are evidence only.
  Supervisor-mediated behavior captures now emit bounded
  `BEHAVIOR_COLLECTION_OUTCOME` records for captured, failed, cancelled,
  deferred, and unavailable requests; these records contain collection
  metadata only and cannot modify policy or authority. Unsupervised local
  operator captures use the same projection with a local Caretaker actor,
  while supervised children remain prohibited from writing their own event.
  Supervised application validation decisions cross an output-only, PID-bound,
  allow-listed control-socket submission path; worker identity is derived by the
  supervisor and the submitted policy context remains evidence. Remaining work
  is to connect every registry type to its producer and complete external
  delivery semantics. A pluggable output-only sink can now receive each exact
  locally persisted audit record, with optional policy-required fail-closed
  delivery, bounded delivery status, and an integrity-checked local retry
  queue. The local writer now applies explicit
  critical/important/ordinary/debug retention rates, preserves critical events
  fail-closed, and records policy-suppressed lower-priority events as critical
  `AUDIT_DATA_LOSS` records.
  Accepted adaptive policy transitions and, when `logging.audit.sign_events` is
  enabled, every audit event are now signed as runtime artifacts when a runtime
  signer is configured; hash-chained mode remains explicitly unsigned. Signed
  audit records are verified during restart recovery using the retained public
  identity journal.
- Complete policy-controlled audit integrity and delivery semantics. Critical policy,
  authority, worker-lifecycle, supervisor-state, and audit-delivery events must
  be retained before their effects are reported complete; ordinary metrics may
  use policy-approved sampling or loss with an explicit loss event.
- Ship critical audit events to an independently secured external sink in
  real time, with bounded local store-and-forward. The current adapter is
  synchronous and output-only, and has bounded local store-and-forward;
  optional record-hash acknowledgements are policy controlled. An optional
  standard-library HMAC delivery adapter now authenticates the exact record
  and its deterministic idempotency key, carries an explicit key ID, and
  verifies a receiver acknowledgement bound to the key and both values.
  Schema-1 envelopes remain verifiable during migration. The optional
  in-memory keyring supports deployment-controlled rotation and revocation;
  private-key/secret provisioning, independent receiver security, and the
  security review for injection, redaction, and disk-full behavior remain
  future work. The bounded SQLite receiver retains replay identities across
  restart but does not solve external retention or key persistence. The sink
  is never a command channel.
- Optional byte/time audit bounds now rotate the local stream into immutable,
  content-hashed segments with a manifest. Verification checks the manifest,
  closed-segment hashes, sequence ranges, and cross-segment chain continuity;
  rotation does not delete old segments. Crash recovery at the rename/manifest
  boundary fails closed rather than guessing, and policy-controlled retention
  or deletion remains future work.
- Add a durable adaptive-policy transition ledger with immutable lineage,
  resulting-policy IDs/fingerprints, effective and recorded timestamps, scope,
  validation/acknowledgement references, and operator/deployment attribution.
- Evaluate a formal forward-secure signature construction beyond epoch key evolution.
- Add Zstandard and MessagePack as optional codecs without changing the standard-library default.
- Add distributed multi-host ordering and clock-quality evidence.
- Add index migrations and faster columnar analytical exports.

## Other system evidence and metrics work

**Status: Implemented in development tree for the policy-disabled-by-default,
bounded output-only monitoring stream and its JSON Lines, Datadog, Splunk HEC,
and New Relic serialization dialects, plus an optional non-privileged
process-scoped metrics provider, bounded publication bridge, and explicit
policy-controlled correlation adapter; advanced system collection remains
future work.**

The existing bounded Caretaker logging-overhead snapshot can now be published
to the optional monitoring stream. The stream is telemetry only and cannot be
read as a command, policy, approval, or authority channel. See
[`MONITORING_STREAM.md`](MONITORING_STREAM.md).

`ProcessMetricsProvider` supplies bounded CPU, memory, thread, and optional I/O
samples for one process without privilege escalation. Consumers can publish
them with `MonitoringStreamWriter.emit_samples()`. The `logging.metrics`
binding can now enable the built-in provider, enforce sampling and output
bounds, and attach policy-selected target, call, incident, Guard-window,
baseline, and process identifiers. Metrics remain output-only evidence and
cannot affect policy or authority.

- Add specialized parsers for collected `/proc` and `/sys` bodies.
- Add process-scoped performance tracing that does not require privilege escalation.
- Add cgroup-aware application process selection.
- Correlate provider snapshots with system cycles and richer Guard windows,
  calls, incidents, and baseline units of work.

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
- Stronger sensitive-file to outbound-network analysis across native code,
  subprocesses, and operating-system event sources.
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

Major reserved groups include incident-history Repair context, structural-review scheduling, incident-window oscillation/replay, Guard environment/function-call collectors, durable time-based Guard retention, periodic behavior-comparison scheduling, segment-class-aware log retention, automatic logging-baseline orchestration, metrics-provider adapters, cgroup process discovery, and system-collector-driven Guard/mode degradation.

Before any reserved setting becomes active it must receive runtime semantics, authority/profile review, behavioral tests, migration documentation, and an updated reviewed policy-surface fingerprint.
