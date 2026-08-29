# Caretaker future work

This document records intentionally incomplete, deferred, or proposed Caretaker capabilities. An item listed here is not an implicit security guarantee and must not be treated as implemented until it has code, policy semantics, tests, and documentation.

Last reviewed: 2026-08-29

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
side-artifact, and correlated persisted-timeline inspection. Isolated replay,
full policy-specific capture of every application state source, communication
approval, and delivery remain future work. Capsule viewing remains read-only
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

- a validation result is not structurally or cryptographically bound to the candidate hash, base source hash, target, policy/authority fingerprints, backend identity, and unique validation transaction;
- the parent does not require proof that every mandatory validation check was returned and passed;
- non-finite numeric validation measurements are not rejected fail-closed;
- persisted `RepairAttempt` evidence does not retain the backend name, isolation tier, and capability/validator identity that produced it;
- validation requests use Python `pickle` and can carry arbitrary pickle-serializable application objects rather than a data-only versioned protocol;
- `StatePolicy.restore_for_validation` is accepted but has no runtime enforcement consumer;
- an operator approval can override missing policy-requested isolation and activate the candidate;
- Multipass network isolation relies on a root-owned provisioning marker rather than live network-policy attestation;
- a persistent Multipass guest can advertise an ephemeral workspace without a configured restore or disposable-clone boundary;
- static candidate inspection does not comprehensively detect dynamically constructed prohibited attribute names;
- same-UID Unix peer credentials do not distinguish application code from an independent operator.

These debts are also executable documentation in `tests/test_validation_trust_boundary.py` and `tests/test_security_assurance_regressions.py`. They should remain strict expected failures until the corresponding boundary is implemented and the test passes normally.

### Validation transaction and protocol hardening

Future validation requests and results should use a canonical, versioned, data-only schema. A supervisor-generated transaction ID should bind the candidate artifact hash, base code hash, target and callable contract, policy and authority fingerprints, requested isolation, backend identity, mandatory check set, and result. The parent should reject missing, duplicate, unknown, malformed, non-finite, or mismatched evidence. External validators should authenticate the result envelope.

Registered cases that require domain types need explicit trusted codecs or fixture references; arbitrary object deserialization should not be part of the validator protocol.

### Independent operator authorization

Administrative commands currently rely on filesystem permissions and Unix PID/UID/GID credentials. A same-account application can therefore be indistinguishable from its operator. Future work should support a separate operator agent/account or authenticated command envelopes with replay protection, explicit action scope, expiry, and policy-generation binding.

### Non-overridable isolation

Policy should distinguish a hard, non-overridable minimum from a preferred tier that an operator may override. An override record must preserve the fact that the requested validation did not occur and must never satisfy a `validation_passed` predicate.

### VM capability attestation

The VM backend should derive capability claims from verified configuration and current guest state: reset/clone boundary, image identity, mounts, subject UID, routes, firewall/egress rules, and relevant profile hashes. A marker file can remain operator-supplied evidence but must not be the sole basis for claiming network isolation.

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

**Status: Proposal pending decision.**

Add an optional collection mode that creates randomized, non-overlapping behavior
snapshot boundaries within an otherwise unchanged code and monitoring generation.
This is intended to reveal distinct runtime regimes—such as configuration-selected
implementations, workload classes, rare resource use, or behavior changed through
mutable global/dependency state—without falsely claiming that the function code
changed.

The mode should:

- select bounded epoch lengths or closing points from a policy-controlled random
  distribution rather than always sealing at the same call count;
- keep every call in at most one epoch and preserve generation-scoped sample
  sequence ranges so randomized snapshots cannot double-count evidence;
- record the selection algorithm, parameters, effective random seed/commitment,
  and reason for each boundary as sampling provenance;
- support optional application-supplied workload or behavior-regime labels without
  treating those labels as trusted proof of equivalence;
- retain unlabeled regime discovery using normalized event/resource rates,
  distributions, and novelty rather than requiring application cooperation;
- show regime/epoch coverage separately from generation-wide coverage so samples
  from observably different populations are not presented as one homogeneous
  profile;
- impose minimum useful sample counts, maximum snapshot rates, retention bounds,
  and supervisor backpressure to avoid floods of low-value artifacts;
- preserve rare/outlier epochs even when common regimes dominate the workload;
- compare discovered regimes both within one unchanged code generation and across
  code/monitoring generations; and
- never automatically promote a randomized snapshot to an accepted Guard baseline
  merely because it reached a sample target.

Open design choices include whether random boundaries should be deterministic from
a committed seed for reproducibility, cryptographically unpredictable to reduce
workload gaming, or selectable by policy; and whether regime clustering belongs in
the application process, supervisor, offline analysis, or a combination of those
layers.

## Operator-directed and coverage-complete behavior collection

**Status: Proposal pending decision.**

Caretaker should let an operator deliberately promote an eligible lightweight
slot into Behavior collection from the console. This supports investigation of a
suspicious function, collection requested by an external audit, and deliberate
completion or refresh of a behavioral snapshot. The request should identify the
subject and generation, reason, requested evidence target or duration, requesting
operator, governing policy/authority generation, and eventual outcome. Promotion
is an evidence-collection request, not acceptance of the resulting behavior as a
trusted Guard baseline.

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
snapshot should enter a bounded coverage backlog. Caretaker should gradually work
through this backlog instead of promoting all functions at startup. Scheduling
should favor missing, stale, suspicious, repair-relevant, or operator-requested
coverage while respecting the collection budget. The console should distinguish
queued, armed/waiting, actively collecting, sufficiently covered, deferred, and
failed collection states and explain why a subject is in that state.

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

Review the current implementation and document exactly how Caretaker learns and
persists expected function returns and how it detects unusual returns. The review
should distinguish declared annotations and validators from observed runtime
types, structural shapes, bounded categorical summaries, and exact values. It
should also determine:

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

The result should be an explicit tested return-behavior contract before unusual
return detection is described as an implemented guarantee.

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

## Validation isolation backends

**Status: Implemented in development tree for PROCESS, rootless Podman CONTAINER, and Multipass VM. Docker and EXTERNAL adapters remain future work.**

Validation uses a common capability-based backend contract. Policy specifies a minimum isolation level rather than a product name:

- **PROCESS**: the existing subprocess worker; fast and portable, but not a hostile-code sandbox.
- **CONTAINER**: `RootlessPodmanValidationBackend`, which requires rootless Podman and a pre-provisioned local image. It uses no network, a read-only root filesystem, dropped capabilities, `no-new-privileges`, PID/CPU/memory limits, an isolated writable request/result directory, and read-only Caretaker/application inputs. It never pulls an image automatically.
- **VM**: `MultipassValidationBackend`, which uses a pre-provisioned guest with no host-directory mounts. Artifacts cross the boundary through `multipass transfer`. Normal mode can restore a configured clean snapshot before validation; suspicious scenarios can use a disposable clone of a stopped clean template and purge it afterward.
- **EXTERNAL**: reserved for a future dedicated remote/disposable validation service.

If a configured backend cannot meet `ValidationPolicy.minimum_isolation`, `backend_unavailable_action` controls whether repair fails, remains proposal-only, or enters the explicit operator-override workflow. The current approval path can authorize activation without the requested isolation; this is recorded as an override and is not successful validation at that tier. Making required isolation non-overridable is tracked as security work.

Multipass candidate validation is distinct from the existing whole-subject Multipass deployment documented in `ISOLATED_EXECUTION.md`. The built-in VM backend requires the validator guest to contain Caretaker/application dependencies, refuses host mounts, and by default requires a root-owned network-isolation provisioning marker before advertising guest network control.

Outstanding isolation work:

- Docker-rootless compatibility adapter using the same CONTAINER contract;
- EXTERNAL/remote validator backend;
- richer capability attestation (seccomp/profile hashes, guest firewall policy hash, image provenance);
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

**Status: Explicitly deferred.**

The default Repair engine, pending approvals, active work, repair-rate history, regression corpus, FunctionSlot replacements, and candidate observation lifecycle are process-local. Historical records may be written to logging or an explicitly supplied SQLite Repair store, but a new engine does not reconstruct an actionable workflow or reactivate a runtime replacement from those records.

Future recovery semantics must define how to:

- mark interrupted incidents, generations, attempts, and validations incomplete;
- reconstruct or deliberately stale pending approvals;
- verify candidate source and policy/authority bindings again after restart;
- recover probation and long-term observation state without double counting;
- provide a production isolated replay backend and safe rehydration for the
  already implemented data-only persistent regression fixtures;
- coordinate the same target across multiple application workers;
- decide whether an accepted runtime replacement may be reactivated at all.

Until this exists, restart is a rollback to deployed application code, not continuation of an in-memory repair.

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
