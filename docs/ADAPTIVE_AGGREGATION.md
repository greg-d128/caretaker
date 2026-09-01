# Supervisor-owned adaptive aggregation

Caretaker's adaptive wrappers run inside application worker processes, but
application-wide adaptive counters must not be inferred by combining
process-local state files. The supervisor-owned aggregation protocol therefore
uses bounded worker batches and an explicit supervisor context.

## Ownership and protocol

`SupervisorAdaptiveAggregationStore` is the single-writer ledger. A worker may
submit a batch containing bounded counters and timestamp-only threshold events;
submission creates an immutable pending file and does not make a promotion or
Repair decision. The supervisor supplies the authoritative:

- target-to-current-generation map;
- effective policy fingerprint;
- authority policy generation; and
- authority policy fingerprint.

The ledger rejects batches with missing or stale context. This prevents a worker
from extending an old generation or policy episode by presenting its own
metadata as current authority.

Each accepted aggregate is scoped by target, optional `aggregation_scope`, generation, code identity,
monitoring fingerprint, policy fingerprint, and authority context. The durable
record merges counters, retains a bounded recent event-time window, and records
bounded per-worker sequence and observation provenance. State is content-hash
protected and checkpointed before the corresponding batch is archived. A batch
ID is retained in the aggregate for bounded deduplication, and an archived
resubmission is idempotent.

`aggregation_scope` is an optional policy value for a known population or
behavior regime, such as a declared input cluster. It is not a clustering
algorithm and does not infer a relationship from observed values. When present,
the supervisor addresses the population with the extended target identity
`<target>::aggregation-scope::<scope>` in its current-generation and policy
maps. A scoped batch is rejected unless that exact extended identity is
current; scoped and unscoped batches therefore cannot merge accidentally. The
durable aggregate retains both the original target and the scope for operator
display. The scope does not grant authority or alter Repair policy.

Applications that can classify population membership from a call may provide
an explicit `aggregation_scope_resolver` to `lightweight()`. The resolver
receives bounded `(args, kwargs)` and returns a non-empty scope string or
`None` for the unscoped population. Caretaker validates the resulting extended
target identity and flushes the current worker batch before switching scopes,
so observations from different populations cannot be merged accidentally. A
resolver exception or invalid result suppresses aggregation for that call only;
the wrapped application call continues normally and the controller records
scope-unavailable diagnostic evidence. This is application-supplied
classification, not automatic regime discovery or proof that two populations
are equivalent.

Reconciliation also writes a bounded per-batch acknowledgement containing the
batch ID, batch hash, result (`ACCEPTED`, `DUPLICATE`, or `REJECTED`), and
aggregate key/rejection reason where applicable. This is delivery provenance
only: an acknowledgement cannot authorize a transition or change policy.

When an adaptive wrapper runs inside a supervised application worker, it may
submit its bounded batch through the supervisor's output-only control socket
using `adaptive-observation-submit`. The supervisor re-normalizes the batch,
binds its `worker_pid` to the authenticated Unix peer PID of the live
application process, and then writes it through the same single-writer ledger.
Worker-supplied identity and context remain provenance and evidence; they do
not grant authority. Unsupervised runs retain the direct local-ledger path as
the least-friction default. A configured supervisor socket that is unavailable
is reported as submission failure and is not silently converted to local
aggregation.

For sufficiently large complete worker samples, the aggregate also tracks
per-worker exception and timing-breach rates. A worker whose rate differs from
the other eligible workers by more than three standard deviations produces a
bounded `ADAPTIVE_DISTRIBUTION_CONFLICT` report. Both the worker and comparison
counts remain in the aggregate; conflict detection is investigation evidence,
not a merge veto or a claim that the workers are equivalent.

Timing-breach batches also carry at most 256 bounded duration samples. The
supervisor stores mergeable count/mean/variance/minimum/maximum summaries rather
than an unbounded raw sample list. When each of at least the configured minimum
number of observations is complete, it compares each worker's breach-duration
mean with the other workers using the standard error of the two summaries and
the same three-standard-deviation threshold. A
`timing_duration_seconds` conflict retains both sample counts and standard
deviations as evidence. Missing legacy samples and truncated samples are not
treated as comparable distributions, so incomplete coverage cannot become an
absence or equivalence claim.

Workers may also attach a bounded mapping of numeric resource samples, such as
`cpu_seconds` or `memory_bytes`, to an observation batch. Metric names, values,
metric count, and samples per metric are bounded and finite; the supervisor
retains only mergeable count/mean/variance/minimum/maximum summaries. A metric
is compared between workers only when both sides have enough non-truncated
samples, using the same three-standard-deviation evidence threshold. These
values are worker-supplied evidence: the current lightweight path does not
automatically collect host metrics, and a resource conflict does not veto a
merge, change policy, or authorize a repair.

## Current boundary

This first slice establishes durable ownership, batching, generation scope,
policy-transition rejection, and cross-process provenance. The
`AdaptiveAggregationPolicy` opt-in connects the adaptive controller to the
in-process batcher; its default is disabled for least-friction startup. When
enabled, workers retain the inexpensive local collection path but do not
promote from an exception or timing threshold themselves. After reconciliation,
the supervisor evaluates the application-wide event window and persists a
generation- and policy-bound Behavior transition request. Each contributing
worker can validate and apply that request locally, then acknowledge it; the
request is `PENDING`, `PARTIAL`, `APPLIED`, or `FAILED` based on those
acknowledgements. No LLM, batch field, aggregate counter, or transition request
creates authority, changes policy, accepts a Guard baseline, or activates
Repair.

Once all required Behavior requests are acknowledged, the supervisor can also
evaluate the application-wide behavioral evidence gate and record an
`ADAPTIVE_REPAIR_PROPOSAL`. This is a durable, proposal-only record containing
the evidence counts and observation-window duration. It cannot be acknowledged
as an applied transition and still requires the ordinary Repair policy,
validation, approval, and authority gates.

Transition listings can include a `context_status` of `CURRENT`,
`UNVERIFIED`, or a fail-closed stale-context reason such as `STALE_POLICY` or
`STALE_AUTHORITY_FINGERPRINT`. The supervisor validates the current target
generation, policy fingerprint, and authority context before accepting a
worker acknowledgement; if that context cannot be read or no longer matches,
the acknowledgement is rejected and no transition state is changed.

Worker submission loss and backpressure are policy controlled. The local
batcher defaults to `RETAIN`, which keeps a failed batch bounded for a later
flush; `DROP` explicitly discards that failed batch and records the dropped
count; and `REDUCE` retries once with event timestamps, duration samples, and
resource samples removed while preserving bounded counters. All three actions
are evidence handling only and cannot change application results, policy, or
authority. Incident callbacks, parallel stores, and transport-level throttling
remain future integrations.

The supervisor can also persist a delayed `ADAPTIVE_THRESHOLD_PROPOSAL` for a
bounded set of threshold fields. The proposal records the requested changes,
requester, reason, effective time, expiry, and full context binding. It is
listed as `PROPOSAL_ONLY` and becomes visibly stale when generation, policy, or
authority context changes. Recording or displaying it never applies a policy
change; an authorized application-owned authority workflow must perform any
later update. The authenticated `adaptive-threshold-apply` control operation
performs that workflow only after an approved proposal reaches its effective
time, the old context is still current, and aggregate worker provenance is
available. It acquires a target-scoped runtime lease bounded by the proposal
expiry, propagates the authority snapshot to the application, and rolls the
lease back if the application does not expose the changed policy context.
After that workflow applies a reviewed change, the supervisor records an
`ADAPTIVE_POLICY_TRANSITION` bound to the new policy and authority
fingerprints. Its required workers must acknowledge the post-change context
before the transition is `APPLIED`; recording the transition still does not
grant authority. An
authenticated operator can record one context-checked `APPROVE` or `REJECT`
review for the proposal. `APPROVE` means only that the proposal is eligible for
later staged policy review; it does not apply thresholds, reload workers, grant
authority, or replace the policy. Conflicting review reuse is rejected and a
stale or expired proposal cannot be reviewed.
Before acceptance, an authenticated operator can use
`adaptive-threshold-rollback` with an explicit confirmation and reason. This
releases the transition's target-scoped runtime lease when present and writes a
separate content-hashed rollback record while preserving the original
transition as immutable evidence. Rolled-back transitions are visible as
`ROLLED_BACK`, reject subsequent worker acknowledgements, and cannot be
re-applied. An `APPLIED` transition is accepted state; correcting it requires
a new incident and a new approval workflow.

Each applied threshold transition also creates immutable policy-lineage records
under `adaptive/policy-ledger/`. The initial record is `PENDING`; completion of
all required worker acknowledgements adds `APPLIED`, a failed acknowledgement
adds `FAILED`, and an explicit pre-acceptance rollback adds `ROLLED_BACK`.
Records bind the transition to the prior and resulting policy fingerprints and
stable UUID policy IDs, affected fields, target/aggregation scope, effective
and recorded timestamps, authority type, authority expiry, evidence references,
and worker acknowledgement counts. Native policy snapshot IDs can be supplied;
otherwise the UUID is deterministically derived from the policy fingerprint.
When a runtime artifact signer is configured, the transition record contains
its serialized `adaptive-policy-transition` signature and the canonical
transition content hash it covers. In hash-chained mode the record remains
explicitly `UNSIGNED`; this is integrity evidence, not a cryptographic
signature. The exported `verify_adaptive_policy_transition_signature()` helper
verifies signed records through the signing identity journal. These records are
append-only and read-only: they do
not replace the authority stack, reapply policy after restart, or allow an
adaptive actor to activate its own proposal.

Each apply, worker verification, pre-acceptance rollback, and persistent
acceptance decision also emits a critical `ADAPTIVE_POLICY_TRANSITION` record
to `caretaker_audit.log`. The record carries the transition identity, policy
lineage when available, lifecycle state, bounded worker/lease references, and
`authority_granted: false`; it is audit evidence and never acts as a policy or
authority input.

`adaptive-aggregation-status` and `adaptive-transition-list` include the bounded
policy-lineage projection. The projection is for operator history and analytics;
it does not turn a runtime lease into a permanent deployment policy.

When the effective adaptive policy explicitly enables
`aggregation.allow_persistent_acceptance`, an authenticated operator can use
`adaptive-threshold-accept` after all required workers have acknowledged an
`APPLIED` transition. The command requires the changed target, generation,
policy, and authority context to still be current and requires the runtime
authority to remain unexpired. It writes one immutable record under
`adaptive/policy-acceptance/`, including the operator identity, affected fields,
policy IDs/fingerprints, reason, authority expiry, and optional incident
reference. A configured runtime signer signs the canonical acceptance content
as an `adaptive-policy-acceptance` artifact.

Acceptance records are a durable operator/deployment handoff, not an authority
source. The operation does not renew the lease, mutate the active policy, grant
authority, or reactivate the accepted policy after restart. A deployment
workflow with its own authority must apply the accepted policy; until then the
record remains reviewable evidence. The default policy keeps persistent
acceptance disabled.

The supervisor exposes `adaptive-observation-submit`,
`adaptive-aggregation-status`,
`adaptive-aggregation-reconcile`, `adaptive-aggregation-ack`,
`adaptive-transition-list`, `adaptive-transition-ack`,
`adaptive-threshold-proposal`, `adaptive-threshold-review`,
`adaptive-threshold-apply`, `adaptive-threshold-accept`, and
`adaptive-threshold-rollback` through its
control socket. All threshold commands
derive the live context and the caller's local UID; they cannot accept
arbitrary context supplied by the caller. Its health cycle
reconciles enabled worker contexts and evaluates
thresholds automatically. The worker-side
`apply_supervisor_transition()` method requires exact target, generation, code,
monitoring, policy, and authority context before applying Behavior. Dynamic
console-managed thresholds, supervisor-owned Repair activation/evidence beyond
the current bounded gate, cross-host transport, and automatic worker process
orchestration remain future work. Each generated Behavior transition carries
the policy's bounded `transition_timeout_seconds` (60 seconds by default) and
an absolute `expires_at`. A completed transition remains `APPLIED`; an
incomplete transition becomes `EXPIRED` after its deadline, reports the stale
worker IDs, and rejects late acknowledgements. Caretaker does not automatically
replace stale workers or change policy; application-owned lifecycle handling
remains future work.

The Textual console's **Adaptive** tab provides a manually refreshed view of
aggregate provenance, active threshold policy context, and transition state.
It shows scoped target identity, generation, worker acknowledgement coverage,
deadlines, stale-worker counts, and the effective exception, timing, and
Repair-evidence thresholds that produced the current supervisor view. The
policy context is bounded and unavailable when the live runtime cannot be
queried. The console can draft a new bounded, proposal-only threshold change
with an explicit operator reason, target/scope, delay, expiry, and confirmation;
the runtime validates its fields and derives all context from the live worker
registration. Selecting an existing proposal loads its target, scope, and
changes as a starting point, but does not edit the immutable record. An
unreviewed threshold proposal can be selected and given an explicitly reasoned
operator approval or rejection; that action records only the advisory review
record. The tab does not expose transition-acknowledgement controls. It does
expose application of a selected approved proposal through the separately
gated control-plane operation; the console does not bypass its review, timing,
provenance, authority, or worker acknowledgement requirements.
The same table includes bounded immutable policy-lineage rows for pending,
applied, failed, and rolled-back transitions. Their detail view includes the
policy IDs, fingerprints, authority metadata, effective time, and affected
fields. Selecting a lineage row is read-only and cannot enable threshold
review, application, or rollback controls.
The authenticated review, application, and pre-acceptance rollback operations
also emit attributable `POLICY_REVIEWED`, `POLICY_APPLIED`, and
`POLICY_ROLLED_BACK` records to `caretaker_audit.log`; these audit records are
evidence only and do not grant authority.
