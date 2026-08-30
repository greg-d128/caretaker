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

Reconciliation also writes a bounded per-batch acknowledgement containing the
batch ID, batch hash, result (`ACCEPTED`, `DUPLICATE`, or `REJECTED`), and
aggregate key/rejection reason where applicable. This is delivery provenance
only: an acknowledgement cannot authorize a transition or change policy.

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
change; an authorized policy workflow must perform any later update.

The supervisor exposes `adaptive-aggregation-status`,
`adaptive-aggregation-reconcile`, `adaptive-aggregation-ack`,
`adaptive-transition-list`, and `adaptive-transition-ack` through its control
socket. Its health cycle reconciles enabled worker contexts and evaluates
thresholds automatically. The worker-side
`apply_supervisor_transition()` method requires exact target, generation, code,
monitoring, policy, and authority context before applying Behavior. Dynamic
console-managed thresholds, supervisor-owned Repair activation/evidence beyond
the current bounded gate, remote transport, and automatic worker process
orchestration remain future work. Each generated Behavior transition carries
the policy's bounded `transition_timeout_seconds` (60 seconds by default) and
an absolute `expires_at`. A completed transition remains `APPLIED`; an
incomplete transition becomes `EXPIRED` after its deadline, reports the stale
worker IDs, and rejects late acknowledgements. Caretaker does not automatically
replace stale workers or change policy; application-owned lifecycle handling
remains future work.

The Textual console's **Adaptive** tab provides a manually refreshed,
read-only view of aggregate provenance, active threshold policy context, and
transition state. It shows scoped target identity, generation, worker
acknowledgement coverage, deadlines, stale-worker counts, and the effective
exception, timing, and Repair-evidence thresholds that produced the current
supervisor view. The policy context is bounded and unavailable when the live
runtime cannot be queried. The tab has no threshold-editing,
transition-acknowledgement, or application action control; threshold changes
remain a future policy-transition capability.
