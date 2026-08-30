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

Each accepted aggregate is scoped by target, generation, code identity,
monitoring fingerprint, policy fingerprint, and authority context. The durable
record merges counters, retains a bounded recent event-time window, and records
bounded per-worker sequence and observation provenance. State is content-hash
protected and checkpointed before the corresponding batch is archived. A batch
ID is retained in the aggregate for bounded deduplication, and an archived
resubmission is idempotent.

Reconciliation also writes a bounded per-batch acknowledgement containing the
batch ID, batch hash, result (`ACCEPTED`, `DUPLICATE`, or `REJECTED`), and
aggregate key/rejection reason where applicable. This is delivery provenance
only: an acknowledgement cannot authorize a transition or change policy.

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

The supervisor exposes `adaptive-aggregation-status`,
`adaptive-aggregation-reconcile`, `adaptive-aggregation-ack`,
`adaptive-transition-list`, and `adaptive-transition-ack` through its control
socket. Its health cycle reconciles enabled worker contexts and evaluates
thresholds automatically. The worker-side
`apply_supervisor_transition()` method requires exact target, generation, code,
monitoring, policy, and authority context before applying Behavior. Dynamic
console-managed thresholds, supervisor-owned repair-evidence accumulation,
remote transport, and automatic worker process orchestration remain future
work.
