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

## Current boundary

This first slice establishes durable ownership, batching, generation scope,
policy-transition rejection, and cross-process provenance. The
`AdaptiveAggregationPolicy` opt-in connects the adaptive controller to the
in-process batcher; its default is disabled for least-friction startup. It is
evidence aggregation only. The existing adaptive controller still owns live
promotion transitions until a subsequent slice adds supervisor-authorized
transition requests and worker acknowledgements. No LLM, batch field, or
aggregate counter creates authority, changes policy, accepts a Guard baseline,
or activates Repair.

The supervisor now exposes `adaptive-aggregation-status` and
`adaptive-aggregation-reconcile` through its control socket, and its health
cycle reconciles enabled worker contexts automatically. The next implementation
slice must move threshold evaluation and promotion state to the supervisor
without double-counting the existing process-local lifecycle, then add explicit
transition requests and worker acknowledgements.
