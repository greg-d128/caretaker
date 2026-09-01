# Application worker lifecycle and comparison work

Caretaker's supervisor is a controller and verifier. It does not perform the
ordinary worker task and it does not gain host-level process-management
authority. The embedding application owns process creation, transport, and
shutdown.

## Authorized worker state

An application worker enters through a supervisor-issued
`RecoveryAuthorityPacket`. The packet binds the worker to its target,
generation, code hash, policy, authority context, capabilities, and expiry.
The worker registry verifies that packet before admission and preserves
probation and acceptance counters independently from packet authority.

## Comparison worker assignment

When the supervisor needs an independent check—for example, because a worker's
behavior differs from its peers—the supervisor may issue a
`ComparisonWorkerAssignment`. The assignment is bounded and content-hashed and
contains:

- a reconciliation scope and target/generation identity;
- the policy and authority fingerprints being checked;
- the existing worker packet identity and worker kind;
- bounded references to the evidence to review; and
- an expiry no later than the packet expiry.

The application may use the assignment to start or route work to another
authorized worker. Caretaker does not start a process from the assignment.
The worker must verify both assignment and packet before doing work.

The worker returns a `ComparisonWorkerResult` containing bounded JSON-shaped
evidence and a status of `COMPLETED`, `FAILED`, or `INCOMPLETE`. The supervisor
accepts it only when the worker ID, PID, process-start identity, worker kind,
packet, target context, assignment hash, and result hash all match. Results are
stored as evidence and can be inspected through the read-only worker recovery
status projection. They cannot:

- grant worker or Repair authority;
- change policy or acceptance counters;
- activate a candidate;
- select a recovery action; or
- replace the source evidence used for reconciliation.

The supervisor can compare a completed result's `behavior_signature` with a
bounded set of peer signatures. Each signature must provide the same finite
metric set and at least the configured sample count. Compatible distributions
are combined using weighted mean/variance calculations; a difference beyond
the configured three-standard-deviation threshold is retained as an outlier
conflict. Missing, malformed, or insufficient signatures produce
`INCOMPLETE_EVIDENCE` and are never counted as agreement.

The assignment/result/comparison contract is the current application-scoped
protocol slice. Combining multiple comparison reports with worker post-mortems,
cross-process transport, fleet coordination, and deployment-specific process
orchestration remain separate policy- and deployment-owned work.
