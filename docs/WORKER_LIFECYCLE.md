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

Authority expiry is enforced by the supervisor's control cycle as well as by
worker heartbeats. A silent packet-bearing worker is marked `UNAUTHORIZED` at
or after the packet expiry time, and the supervisor emits one
`WORKER_AUTHORITY_EXPIRED` audit event for that transition. Reconciliation is
idempotent and does not create a replacement or grant a new packet; deliberate
replacement still requires the existing policy and application-owned process
callback path.

## Authority packet transport

`serialize_recovery_authority_packet()` provides a bounded canonical JSON
envelope for an application-owned socket, shared-memory buffer, or queue. The
envelope carries the packet content hash and is limited to 64 KiB. The matching
`deserialize_recovery_authority_packet()` function validates the envelope,
packet schema, JSON data, timestamps, capabilities, size, and content hash.
It does not validate the packet against current runtime context and does not
grant authority.

The local supervisor control-socket path now provides
`submit_worker_authority_packet()` for register and refresh handoffs. The
corresponding supervisor handler accepts only explicitly allow-listed worker
kinds, derives the process ID from authenticated Unix peer credentials, and
requires the application to supply the current live context. A unique handoff
ID is consumed after successful admission and is retained for the supervisor
lifetime, so an accepted envelope cannot be replayed to create another worker.
Refresh additionally requires the registered worker ID and process-start ID.

The transport path still does not create an OS process, choose a deployment
transport, or grant authority by itself. The application owns process
creation and must wire the handler with authoritative current context; packet
verification and registry admission remain the gates that record a worker as
authorized. The bounded `ApplicationLocalQueueTransport` can carry the packet
envelope through an application-owned queue as canonical bytes, but queue
access and the reported sender PID are not authentication. The application
must bind receipt to the live worker context before admission. Cross-host
authentication, durable cross-restart replay state, and process lifecycle
orchestration remain future work.

`QueueWorkerAuthorityPacketTransport` and
`QueueWorkerReplacementRequestTransport` provide typed convenience wrappers
for the same queue envelope. They decode the existing packet/request codecs
and return transport provenance for the application to verify and admit. They
do not call the registry, start a process, consume a replacement request, or
turn queue access into worker authority.

The replacement handler provides the corresponding application-owned launch
boundary. `spawn_worker(request)` receives the immutable replacement request
and must return a positive process ID only after the application has started
the process. The new process must remain unable to perform ordinary worker
work until it has presented the nested packet through the configured transport
and been admitted. If admission fails after a process has started, the handler
calls the optional `stop_worker(pid)` callback and reports its result. A
missing or rejected cleanup callback is explicit failure evidence; it is never
treated as successful replacement. Caretaker does not terminate operating
system processes itself.

`ApplicationWorkerLifecycle` packages this initial-worker path with the
existing replacement handler. `start_authorized_worker()` verifies the full
packet and live context before asking the application to launch, then admits
the returned process through `WorkerRegistry.register_authorized()`. If a
configured acceptance policy marks the worker failed, it is cleaned up the
same way as any other unadmitted process; when no acceptance policy is
configured, the worker may remain `UNTRACKED` because packet authority and
acceptance tracking are separate concerns. `build_replacement_handler()`
uses the same supervisor gates and callback pair for failed-worker recovery.
This is an application-scoped coordination adapter, not a process manager:
deployment code still owns command construction, environment, transport
startup, waiting, and process termination.

Replacement workers use the existing `WorkerReplacementRequest` as a second
bounded local handoff. `serialize_worker_replacement_request()` includes the
failed-worker identity, worker kind, issuance time, reason, and nested
authority-packet envelope with a request content hash. The
`worker-replacement-packet` handler accepts only allow-listed kinds, binds the
new registration to the authenticated peer PID, and passes the request through
the existing failed-worker, exact-context, expiry, and acceptance gates. The
request ID is already single-use in the registry, so a successful replacement
handoff cannot be replayed. The handler returns the newly assigned worker and
process-start identities for subsequent worker IPC.

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

The supervisor can also reconcile multiple independently produced comparison
reports. It requires at least two distinct assignments and matching assignment
contexts for target, generation, code, policy, authority, worker kind, and
scope. It retains report and result references, conflict/outlier evidence, and
incomplete coverage without averaging already-aggregated metrics; shared
baselines must never be double-counted. The resulting
`ComparisonWorkerReconciliationReport` is durable, hash-verifiable, visible in
the read-only status projection, and cannot select recovery or grant authority.

The supervisor can join that report to a same-scope worker post-mortem
reconciliation. The join requires assignment contexts to bind the comparison
evidence to the post-mortem target, preserves all source IDs and packet hashes,
and classifies target mismatches as `NOT_COMPARABLE`. It does not merge the
statistical summaries or treat agreement as proof of safety or authority.

The assignment/result/comparison/reconciliation contract is the current
application-scoped protocol slice. Combining comparison reports with worker
post-mortems, cross-process transport, fleet coordination, and
deployment-specific process orchestration remain separate policy- and
deployment-owned work.
