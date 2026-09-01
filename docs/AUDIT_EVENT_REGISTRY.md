# Caretaker audit event registry

This document is the per-event contract for the `caretaker_audit.log`
stream. Every registered event has a stable name, a minimum evidence priority,
required envelope paths, and a bounded example. The examples show the
event-specific fields only; all events also carry the common envelope defined
in [`LOGGING_RECORD_FORMAT.md`](LOGGING_RECORD_FORMAT.md).

The writer applies the minimum priority and required-path checks for registered
events. An unknown uppercase event name may still be retained for forward
compatibility, but it has no registered event guarantees and is never treated
as a command. Event-specific values are evidence, not authority.

The audit policy retains `IMPORTANT` and `CRITICAL` events by default. Lower
priorities may be sampled with explicit per-priority rates. A sampled event is
not assigned a stream sequence; the writer emits a subsequent critical
`AUDIT_DATA_LOSS` record with the suppressed priority counts before the next
retained event (and during flush/close). `CRITICAL` is always preserved and
cannot be sampled or dropped by policy. This keeps loss visible without
creating a control channel or weakening the hash chain of retained records.

An embedding application may provide an output-only `AuditDeliverySink`. The
writer sends the exact redacted, newline-terminated JSON record after local
persistence, and reports delivery as `ACTIVE`, `DEGRADED`, or `LOCAL_ONLY`.
`logging.audit.external_delivery_required=true` makes a missing or failed sink
fail closed after preserving the local record. The adapter has no read or
command interface; transport authentication, remote retention, and replay
protection remain external responsibilities. When
`logging.audit.external_delivery_require_ack=true`, the sink must return an
acknowledgement mapping with `acknowledged: true` and `record_sha256` equal to
the SHA-256 digest of the exact record bytes it received. A missing,
malformed, or mismatched acknowledgement is treated as a failed delivery and
the locally persisted record remains in the retry queue. The record digest is
the sink-side idempotency key; this basic contract does not itself provide
transport authentication or replay protection.

For an application that has a shared secret with its external receiver,
`AuthenticatedAuditDeliverySink` wraps an output-only transport with the
optional `serialize_authenticated_audit_record()` contract. It sends a bounded
JSON envelope containing the exact record bytes, SHA-256 digest, deterministic
delivery ID (the same digest), sender ID, an explicit key ID, and an
HMAC-SHA256 signature. Schema-1 envelopes without a key ID remain verifiable
for migration compatibility; new envelopes use schema 2. The receiver can
validate them with `verify_authenticated_audit_record()` and should retain
delivery IDs so exact retries are idempotent. Its response must be created
with `create_authenticated_audit_acknowledgement()`; the adapter rejects
acknowledgements whose signature, key ID, delivery ID, or record digest does
not match. This is an authenticated transport primitive, not a command
channel, and it does not replace external key management, receiver retention,
or independent security review.

`AuthenticatedAuditKeyring` provides an optional in-memory key lifecycle for
deployments that need rotation or revocation. The deployment supplies named
keys, selects one active key for new records, and may retain older keys for
verification during a rotation window. Revoking an old key prevents further
verification and acknowledgement with that key; an active key must be rotated
before it can be revoked. Key material is never persisted by Caretaker, and
keyring state does not grant policy or authority. Deployments remain
responsible for provisioning, protecting, persisting, and auditing key state.

`AuthenticatedAuditReplayStore` is a bounded SQLite reference receiver for
this protocol. It stores sender ID, delivery ID, record digest, and receipt
time—not the audit payload—and survives receiver restart. It returns a
positive signed acknowledgement for a new or exact duplicate delivery and a
negative signed acknowledgement when capacity is exhausted or the delivery
identity conflicts. It does not delete old identities automatically, because
deletion would reopen a replay window.

Authenticated envelope example (the record body is base64 encoded):

```json
{
  "algorithm": "HMAC-SHA256",
  "delivery_id": "record-sha256",
  "record_base64": "eyJldmVudF90eXBlIjoi...",
  "record_sha256": "record-sha256",
  "schema_version": 2,
  "sender_id": "runtime-1",
  "key_id": "audit-2026-01",
  "signature": "hmac-sha256-hex"
}
```
Failed deliveries are retained in a bounded local store-and-forward queue and
retried in order during writer startup, flush, and the next retained event.
`external_delivery_max_pending_records` and
`external_delivery_max_pending_bytes` bound that queue; exhaustion raises an
explicit error and never removes the local audit record.

When an output-only sink changes between `ACTIVE` and `DEGRADED`, the writer
records an `AUDIT_DELIVERY_STATUS` transition in the local hash chain. A
degraded transition is placed directly into the retry queue after local
persistence; it does not retry the already-failed sink recursively. When the
queue drains and delivery becomes active again, the recovery transition is
delivered as the next status record. If the bounded retry queue is full, the
status record remains in the local stream and the queue-full failure remains
visible through the delivery projection. These status records describe
delivery evidence only and never create a command or authority channel.

All event types share these redaction rules:

- never include credentials, private keys, bearer tokens, or authentication
  material;
- place raw evidence in a separately governed attachment and include only its
  bounded reference and content hash;
- apply the active masking policy before serialization; and
- bound identifiers, reasons, field paths, and diagnostic text.

| Event type | Minimum priority | Required paths | Example event-specific fields |
| --- | --- | --- | --- |
| `AUDIT_STREAM_STARTED` | `CRITICAL` | `policy.policy_id`, `policy.fingerprint`, `details.hash_chain` | `{"hash_chain": true}` |
| `AUDIT_STREAM_ROTATED` | `IMPORTANT` | — | `{"segment_id": "segment-42", "content_sha256": "sha256:..."}` |
| `AUDIT_DELIVERY_STATUS` | `IMPORTANT` | — | `{"sink_id": "local-file", "state": "ACTIVE", "external_delivery": false, "acknowledgement_required": false}` |
| `AUDIT_DELIVERY_KEY_LIFECYCLE` | `CRITICAL` | `scope.key_id`, `outcome.state` | `{"key_id": "audit-2026-01", "state": "KEY_REVOKED", "authority_granted": false}` |
| `AUDIT_DATA_LOSS` | `CRITICAL` | — | `{"category": "ordinary_metrics", "count": 1, "reason": "sampling_policy"}` |
| `CONSOLE_INVOCATION_STARTED` | `CRITICAL` | — | `{"console_invocation_id": "console-uuid", "console_identity": {"algorithm": "ed25519", "encoding": "base64", "public_key_fingerprint": "sha256:..."}}` |
| `CONSOLE_INVOCATION_ENDED` | `IMPORTANT` | — | `{"console_invocation_id": "console-uuid", "reason": "operator_exit"}` |
| `POLICY_PROPOSED` | `CRITICAL` | `policy.policy_id`, `policy.fingerprint`, `outcome.state` | `{"state": "PROPOSED"}` |
| `POLICY_REVIEWED` | `CRITICAL` | — | `{"state": "APPROVED", "review_id": "review-uuid"}` |
| `POLICY_APPLIED` | `CRITICAL` | `policy.policy_id`, `policy.fingerprint`, `outcome.state` | `{"state": "APPLIED"}` |
| `POLICY_ACCEPTED` | `CRITICAL` | `policy.policy_id`, `policy.fingerprint`, `outcome.state` | `{"state": "ACCEPTED", "policy_mutated": false}` |
| `POLICY_REJECTED` | `CRITICAL` | — | `{"state": "REJECTED", "reason": "stale_context"}` |
| `POLICY_ROLLED_BACK` | `CRITICAL` | — | `{"state": "ROLLED_BACK", "transition_id": "transition-uuid"}` |
| `ADAPTIVE_POLICY_TRANSITION` | `CRITICAL` | `scope.transition_id`, `outcome.state` | `{"state": "PENDING", "transition_id": "transition-uuid", "policy_applied": true, "authority_granted": false}` |
| `POLICY_SUPERSEDED` | `IMPORTANT` | — | `{"state": "SUPERSEDED", "replacement_policy_id": "policy-new-uuid"}` |
| `AUTHORITY_SNAPSHOT_CHANGED` | `CRITICAL` | `scope.lease_id`, `outcome.state` | `{"state": "APPLIED", "lease_id": "lease-uuid"}` |
| `WORKER_AUTHORITY_ISSUED` | `CRITICAL` | — | `{"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"}` |
| `WORKER_AUTHORITY_REFRESHED` | `CRITICAL` | — | `{"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"}` |
| `WORKER_AUTHORITY_EXPIRED` | `CRITICAL` | — | `{"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"}` |
| `WORKER_FAILED` | `CRITICAL` | — | `{"transaction_state": "ROLLED_BACK", "failure_id": "failure-uuid"}` |
| `WORKER_POSTMORTEM_RECONCILED` | `CRITICAL` | `scope.reconciliation_scope`, `outcome.state` | `{"state": "COMBINED", "unique_packet_count": 2, "conflict": false, "authority_granted": false}` |
| `WORKER_REPLACEMENT_REQUESTED` | `CRITICAL` | — | `{"failed_worker_id": "worker-old", "replacement_request_id": "request-uuid"}` |
| `WORKER_REPLACED` | `CRITICAL` | — | `{"failed_worker_id": "worker-old", "replacement_worker_id": "worker-new"}` |
| `WORKER_COMPARISON_ASSIGNMENT` | `CRITICAL` | — | `{"assignment_id": "assignment-uuid", "authority_packet_id": "packet-uuid", "state": "ISSUED", "authority_granted": false}` |
| `WORKER_COMPARISON_RESULT` | `CRITICAL` | — | `{"assignment_id": "assignment-uuid", "result_id": "result-uuid", "state": "ACCEPTED", "authority_granted": false}` |
| `WORKER_COMPARISON_RECONCILED` | `CRITICAL` | — | `{"comparison_id": "comparison-uuid", "state": "COMBINED", "outlier_count": 0, "authority_granted": false}` |
| `SUPERVISOR_STATE_CHANGED` | `CRITICAL` | — | `{"state": "CONTROL_PLANE_LOST", "reason": "heartbeat_timeout"}` |
| `INCIDENT_CAPTURED` | `IMPORTANT` | — | `{"incident_id": "incident-uuid", "capture_level": "STANDARD"}` |
| `INCIDENT_REPLAY_OUTCOME` | `IMPORTANT` | `scope.replay_scope`, `outcome.state` | `{"scope": "all", "state": "PARTIAL", "fixture_count": 4, "completed_count": 3, "capsule_modified": false, "authority_granted": false}` |
| `INCIDENT_COMMUNICATION_DRAFTED` | `IMPORTANT` | `scope.communication_id`, `outcome.state` | `{"communication_id": "communication-uuid", "state": "GENERATED", "delivery_authorized": false}` |
| `INCIDENT_COMMUNICATION_REVIEWED` | `CRITICAL` | `scope.communication_id`, `outcome.state` | `{"communication_id": "communication-uuid", "state": "APPROVED", "delivery_authorized": false}` |
| `ADAPTIVE_AGGREGATION_RECONCILED` | `IMPORTANT` | `scope.aggregation_scope`, `outcome.state` | `{"scope": "application", "state": "RECONCILED", "merged": 3, "rejected": 0, "authority_granted": false}` |
| `ADAPTIVE_REPAIR_PROPOSAL` | `CRITICAL` | `scope.aggregation_scope`, `outcome.state` | `{"scope": "application", "state": "PROPOSAL_ONLY", "proposal_count": 1, "authority_granted": false}` |
| `ADAPTIVE_AGGREGATION_BACKPRESSURE` | `CRITICAL` | `scope.target_id`, `outcome.state` | `{"target_id": "demo.target", "state": "INCIDENT_RECORDED", "action": "INCIDENT", "pending_records": 4, "authority_granted": false}` |
| `ADAPTIVE_BATCH_REVALIDATED` | `IMPORTANT` | `scope.batch_id`, `outcome.state` | `{"batch_id": "batch-uuid", "state": "VALIDATED", "aggregate_modified": false, "authority_granted": false}` |
| `ADAPTIVE_POLICY_INSTALLATION` | `CRITICAL` | `scope.acceptance_id`, `outcome.state` | `{"acceptance_id": "acceptance-uuid", "installation_id": "installation-uuid", "state": "INSTALLED", "policy_mutated": false, "authority_granted": false}` |
| `BEHAVIOR_COLLECTION_OUTCOME` | `IMPORTANT` | `scope.scope`, `scope.subject`, `outcome.state` | `{"scope": "function", "subject": "demo.target", "state": "CAPTURED", "observed_calls": 50, "authority_granted": false}` |
| `VALIDATION_DECISION` | `IMPORTANT` | — | `{"state": "ELIGIBLE", "validation_id": "validation-uuid"}` |
| `RECOVERY_DECISION` | `CRITICAL` | — | `{"state": "PLANNED_ONLY", "action": "ROLLBACK_TO_DEPLOYED_CODE"}` |
| `REPAIR_ROLLOUT_TRANSITION` | `CRITICAL` | `scope.rollout_id`, `scope.transition_id`, `outcome.state` | `{"rollout_id": "rollout-uuid", "transition_id": "transition-uuid", "state": "validated", "action": "advance"}` |
| `SHADOW_EXECUTION_DECISION` | `IMPORTANT` | — | `{"state": "COMPLETED", "candidate_authoritative": false, "candidate_succeeded": true, "equivalent": true, "isolation_verified": true}` |
| `REPAIR_ROLLOUT_ROUTING_DECISION` | `IMPORTANT` | `scope.rollout_id`, `scope.routing_scope`, `outcome.state` | `{"state": "SELECTED", "stage": "canary", "strategy": "canary", "candidate_selected": true, "candidate_authoritative": true}` |
| `REPAIR_ROLLOUT_EXECUTION_OUTCOME` | `IMPORTANT` | `scope.rollout_id`, `scope.routing_scope`, `outcome.state` | `{"state": "COMPLETED", "implementation": "candidate", "candidate_executed": true, "candidate_authoritative": true}` |
| `REPAIR_CANDIDATE_OBSERVATION` | `IMPORTANT` | `scope.target_id`, `scope.candidate_id`, `outcome.state` | `{"state": "ACCEPTANCE_OBSERVED", "succeeded": true, "candidate_state": "INITIALLY_VALIDATED", "mode": "canary"}` |

In a supervised run, the application process may submit only a bounded
`VALIDATION_DECISION` through the supervisor control socket. The supervisor
checks that the Unix peer PID is the live application child, accepts only
allow-listed scalar scope, policy, outcome, and detail fields, and derives the
event actor from peer credentials. The submitted validation policy is retained
as reported evidence; the audit envelope's policy identifies the supervisor's
current audit policy. This path is output-only: it cannot submit arbitrary
event types, change policy, grant authority, or invoke a control operation.
Supervisor-mediated behavior captures likewise produce a bounded
`BEHAVIOR_COLLECTION_OUTCOME` record after the application returns its
collection projection. The supervisor derives the operator identity from the
authenticated console request and records only request metadata, generation
identifiers, snapshot references, counts, duration, and outcome; snapshot
contents remain in the behavior evidence store. A failed, cancelled, deferred, or unavailable
collection is recorded as evidence and does not change policy or authority.
Adaptive backpressure may use the same supervised output-only path through
`audit-adaptive-backpressure`. Its bounded payload is accepted only from the
live application PID; the supervisor derives the worker actor, replaces the
policy envelope with current supervisor context, preserves worker policy
values as reported evidence, and forces `CRITICAL` priority. The handler
rejects unknown or nested fields and authority-granting claims before the
record is emitted.
In an unsupervised local runtime, the operator registry uses the same bounded
projection with a `caretaker` actor; it never attempts to use the supervised
control-socket path.
Console clients likewise register a UUID-scoped invocation start and end; the
supervisor binds the session to the console's Unix peer PID and records the OS
UID/GID. When the signing extra is available, the console keeps a fresh
Ed25519 private key in memory for the session and publishes only its public key
and fingerprint. The public identity is recorded in the audit event and the
supervisor's `security/console-identities.sqlite` journal. An invocation record
is attribution evidence only and does not grant authority.

The registry is descriptive and fail-closed for the fields it declares. It
does not verify operator signatures, authorize policy changes, or provide an
external witness. Those are separate policy-controlled capabilities.
