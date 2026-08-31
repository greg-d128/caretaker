# Caretaker audit event registry

This document is the per-event contract for the local `caretaker_audit.log`
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
| `AUDIT_DELIVERY_STATUS` | `IMPORTANT` | — | `{"sink_id": "local-file", "state": "ACTIVE", "external_delivery": false}` |
| `AUDIT_DATA_LOSS` | `CRITICAL` | — | `{"category": "ordinary_metrics", "count": 1, "reason": "sampling_policy"}` |
| `CONSOLE_INVOCATION_STARTED` | `CRITICAL` | — | `{"console_invocation_id": "console-uuid", "console_identity": {"algorithm": "ed25519", "encoding": "base64", "public_key_fingerprint": "sha256:..."}}` |
| `CONSOLE_INVOCATION_ENDED` | `IMPORTANT` | — | `{"console_invocation_id": "console-uuid", "reason": "operator_exit"}` |
| `POLICY_PROPOSED` | `CRITICAL` | `policy.policy_id`, `policy.fingerprint`, `outcome.state` | `{"state": "PROPOSED"}` |
| `POLICY_REVIEWED` | `CRITICAL` | — | `{"state": "APPROVED", "review_id": "review-uuid"}` |
| `POLICY_APPLIED` | `CRITICAL` | `policy.policy_id`, `policy.fingerprint`, `outcome.state` | `{"state": "APPLIED"}` |
| `POLICY_REJECTED` | `CRITICAL` | — | `{"state": "REJECTED", "reason": "stale_context"}` |
| `POLICY_ROLLED_BACK` | `CRITICAL` | — | `{"state": "ROLLED_BACK", "transition_id": "transition-uuid"}` |
| `POLICY_SUPERSEDED` | `IMPORTANT` | — | `{"state": "SUPERSEDED", "replacement_policy_id": "policy-new-uuid"}` |
| `AUTHORITY_SNAPSHOT_CHANGED` | `CRITICAL` | `scope.lease_id`, `outcome.state` | `{"state": "APPLIED", "lease_id": "lease-uuid"}` |
| `WORKER_AUTHORITY_ISSUED` | `CRITICAL` | — | `{"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"}` |
| `WORKER_AUTHORITY_REFRESHED` | `CRITICAL` | — | `{"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"}` |
| `WORKER_AUTHORITY_EXPIRED` | `CRITICAL` | — | `{"worker_id": "worker-uuid", "authority_packet_id": "packet-uuid"}` |
| `WORKER_FAILED` | `CRITICAL` | — | `{"transaction_state": "ROLLED_BACK", "failure_id": "failure-uuid"}` |
| `WORKER_REPLACEMENT_REQUESTED` | `CRITICAL` | — | `{"failed_worker_id": "worker-old", "replacement_request_id": "request-uuid"}` |
| `WORKER_REPLACED` | `CRITICAL` | — | `{"failed_worker_id": "worker-old", "replacement_worker_id": "worker-new"}` |
| `SUPERVISOR_STATE_CHANGED` | `CRITICAL` | — | `{"state": "CONTROL_PLANE_LOST", "reason": "heartbeat_timeout"}` |
| `INCIDENT_CAPTURED` | `IMPORTANT` | — | `{"incident_id": "incident-uuid", "capture_level": "STANDARD"}` |
| `VALIDATION_DECISION` | `IMPORTANT` | — | `{"state": "ELIGIBLE", "validation_id": "validation-uuid"}` |
| `RECOVERY_DECISION` | `CRITICAL` | — | `{"state": "PLANNED_ONLY", "action": "ROLLBACK_TO_DEPLOYED_CODE"}` |

In a supervised run, the application process may submit only a bounded
`VALIDATION_DECISION` through the supervisor control socket. The supervisor
checks that the Unix peer PID is the live application child, accepts only
allow-listed scalar scope, policy, outcome, and detail fields, and derives the
event actor from peer credentials. The submitted validation policy is retained
as reported evidence; the audit envelope's policy identifies the supervisor's
current audit policy. This path is output-only: it cannot submit arbitrary
event types, change policy, grant authority, or invoke a control operation.
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
