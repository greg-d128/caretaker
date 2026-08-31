# Logging record and segment format

## Primary envelope

The encoded primary record is limited to 4096 bytes. It contains a fixed header and versioned TLV fields.

The fixed header identifies:

- magic value;
- format version;
- writer version;
- total record length;
- record kind and flags;
- UTC timestamp;
- process clock value;
- process-start identity;
- sequence number;
- record checksum.

Unknown TLV fields can be skipped using their type and length. Newer writers may therefore add fields without making the entire record unreadable to an older parser.

## Time and ordering

Every record contains UTC wall time and a process clock value. The clock value is not assumed to remain globally monotonic forever. Process-start identity, sequence, prior clock values, and UTC time allow readers to detect reset or wrap and calculate local deltas appropriately.

Cross-host ordering remains approximate unless an external time-quality source is supplied.

## Truncation

A crash can leave an incomplete final record. Readers recover every complete preceding record, stop at the incomplete frame, and report a warning. They do not treat the entire segment as corrupt.

## Segments

Only one writer owns an open segment. Closed segments receive:

- content hash;
- previous-segment hash;
- first and last global sequence;
- record count;
- optional compressed path;
- optional runtime signature reference.

SQLite stores offsets and selected metadata but is rebuildable.

## Attachments

Large bodies are stored outside the 4 KiB event stream. The event contains a compact typed reference. Attachment segments have independent hash chains, manifests, rotation, compression, retention, size limits, and probabilistic overload sampling. When attachment-manifest signing is enabled, the active attachment manifest is checkpointed and its hash is bound into the signed event manifest at every event-segment rotation, as well as at graceful shutdown.

Attachment overload now preserves all payloads by default. Sampling or dropping requires an explicit `AttachmentOverloadAction`; when selected, the primary event records the resulting storage decision. Critical categories can bypass sampling/drop policies.

## Caretaker audit stream

The local `caretaker_audit.log` implementation is a high-value, output-only decision stream. It is
separate from the detailed evidence stream, Incident Capsule attachments, and the
authenticated control socket. It contains compact facts about authority, policy,
worker lifecycle, incident, recovery, and audit-delivery decisions; it does not
accept commands and it should not contain raw evidence when a reference and hash are
sufficient.

The stream uses a canonical, bounded JSON-lines payload. Its local implementation
is intentionally small and does not replace the existing binary record and
segment framing for detailed evidence. Its typed payload has this common envelope:

| Field | Requirement |
| --- | --- |
| `schema_version`, `event_type`, `event_version` | Versioned schema and registry name; unknown future types are retained but never interpreted as commands. |
| `event_id`, `stream_sequence` | Globally unique event ID and monotonic sequence within the audit stream. |
| `occurred_at`, `monotonic_ns`, `process_start_id` | UTC time plus local ordering evidence; supervisor time is authoritative for control decisions. |
| `run_id`, `supervisor_id` | Runtime and supervisor provenance. |
| `actor` | `supervisor`, `worker`, `operator`, `deployment`, `adaptive`, or `system`, with an ID and public-key fingerprint where applicable. `adaptive` is a proposer, never an authority source by itself. |
| `scope` | Optional `target_id`, extended aggregation scope, `incident_id`, `transition_id`, rollout ID, and worker ID. |
| `policy` | Effective policy ID/fingerprint, authority generation/fingerprint, authority type, and affected canonical field paths when relevant. |
| `outcome` | Bounded state, reason, effective time, and references to durable evidence or validation results. |
| `integrity` | Previous-event hash, canonical-content hash, signing mode/status, signer fingerprint, and signature or signature reference. |
| `details` | Versioned, event-specific bounded fields. Large data belongs in a referenced attachment. |

Example:

```json
{
  "schema_version": 1,
  "event_type": "POLICY_APPLIED",
  "event_version": 1,
  "event_id": "2dc1f50b-5f66-4b8f-a8ca-1f8b5e4ab2d1",
  "stream_sequence": 42,
  "occurred_at": "2026-08-31T15:04:05.123Z",
  "monotonic_ns": 881234567890,
  "process_start_id": "run-start-uuid",
  "run_id": "run-uuid",
  "supervisor_id": "supervisor-uuid",
  "actor": {
    "type": "operator",
    "id": "console-invocation-uuid",
    "public_key_fingerprint": "sha256:..."
  },
  "scope": {
    "target_id": "billing.charge",
    "aggregation_scope": "billing-cluster-a",
    "transition_id": "transition-uuid"
  },
  "policy": {
    "prior_policy_id": "policy-old-uuid",
    "policy_id": "policy-new-uuid",
    "prior_fingerprint": "sha256:...",
    "fingerprint": "sha256:...",
    "authority_type": "operator",
    "authority_generation": 18,
    "fields_affected": ["repair.thresholds.timeout"]
  },
  "outcome": {
    "state": "APPLIED",
    "effective_at": "2026-08-31T15:04:05.123Z",
    "reason": "Reviewed adaptive proposal AP-17",
    "evidence_refs": ["incident:...", "proposal:...", "validation:..."]
  },
  "integrity": {
    "previous_event_hash": "sha256:...",
    "content_sha256": "sha256:...",
    "hash_chain": true,
    "signature_state": "EPHEMERAL_SIGNED",
    "signer_fingerprint": "sha256:...",
    "artifact_signature": {
      "artifact_kind": "caretaker-audit-event",
      "content_hash": "sha256:...",
      "context": {
        "event_id": "2dc1f50b-5f66-4b8f-a8ca-1f8b5e4ab2d1",
        "event_type": "POLICY_APPLIED",
        "stream_sequence": 42
      },
      "signature": "base64:..."
    }
  },
  "details": {"worker_acknowledgements": {"accepted": 3, "required": 3}}
}
```

The initial event registry is finite and reviewable: `AUDIT_STREAM_STARTED`,
`AUDIT_STREAM_ROTATED`, `AUDIT_DELIVERY_STATUS`, `AUDIT_DATA_LOSS`,
`CONSOLE_INVOCATION_STARTED`, `CONSOLE_INVOCATION_ENDED`,
`POLICY_PROPOSED`, `POLICY_REVIEWED`, `POLICY_APPLIED`, `POLICY_REJECTED`,
`POLICY_ROLLED_BACK`, `POLICY_SUPERSEDED`, `AUTHORITY_SNAPSHOT_CHANGED`,
`WORKER_AUTHORITY_ISSUED`, `WORKER_AUTHORITY_REFRESHED`,
`WORKER_AUTHORITY_EXPIRED`, `WORKER_FAILED`, `WORKER_REPLACEMENT_REQUESTED`,
`WORKER_REPLACED`, `SUPERVISOR_STATE_CHANGED`, `INCIDENT_CAPTURED`,
`VALIDATION_DECISION`, and `RECOVERY_DECISION`. Each supported type must define
required fields, redaction rules, priority, and a valid example fixture before
implementation is considered complete. Registry additions require a schema
version or a backward-compatible event version; they must not silently reuse a
different event's meaning.

During a supervised run, validation decisions are submitted from the
application process over the supervisor control socket as bounded evidence.
Only `VALIDATION_DECISION` is accepted on that path. The supervisor binds the
submission to the live application peer PID, derives the worker actor from
Unix peer credentials, validates allow-listed scalar fields, and writes the
event to the supervisor-owned audit stream. Worker-reported validation policy
and authority fingerprints remain explicitly reported evidence; they do not
authorize the candidate or alter the supervisor's effective policy.

The executable registry and per-event examples are maintained in
[`AUDIT_EVENT_REGISTRY.md`](AUDIT_EVENT_REGISTRY.md). The local writer applies
the registered minimum priority and required envelope paths. Unknown future
uppercase names remain forward-compatible evidence without registered
semantics or command meaning.

The signed artifact also repeats and signs the event's `run_id` and
`process_start_id`; readers must require those values to match the enclosing
event before accepting the signature. Audit integrity is policy controlled.
`logging.audit.hash_chain` controls the
local event chain and `logging.audit.sign_events` controls per-event runtime
artifact signatures. Signing may use runtime-ephemeral keys or an independently
managed external signer through `logging.signing.mode`; signed mode requires a
compatible signer and fails closed if one is unavailable. When hash chaining is
enabled, each event commits to the previous event and each segment commits to
the previous segment using the existing segment mechanism.
Signing and chaining prove continuity of the retained local stream; immediate
external shipping is required for stronger protection against an attacker who can
rewrite local storage. External delivery is a replica, not an authority source.

The local writer must durably queue critical decision events before the associated
effect is reported as complete. Policy changes, authority changes, worker
authority events, supervisor state changes, and audit-chain failures are highest
priority. Incident and recovery events follow. Ordinary metrics may be sampled or
dropped only under explicit policy, with the loss recorded in `AUDIT_DATA_LOSS` or
`AUDIT_DELIVERY_STATUS`. If critical audit data cannot be retained, the configured
failure policy decides whether Caretaker degrades, refuses the transition, raises
an incident, or stops the application; it must never silently claim success.

The local audit file is `caretaker_audit.log` below the configured logging
directory. Its enablement, filename, hash-chain choice, and event-size limit are
startup/run-bound for the current process. A policy reload records the proposed
change under the current stream first and requires a new run for those audit
settings to take effect.

The external sink is write-only from Caretaker's perspective. Incoming records,
alerts, or suggested actions are untrusted input and cannot be routed back into
the control plane. Sink authentication, confidentiality, replay handling,
redaction, rate limits, and retention remain separate policy requirements.

### Offline verification

An exported stream can be checked without opening it for append:

```python
from caretaker.logging import verify_audit_stream

report = verify_audit_stream(
    "caretaker_audit.log",
    require_signatures=True,
    identity_public_keys={fingerprint: public_key_bytes},
)
assert report["valid"] is True
```

The verifier never truncates or repairs a file. It reports an incomplete final
line as invalid, checks sequence continuity, canonical content hashes, the
configured hash-chain mode, and (when requested and keyed) every artifact
signature. Missing public keys are reported as `UNAVAILABLE` for optional
verification and fail a `require_signatures=True` report. The returned report
is evidence only and is not an authority or command interface.
