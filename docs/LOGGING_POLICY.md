# Logging policy

## Authority

The software administrator owns the effective deployment policy. Application code may emit records and recommend defaults but cannot accept baselines, approve overrides, select arbitrary policy files, or disable operator-required channels.

The policy snapshot records its source path, canonical hash, owner, permissions, and loaded time. The hash is attribution evidence, not a Caretaker authorization signature.

## Reconciliation

Application mode follows the base policy. Higher modes declare required capabilities. Missing capabilities produce explicit `LoggingPolicyOverride` records or prevent activation according to `PolicyConflictAction`.

```text
APPLY_REQUIRED_OVERRIDES
REFUSE_HIGHER_MODE
FALL_BACK_TO_APPLICATION_LOGGING
REQUIRE_INTERACTIVE_APPROVAL
```

## Mode leases

Temporary escalation is represented by `ModeLease`. A lease records scope, requester, reason, expiration, work identity, policy generation, and required overrides. Releasing it re-runs reconciliation against the current base policy rather than restoring a stale policy snapshot.

## Hot reload

The complete TOML document is parsed before replacement. On failure, the previous policy remains active. Safe runtime settings are applied immediately. Directory, codec, index layout, queue capacity, and runtime signing identity are startup- or run-bound and are reported as requiring a new supervised run.

## Security warnings

Caretaker warns when the application account owns the policy, the file is group/world writable, its directory is unsafe, or the path is a symbolic link. These warnings rely on operating-system permissions, not OpenPGP.

## Repair changes during evaluation

Every repair episode captures the effective logging-policy generation. A change before activation makes the pending repair `STALE_POLICY`; the candidate must be reviewed and revalidated before deployment.

## Worker health and restart

The supervised runtime maintains heartbeats for its writer, event server, control server, and optional system collector. In 0.6.1 the system collector is automatically restartable; writer and socket failures are detected and surfaced as degraded or failed health because safe reconnection and open-segment recovery must take precedence over blind restart.

Restart exhaustion may continue degraded, disable the affected component, or stop the supervised application. Caretaker workers do not elect a replacement supervisor; they remain subordinate to the application-scoped supervisor.

When a worker reports bounded diagnostic context with its heartbeat, the
supervisor carries that context into the failed-worker envelope only when
`CARETAKER_DIAGNOSTIC_DEBUG=1` is explicitly enabled. This is intended for
controlled diagnosis and may include the last milestone, partial queue, and
policy-state snapshot supplied by the worker. Standard envelopes retain
identity, queue counters, active work IDs, authority context, and the failure
fingerprint without copying the diagnostic context. Context is size- and
depth-bounded, treated as evidence, and never authorizes a replacement or
other recovery action. A worker can continue supplying context with
`WorkerRegistry.heartbeat(..., diagnostic_context={...})` or preserve/replace
it when marked failed. The supervised runtime also stores the bounded envelope
in `<policy.directory>/repair.sqlite` before applying its configured worker
failure action. This record is available for restart reconciliation but does
not itself authorize a replacement or claim complete post-mortem coverage.


## Storage-unavailable default

Ordinary application logging now fails by stopping Caretaker logging rather than terminating the application. Deployments that require fail-closed audit semantics can explicitly set `storage_emergency.unavailable_action = STOP_APPLICATION`.


## Storage paths

Logging and system-collection output directories are normalized to absolute paths when policies are constructed. Relative paths loaded from a TOML policy are resolved relative to the policy file rather than the process working directory. This prevents a working-directory change from silently redirecting evidence storage.

## Caretaker audit stream

The local high-value audit stream is configured independently under
`[logging.audit]`:

```toml
[logging.audit]
enabled = true
file_name = "caretaker_audit.log"
hash_chain = true
flush_critical = true
maximum_event_bytes = 4096
```

The current implementation writes the output-only local stream below the main
logging directory and emits startup, policy, and authority-snapshot events.
Audit settings are run-bound; a reload records the attempted change but requires
a new run to change the stream configuration. External delivery and per-event
signatures remain future capabilities. See
[`LOGGING_RECORD_FORMAT.md`](LOGGING_RECORD_FORMAT.md) for the proposed envelope
and event registry.

## Incident communication drafts

Communication drafting is controlled by `[logging.communications]`. Each
audience is an explicit named profile with an allowed section list, bounded
text/item limits, and a review requirement. For example:

```toml
[logging.communications]
enabled = true
maximum_draft_bytes = 131072

[[logging.communications.audiences]]
profile_id = "public-v1"
display_name = "Public status readers"
allowed_sections = [
  "identity", "confirmed_observations", "impact", "scope",
  "mitigation", "next_update", "ownership", "unknowns", "provenance",
]
maximum_text_characters = 2000
maximum_items = 16
require_review = true
```

The generator filters by this allowlist before rendering, applies the bounded
data/redaction path, preserves capsule and policy fingerprints, and marks
unrecorded fields as unknown. Drafts are reviewable exports only;
`delivery_authorized` is always false and no external adapter is configured by
this policy.

## Persistent regression fixtures

Successful pure or idempotent repair retries continue to create executable
regression cases only in the process-local corpus. Persistent copies are
opt-in because they retain bounded representations of call arguments and
expected output:

```toml
[logging.regression]
enabled = true
maximum_cases_per_target = 100
maximum_fixture_bytes = 131072
maximum_depth = 6
maximum_collection_items = 32
maximum_text_characters = 2048
replay_enabled = false
replay_minimum_isolation = "VM"
replay_require_source_match = true
maximum_source_bytes = 262144
```

The resulting JSON records are inspection evidence, not replay authority. They
are integrity checked, redacted, resource bounded, and explicitly marked
`DATA_ONLY_NOT_EXECUTABLE`. Replay is separately authorized and disabled by
default. The rootless Podman backend can execute only `JSON_EXACT` fixtures in a
container; it does not provide a process-level fallback. VM replay and richer
type-preserving rehydration remain future work.
When replay is enabled, `replay_require_source_match = true` restricts a
fixture to the exact source hash recorded when it was captured. Operators may
set it to false for an explicitly configured cross-version comparison; the
request still carries both the historical and subject source hashes.
