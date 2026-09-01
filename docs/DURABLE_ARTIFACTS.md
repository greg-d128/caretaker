# Durable artifact contracts

This document defines the current application-scoped durable artifact families
and the limits of their compatibility. It is an implementation contract for
0.6.5, not a promise of cross-version or cross-host migration.

| Family | Schema | Read/migration rule | Retention class |
| --- | ---: | --- | --- |
| Repair SQLite store | 9 | The store rejects an unknown metadata version. Family-local migration is required before opening a newer or older store. | Operational lifecycle, incidents, rollout, recovery, and audit evidence |
| Guard evidence SQLite store | 1 | The store rejects an unknown metadata version. JSON payloads retain family details; required indexed fields remain fail-closed. | Raw evidence and derived Guard records; policy controls bounded raw retention |
| Incident Capsule and capsule artifacts | 1 / 1 | Loaders validate schema and integrity and reject unsupported or malformed records. | Incident-preserved evidence |
| Behavior snapshots and statistics | 2 / 2 | Snapshot verification validates schema, integrity, identity, and generation; invalid records are not accepted or deleted. | Bounded operational statistics; signed archives are preserved evidence |
| Regression fixtures | 1 | Fixtures are data-only and bounded; unsupported values require trusted codecs or named fixture references. | Reviewable regression evidence |
| Logging records, audit, and monitoring | 1 / 1 / 1 | Framing/registry readers validate the declared schema. Unknown audit types are retained as evidence, never interpreted as commands. | Policy-controlled logs; critical audit is preserved preferentially |
| Audit delivery envelopes | 1 (queue), 2 (authenticated) | Readers accept only supported versions and fail closed on malformed authentication material. | Delivery/replay evidence |
| Application transport envelopes | 1 | Canonical JSON, size, type, and digest checks are required; unsupported versions fail closed. | Disposable in-flight transport |
| Integrity manifests | 1 (manifest), 1–2 (root) | Supported versions are explicit in the integrity loaders; unknown versions fail closed. | Signed release and verification evidence |

## Field and unknown-data rules

Durable JSON payloads may retain unknown fields for inspection, but unknown
fields do not acquire behavior or authority. A loader may ignore an unknown
field only when all fields required for the family’s integrity and lifecycle
decision are present. Missing, malformed, or incompatible required fields are a
named incompatibility and must fail closed rather than being guessed.

Exact signed bytes, content hashes, and family-specific schemas remain stable
within their declared schema version. A migration must produce a new
content-addressed or signed record where applicable; it must not rewrite the
original evidence in place.

## Retention and deletion

Retention is policy-driven and family-specific. Incident capsules, signed audit
records, integrity manifests, and evidence referenced by an incident or
verification result are preservation candidates and must not be removed by a
generic cleanup operation. Raw routine events, derived summaries, transport
queues, and behavior snapshots may have shorter policy-defined retention, but
deletion must preserve tombstones or archive references where the family
requires them.

The current release provides family-local retention for logging segments,
attachments, system records, signing identity journals, and behavior snapshot
archives. Durable time-based Guard retention and segment-class-aware incident/
baseline retention remain deferred; their policy fields are rejected or treated
as reserved rather than silently applied.

## Store capability views

`RepairStore` remains the single physical InMemory/SQLite persistence seam. To
keep consumers from depending on unrelated record families, the public API
also provides `lifecycle_store_view()`, `evidence_store_view()`,
`worker_recovery_store_view()`, `integrity_store_view()`, and
`postmortem_store_view()`. These are narrow
typed projections over the same store; they do not create additional databases,
change the schema, or provide an authorization boundary. New consumers should
accept the narrowest capability they require. The observation manager uses the
evidence capability and internal post-mortem capture uses the post-mortem
capability. The engine remains the lifecycle coordinator and may use the root
compatibility seam; this is the intentional application-scope ownership
boundary, not an unmigrated leaf consumer.

Archive/compaction work must be an inspectable, resumable operation with a
dry-run projection, preservation exceptions, and reference validation. No
universal migration or deletion framework is implied by this contract.

`SQLiteRepairStore.retention_dry_run()` now provides the bounded read-only
projection for the Repair store. It reports ordinary records eligible for a
caller-supplied cutoff separately from incident-linked, signed, and protected
families, and reports when its result was truncated. It never deletes or
rewrites records. `SQLiteRepairStore.retention_archive()` consumes a complete
plan and copies its candidates to a canonical JSONL archive compressed with
gzip. The archive is created by atomic rename; an incomplete invocation leaves
an integrity-checked `.partial.jsonl` sidecar that can be resumed with the same
plan. `SQLiteRepairStore.retention_archive_status()` verifies a completed
archive and reports its plan fingerprint, record count, and families without
touching the source store. The archive rechecks each source row before copying
and never deletes source records. Both archive and verification operations can
emit the registered `REPAIR_RETENTION_ARCHIVE` audit event through the
application's output-only audit callback. The status operation also validates
an interrupted `.partial.jsonl` sidecar and reports its current record count so
operators can safely resume it. Family-owned compaction and resumable deletion
remain future work.
