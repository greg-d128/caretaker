# Incident Capsules

Caretaker's initial Incident Capsule implementation stores a bounded,
data-only record of an application Incident. Capsules are written by supervised
runs under the logging policy's `[logging.capsules]` section and are kept below
the run data directory in `incident-capsules/`.

## Current contract

Each capsule revision is an immutable JSON envelope containing:

- the incident and run identifiers;
- the incident state permitted by the configured capture level;
- policy and authority fingerprints/generation;
- references to bounded side artifacts; and
- a communication-history list.

The content hash seals every revision. Adding a side artifact or communication
creates a new revision and retains the previous revision. The current runtime
signer may additionally sign the capsule using the existing domain-separated
runtime artifact-signing mechanism.

Captured values are reduced to JSON-compatible safe representations. Collection
sizes, nesting, text, capsule bytes, artifact count, and communication count are
bounded by policy. Sensitive field names and credential-like text are redacted;
unknown objects are represented by type and a bounded representation. Reading a
capsule does not deserialize or execute captured application objects.

`MINIMAL` is the default level and records incident identity, trigger, target,
failure, and policy/authority references. `STANDARD` includes the already
captured call, state-difference, and log sections. Higher levels retain the
remaining bounded incident metadata. A higher capsule level does not request
additional runtime capture or expand Caretaker authority.

## Operator view artifacts

When the console has an incident selected, **Save view to capsule** captures the
current tab as a redacted, bounded `operator-view` side artifact. It records the
tab, selected target/call context, capture time, and the console's rendered
report. The capsule contains a reference and content hash; the artifact contains
the report text. If no runtime-created capsule is available, the supervisor
creates a placeholder capsule containing the incident context and references to
matching persisted log records.

The **Incident Explorer** lists capsule revisions and displays their verified
envelopes. Selecting a capsule exposes its side-artifact references; selecting
an artifact loads and verifies its content and its reference from the capsule.
Invalid hash or revision-chain data is displayed as invalid evidence rather than
being presented as a valid capsule.

For a selected incident, the Explorer also shows a bounded timeline of matching
persisted log records. Each record is labeled as persisted-log evidence and
includes its record identifier and derived content hash. This timeline is a
correlated evidence window, not an extension of the capsule seal; absence from
the window does not prove that an event did not occur.

This action is evidence collection only. It cannot approve Repair, satisfy
validation, change policy, close an incident, or broaden authority. The local
peer identity is recorded as evidence and is not treated as independent human
authentication.

## Communication history

Communication delivery is not implemented. The capsule schema nevertheless
reserves immutable `CommunicationRecord` entries for future drafts, approvals,
exports, deliveries, failures, corrections, and retractions. Records contain
channel/audience/status and content hashes or references rather than granting a
delivery adapter authority.

The future communication projection must use the capsule's canonical incident
state and preserve provenance, uncertainty, redaction, freshness, and policy
bindings.

## Advisory LLM assistance

The Explorer can send an explicit question and local Ollama model name to the
advisory Incident Capsule assistant. Assistance receives one bounded capsule
context at a time, plus its correlated timeline and side artifacts. The result
contains provider/model, prompt-version, evidence, and response hashes and is
shown as untrusted advisory output. It is not written to the capsule, cannot
create a revision, and cannot approve Repair, satisfy validation, or change
policy.

The non-interactive `caretaker-capsule-explorer` command supports `--scope
all`, `--scope incident`, and `--scope selected`. An all-scope query is
submitted independently for each historical capsule, so one invalid capsule or
LLM failure does not turn the remaining results into a single unsupported
aggregate conclusion. When a supervisor is available, the command includes the
bounded persisted timeline; direct offline mode analyzes capsule data without
claiming that absent log records did not occur.

## Remaining work

Incident Capsules do not yet provide isolated replay, policy-specific capture
levels for every application state source, or automatic communication drafting
and delivery. Those remain future work and must be implemented with isolated
replay, explicit authority, and adversarial tests.
