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

The Explorer also renders bounded read-only summaries for standard incident
facts and communication-history records alongside the raw envelope. The
communication summary shows status, channel, audience, and content hash; it
does not render a message body as if it were delivered. Missing sections and
invalid capsules remain explicitly unavailable.

The Explorer also reports availability for bounded evidence sections including
function/call state, call arguments, failure and captured variables, thread and
process state, source identity, state differences, capsule logs, repair and
validation metadata, and system state. Each section is labeled `CAPTURED`,
`EMPTY`, `MISSING`, `REDACTED`, or `TRUNCATED`; the labels describe the stored
evidence and never imply that an absent section was observed to be absent.

For a selected incident, the Explorer also shows a bounded timeline of matching
persisted log records. Each record is labeled as persisted-log evidence and
includes its record identifier and derived content hash. This timeline is a
correlated evidence window, not an extension of the capsule seal; absence from
the window does not prove that an event did not occur.

This action is evidence collection only. It cannot approve Repair, satisfy
validation, change policy, close an incident, or broaden authority. The local
peer identity is recorded as evidence and is not treated as independent human
authentication.

## Policy-governed communication drafts

The logging policy's `[logging.communications]` section defines named audience
profiles and their section allowlists, text/item limits, and review requirement.
The built-in `operators-v1`, `engineers-v1`, `leadership-v1`, and `security-v1`
profiles are local defaults; deployments may replace them explicitly in policy.

`incident-communication-draft` projects one verified capsule into a bounded,
data-only draft. It distinguishes confirmed observations, supported
inferences, hypotheses, recorded operational fields, and unknowns. Each draft
includes a deterministic communication ID, source capsule revision/content
hash, policy fingerprints, field provenance, redaction, and truncation state.
Required fields that are absent remain explicitly `UNKNOWN`; the generator does
not invent impact, mitigation, ownership, recovery, or ETA.

Draft generation records only draft metadata and its content hash in the
capsule's immutable `CommunicationRecord` history. Repeating the same draft is
idempotent. `--no-record` can be used for a purely review-only export. Records
contain channel/audience/status and hashes rather than granting a delivery
adapter authority.

The console's **Create review draft** action and the non-interactive
`caretaker-incident-draft` command produce JSON suitable for local review or a
mode-0600 new file:

```bash
caretaker-incident-draft \
  --data-directory ./caretaker-data \
  --incident-id INCIDENT_UUID \
  --audience-profile operators-v1 \
  --output incident-draft.json
```

External delivery, automatic triggers, correction/retraction workflows, and
ticket/chat/email/status-page adapters are not implemented. Draft output
always reports `delivery_authorized: false`.

## Communication review records

An operator may record an explicit `approved` or `rejected` review for a
recorded draft with `incident-communication-review` or
`caretaker-incident-review`. A reason, reviewer identity evidence, draft ID,
and source capsule revision are retained as a new immutable communication
record. Review is idempotent and later decisions cannot rewrite an existing
review record. Approval is only a local review result: it never authorizes
external delivery, Repair, policy changes, validation, or incident closure.

Future delivery and audience workflow must continue to use the capsule's
canonical incident state and preserve provenance, uncertainty, redaction,
freshness, and policy bindings.

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

The Incident Explorer can also request isolated replay of an incident-linked
persistent regression fixture with `caretaker-capsule-replay`. The default
`--scope selected` mode verifies the selected capsule revision and requires the
fixture's recorded incident identity to match it before dispatch. The
non-interactive `--scope incident` and `--scope all` modes submit a bounded
batch through the supervisor and return an independent result for every
fixture. An invalid fixture, missing capsule, or failed replay is reported for
that fixture without aborting the rest of the batch. Replay requires the
regression and replay policy opt-ins, matching source identity by default, and
a configured backend meeting the policy's minimum isolation. The result is
returned as separate evidence and explicitly reports that the capsule was not
modified; replay never creates a capsule revision or changes Repair state.

Batch replay still requires the operator to provide the subject source and
entrypoint. Historical fixtures whose recorded source hash does not match that
source are rejected by the same policy check as selected replay; the batch
reports that rejection per fixture rather than treating it as a successful
historical comparison.

## Remaining work

Incident Capsules do not yet provide policy-specific capture levels for every
application state source, LLM-assisted language tailoring, or communication
delivery. VM replay with guest attestation and richer type-preserving
rehydration remain future work. Existing replay is deliberately limited to
bounded `JSON_EXACT` fixtures and an explicitly configured isolated backend.
