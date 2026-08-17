# Local administrative control

## Authentication

The control interface uses a Unix-domain socket, filesystem permissions, and peer PID/UID/GID. The application account should not have administrative socket access unless the operator deliberately grants it.

Peer credentials do not provide authorization independent of the operating-system account. When the application and operator share a UID, current control-socket checks cannot reliably distinguish application code from the operator. Use a separately controlled account and filesystem permissions where that distinction matters; Caretaker does not currently provide a separate credential verifier or application-layer authentication mechanism.

No network listener, password database, arbitrary Python, shell command, or unrestricted path execution is provided.

The configured `run/control.sock` and `run/runtime.sock` names are logical paths. On systems with short `AF_UNIX` pathname limits, Caretaker transparently relocates only an overlong socket file to a private per-user runtime directory; the configured evidence/data directory is unchanged. Caretaker's control clients resolve the same mapping automatically.

## Declarative commands

The initial protocol supports status, health, effective-policy inspection, and mode lease acquisition/release. Logging CLI commands also provide offline record, baseline, and interrogation operations.

Every high-impact action should include a reason and is recorded with peer credentials and policy generations.

## Runtime escalation

An administrator can acquire Repair mode for a problem, request proposal or approval-required authority, review validation and testing evidence, deploy an approved candidate, and release the mode. Lease-specific logging overlays are reverted afterward.

## Failure and strict mode

Policy determines whether inability to preserve required evidence continues degraded, disables a component, refuses a mode transition, or terminates the application. There is no silent claim that Guard or Repair is fully operational when a required capability is unavailable.

## Live application runtime inspection

When an application is launched with `caretaker-run`, the supervisor creates a
second same-UID Unix socket for the child application's live Caretaker runtime.
RepairEngine and GuardEngine instances register themselves with a process-local
operator registry. The supervisor proxies declarative `runtime-*` requests to
that child socket.

This makes the operator interface able to inspect live application state rather
than only supervisor/logging state. Exposed information includes:

- registered Repair/Guard targets and active FunctionSlot versions;
- active Repair incidents and candidate validation work;
- repairs awaiting operator approval;
- Guard events, deviations, runtime inspections, decisions, and summaries;
- accepted baselines and configured Repair policies;
- optional Guard LLM assessments when an advisory provider is configured.

Approval/rejection and baseline acceptance remain typed declarative operations.
The runtime socket does not accept arbitrary Python, shell commands, or source
text from the operator console.

## Textual operator console

Textual is a required Caretaker dependency. The primary interactive operator
interface is installed as:

```bash
caretaker-console --data-directory ./caretaker-data/my.application
```

The console attaches to the authenticated `caretaker-run` control socket and
shows a continuously refreshed status line with:

- current runtime state;
- highest Guard alert severity observed in the last five minutes;
- active Repair incident count;
- functions currently undergoing candidate validation;
- repairs awaiting operator approval;
- target count;
- supervisor worker-health issues and degraded Guard capabilities.

Tabs provide target/FunctionSlot inspection, Guard evidence and baseline
operations, Repair event/approval controls, persisted logs, and Guard LLM
assistance when the application configured an advisory assessment provider.

The **Guard** tab discovers Guard-enabled runtime targets and presents their
operational status, most recent inspection/deviation time, recent violation
count, and escalation count. Selecting a row supplies the target context for
summary, event, deviation, inspection, baseline, and advisory actions; operators
do not need to copy an internal target identifier from another screen.

### Log browsing and filtering

The **Logs** view orders records by their `occurred_at` timestamp, newest first,
regardless of segment or writer return order. The left pane is a compact event
list and the right pane shows the full JSON object for the selected record.
Press `r` to refresh the console; a separate refresh button is not required.

The console opens on **Attention**, an operator queue that combines active
incidents, Guard deviations, failed or waiting Repair work, authority-policy
violations, and degraded runtime capabilities. Selecting an item explains why
it needs attention and provides direct navigation to its owning view or a
correlated investigation.

The header reports when the console last refreshed, whether runtime information
is live or cached, whether Logs and Policy came from the supervisor or persisted
fallback files, and the bounded record limit. A shared context banner retains
the selected target, incident, and call while the operator moves between views;
**Clear context** returns to the unscoped console.

For a first response, use this operator workflow:

1. Start in **Attention** and select the highest-priority item.
2. Use its direct action to open the owning tab; the shared target, incident,
   and call context follows automatically.
3. Review the plain-language summary, then follow the related Guard, Behavior,
   Repair, Policy, Log, and Investigation links needed to establish evidence.
4. Treat Behavior comparisons and model assessments as evidence, not proof.
   Check coverage, generation, integrity, source, time range, and omitted data.
5. Before changing state, verify the exact selected object and acknowledge the
   action. Destructive Behavior operations, Repair approval/rejection, policy
   application, signed-lease application, and lease release all fail closed
   without their corresponding confirmation. Repair rejection and every policy
   application also require an explicit operator reason.
6. Refresh to verify the resulting state, then use **Clear context** before
   starting an unrelated investigation.

Disabled actions indicate missing selection, evidence, live-runtime access, or
confirmation; they are not hidden capabilities or undocumented parameters.

The **Overview** view sorts targets needing attention ahead of ordinary targets
and explains its operator-facing health states. Selecting a target provides a
plain-language summary plus direct navigation to Guard evidence, Behavior
history, correlated Logs, or an Investigation; raw FunctionSlot state and the
effective policy remain available as technical detail.

The **Guard** view distinguishes `NO EVIDENCE`, `LEARNING`, `HEALTHY`, and
`DEVIATION` instead of reusing Repair lifecycle states. Findings are sorted
first and summarized in plain language. Baseline acceptance remains disabled
until an aggregate summary exists and the operator explicitly confirms that the
available summary, events, deviations, and inspections were reviewed.

The **Behavior** list shows one analytical row for each subject/generation pair.
It prefers the newest snapshot with proven cumulative epoch coverage; a newer
partial artifact cannot mask that evidence. The newest partial is used only when
the generation has no cumulative snapshot. Within the bounded 500-row response,
the default view retains the three newest generations for every subject when they
exist. **Show older generations**
reveals additional returned history. Grouping and breadth-first allocation occur
before the response limit, so frequent
materialization of a hot function cannot hide a rare generation. Rows are sorted
by subject and then newest generation first. A generation ID is a deterministic
SHA-256 fingerprint over subject, code identity, monitoring configuration, and
statistics schema; it is not an artifact signature. Code or monitoring changes
start a new generation. Snapshot integrity/signature state is reported separately.

Each row reports generation-level first and last seen times, cumulative collection
coverage where snapshots are known to be disjoint, and a bounded histogram of call
counts in up to the latest 24 observed UTC hours (oldest to newest). The bars are
relative within that row. Newly captured snapshots preserve fixed-hour activity
buckets and actual observation-window boundaries; older snapshots made before that
metadata existed show a labeled histogram of up to twelve saved windows and fall
back to saved time for first/last seen.

For a registered function, one authoritative accumulator owns each generation.
Automatic materialization and **Close function epoch** atomically close that
accumulator and install an empty successor under the same lock. Completed calls
receive monotonically increasing generation-scoped sample numbers, and every
closed epoch records its ID, ordinal, and inclusive sample range. Consumers such
as Behavior, Guard, baselines, and investigations can reuse the immutable epoch;
they do not need overlapping captures of the same calls.

Ordinary coverage is displayed as `current/target` when the closed epoch ranges
are contiguous, non-overlapping, and consistent with their call counts. The
exceptional label `partial current/target` is retained for legacy, module,
external, active-view, or malformed captures whose exclusive ownership cannot be
proven. `partial` does not mean the artifact is damaged; ordinary registered-
function capture should display only the count.
In either case, the target measures evidence volume rather than correctness or
workload representativeness.

Zero-call generations are retained because they may contain event-only
forensic evidence such as imports, filesystem access, network activity,
subprocesses, or dynamic code. They cannot support call-duration, outcome-rate,
or call-frequency analysis, so the Behavior list hides them by default. Select
**Show zero-call evidence** when investigating event-only evidence; the list title
reports how many such generations are hidden.

The **Behavior** view treats the selected analytical snapshot as comparison operand B.
**Use B as A** marks an operator baseline; after running more workload and
refreshing, **A ↔ latest** compares that baseline with the newest snapshot for
the same subject automatically. Snapshots are marked `A` and `LATEST`, grouped
by their subject/generation identity, and can be filtered by subject, generation,
evidence state, or integrity state. The table reports collection coverage and
artifact integrity, while snapshot detail reports environment/workload labels,
sampling strata, resource coverage, and monitoring provenance. Saving current
observations does not execute the target function.

The **Repair** view lists waiting decisions first and supports target, state,
episode, and description filtering. A pending approval is rendered as a decision
summary containing the candidate identity, expected active version, artifact
hash, authority generation, and reason approval is required. The console also
states which assurance evidence is absent from the current approval protocol;
operators must not interpret approval as proof of missing validation lineage.
Approval remains disabled until the candidate and evidence gaps are explicitly
acknowledged. The same acknowledgement gates both approval and rejection, and a
rejection additionally requires a reason. Selected episodes link directly to triggering Logs, Guard evidence,
and Investigation.

The **Policy** view separates inspection from mutation. Common Repair authority
changes can be loaded as presets; advanced paths remain available, but every
unsigned lease must be previewed before it can be applied. The preview states
the exact path/value, target scope, expiration, reason, and whether an explicit
constraint override may violate a higher-authority guarantee. Any edited input
invalidates the preview, and the operator must acknowledge the scope and
guarantee impact before **Apply previewed lease** becomes available.
Signed descriptors require an explicit reason and separate scope acknowledgement.
Releasing a selected runtime lease also requires confirmation, reducing accidental
state changes while navigating the policy table.

The filter field accepts ordinary case-insensitive text and compact field
selectors. Multiple terms are combined with AND semantics. Examples:

```text
level:warn+
channel:guard target:lab.divide
logger:caretaker.repair timeout
message:validation level:error
```

`level:warn` selects only warning-level records while `level:warn+` includes
warning, error, and critical records. Supported selectors are `level`,
`channel`, `target`, `logger`, and `message`; unqualified text searches the full
JSON record.

Selecting a log enables contextual navigation. **Investigate correlated** applies
the available target/incident/call identifiers, shows the matching evidence queue,
and opens Investigate. This is identifier correlation, not semantic similarity.
**Open related tab** routes Guard records to the selected
Guard target, Repair records to Repair, integrity/audit records to Policy, and
targeted application records to Behavior when that context is meaningful.

### Structured control-plane failure evidence

The child runtime control boundary is part of Caretaker's diagnostic surface.
If a runtime handler raises, the socket response contains a structured `error`
object rather than only a formatted exception string. The record identifies a
diagnostic ID, failure domain and kind, component, operation and stage, exception
type/module/message, target and Repair correlation IDs when present, authority
generation/fingerprint/assurance, peer PID/UID/GID, and whether durable
diagnostic persistence succeeded.

Unexpected Caretaker exceptions are also emitted at error severity on the
`CARETAKER_INTERNAL` channel when the logging path remains available. Invalid
control requests and authority-policy rejections are classified separately so a
policy decision is not reported as a Caretaker implementation defect.

Set `CARETAKER_DIAGNOSTIC_DEBUG=1` only during controlled diagnosis. It adds a
bounded traceback and request-key inventory to the control response and stores
that supplemental detail as DEBUG-priority attachment evidence when attachment
persistence is available. The underlying failure event and its core diagnostic
fields are emitted independently of this setting. The request body itself is not
copied into diagnostic detail.

The Repair console queries recent events and pending approvals independently.
If event-history retrieval fails, an actionable pending approval remains visible
as long as the approval query succeeds. The failed query appears as a
non-actionable `ERROR` row whose JSON retains the structured control diagnostic.

If diagnostic logging itself fails, Caretaker does not recursively send another
logging event. The control response reports `diagnostic_persisted=false` and a
bounded `diagnostic_persistence_error`, and the bootstrap path makes a best-effort
JSON write to standard error.

### Incident investigation and LLM assistance

The Textual console includes an **Investigate** view. It lists recent warnings
and security-channel records as selectable investigation candidates, rather
than requiring an operator to know a target ID in advance. It builds a bounded
logging interrogation bundle for the selected target, call, or incident and
recent time window, and includes recent Guard deviations when available.

With no model selected, Caretaker performs deterministic interrogation only. If
the operator explicitly supplies an Ollama model, the supervisor sends the
bounded evidence bundle to the loopback Ollama endpoint through
`OllamaRootCauseProvider`. Remote endpoints remain disallowed by default.

The resulting assessment is advisory evidence. It cannot approve a repair,
override candidate validation, or bypass Integrity policy.

The Investigation scope is shown before execution and exposes target, incident,
call, time window, and analysis provider. Candidate rows explain why they were
selected. Results identify their evidence hash, omitted-record count, provider,
and advisory limitation before technical assessment detail.

The Logs view explicitly reports live-supervisor versus persisted-fallback
source, loaded/maximum record counts, ordering, and refresh behavior. Its
**Investigate correlated** action is identifier-based correlation—not semantic
similarity—and selected records render message and target/incident/call context
before raw technical JSON.
