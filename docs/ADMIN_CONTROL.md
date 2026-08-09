# Local administrative control

## Authentication

The control interface uses a Unix-domain socket, filesystem permissions, and peer PID/UID/GID. The application account should not have administrative socket access unless the operator deliberately grants it.

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

### Log browsing and filtering

The **Logs** view orders records by their `occurred_at` timestamp, newest first,
regardless of segment or writer return order. The left pane is a compact event
list and the right pane shows the full JSON object for the selected record.
Press `r` to refresh the console; a separate refresh button is not required.

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

The Textual console includes an **Investigate** view. It builds a bounded logging
interrogation bundle for the selected target and recent time window and includes
recent Guard deviations when available.

With no model selected, Caretaker performs deterministic interrogation only. If
the operator explicitly supplies an Ollama model, the supervisor sends the
bounded evidence bundle to the loopback Ollama endpoint through
`OllamaRootCauseProvider`. Remote endpoints remain disallowed by default.

The resulting assessment is advisory evidence. It cannot approve a repair,
override candidate validation, or bypass Integrity policy.
