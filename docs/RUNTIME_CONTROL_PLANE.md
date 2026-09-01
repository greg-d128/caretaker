# Runtime control plane

The runtime control plane prevents Guard, Repair, Integrity, import hooks, and system hooks from acquiring direct circular dependencies.

## Principal contracts

```python
RuntimeSignal
RuntimeDecision
RuntimeAction
ActionLineage
RuntimePolicyEngine
RuntimeControlPlane
```

A signal describes evidence that may require a decision. A decision selects one or more typed actions. An action records what Caretaker attempted and preserves lineage back to the original signal.

## Signal domains

- `FAILURE` — exceptions, timeouts, invalid output, failed validation
- `BEHAVIOR` — behavioral deviations or candidate capability changes
- `INTEGRITY` — hash, signature, runtime fingerprint, or anti-rollback failures
- `IMPORT` — module route and load decisions
- `INTERNAL` — Caretaker's own failures

## Actions

Important action kinds include:

```text
RECORD
ALERT
ESCALATE_INSTRUMENTATION
OPEN_REPAIR_EPISODE
REJECT_REPAIR_CANDIDATE
ROLLBACK_REPAIR
ALLOW_IMPORT
DENY_IMPORT
SUBSTITUTE_MODULE
QUARANTINE_MODULE
RESTART_WITH_MODULE_ROUTE
TERMINATE_PROCESS
```

## Policy precedence

The default design assumes this precedence:

1. sealed integrity restrictions;
2. root/protected integrity failures;
3. explicit Guard deny or quarantine policy;
4. candidate validation hard gates;
5. repair and fallback policy;
6. statistical significance;
7. LLM advisory assessment.

An LLM recommendation cannot authorize unsigned sealed code, ignore a failed signature, or override an explicit deny policy.

## Action lineage

Bidirectional Guard–Repair integration can produce feedback loops. Every action therefore records:

- root signal ID;
- parent action ID;
- action depth;
- participating components;
- related repair episodes and deviations.

The control plane also deduplicates repeated signals and enforces a maximum action depth.
Recent signals, decisions, and actions are retained in bounded deques controlled
by `RuntimeInteractionPolicy.maximum_history_entries` (4096 by default). This
history is an inspection cache, not the durable audit record; owners should
persist consequential decisions through their existing evidence or audit
stores. Health and authority traffic therefore cannot exhaust memory through
unbounded control-plane history.

## Long-running jobs

Replay batches and non-interactive Incident Explorer assistance use the same
authenticated local control socket but are admitted to a bounded process-local
job registry. A submission returns a `job_id` immediately. Clients poll with
`{"command":"job-status","job_id":"..."}` and may request cooperative
cancellation with `{"command":"job-cancel","job_id":"..."}`.

The supervised application persists bounded job summaries in its local
`control-jobs.sqlite` store. Completed results and the latest operator-facing
progress mapping therefore remain visible after a supervisor restart. The
callable operation is never persisted or resumed: queued, running, and
cancel-requested records found during startup are marked `INTERRUPTED` with a
restart explanation. This preserves evidence without replaying application
work implicitly.

`RuntimeInteractionPolicy` bounds active jobs globally and per client, pending
jobs globally and per client, retained job records, result bytes, and execution
duration. Health, authority, and shutdown traffic continue to use the control
endpoint directly; long jobs do not create a second protocol. Saturated
admission is rejected explicitly. Results are bounded summaries and are never
treated as authority or as permission to modify an Incident Capsule. Runtime
shutdown marks queued and running work `INTERRUPTED`; it does not claim that
unfinished work succeeded.

Long-running handlers may call `RuntimeJobContext.report_progress()` with a
bounded JSON-compatible mapping. Progress is advisory status only, is included
in job transition records, and is subject to the configured result-byte limit.

The supervised logging policy also exposes `[logging.llm_usage]` with
`maximum_requests_per_minute = 6` and `maximum_concurrent_requests = 1` by
default. The request gate rejects excess work instead of accumulating a hidden
queue. This applies to advisory LLM calls initiated through the supervised
runtime; feature enablement remains separate. Guard, Repair, and direct library
provider instances have the same bounded defaults and can share an explicit
gate when they operate in one process.

## Custom policy engine

Applications may replace `DefaultRuntimePolicyEngine` with a custom implementation:

```python
class RuntimePolicyEngine(Protocol):
    def evaluate(
        self,
        signal: RuntimeSignal,
        context: Mapping[str, object],
    ) -> RuntimeDecision:
        ...
```

The policy engine should remain deterministic and fast. It should not perform database scans or call an LLM synchronously from an audit or import hook.

## Hook behavior

System and audit hooks perform only bounded capture, normalization, evidence recording, and immediate deterministic decisions. Long-running repair or LLM work is deferred to normal execution boundaries.

## Operator runtime registry

Repair and Guard engines register weak references with the process-local
`OperatorRuntimeRegistry`. This registry exists only for inspection and explicit
operator actions; it does not own engines and does not participate in Repair or
Guard policy decisions.

The registry exposes a compact status snapshot suitable for an operator status
line. It includes the current operational state, highest recent alert severity,
active incidents, targets currently in candidate validation, pending approvals,
and degraded Guard logging capabilities.


## Policy authority control

The supervisor, not the application process, owns the authoritative policy stack. The child runtime receives an immutable effective snapshot and reports its authority generation/fingerprint through `OperatorRuntimeRegistry.status()`. The supervisor compares that value with its own; a mismatch is a policy-tamper condition rather than a new valid policy generation.

The administrative socket provides declarative operations for authority status and narrowly scoped runtime leases. It does not accept Python or shell code. Temporary `repair.*` leases require an explicit target selector. Signed runtime leases are loaded from descriptors under the deployment policy area and are verified with the existing external GPG authority model. See `POLICY_AUTHORITY.md`.
