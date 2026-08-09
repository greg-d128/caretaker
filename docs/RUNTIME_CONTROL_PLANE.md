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
