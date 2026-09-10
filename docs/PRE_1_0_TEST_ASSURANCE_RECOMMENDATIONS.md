# Pre-1.0 Test-Assurance Recommendations

**Status:** architectural and test-quality guidance
**Scope:** Caretaker implementation repository
**Timing:** close before 1.0; not an instruction to complete all work before the current 0.6.5 pre-release validation

## Purpose

The Caretaker test suite is the canonical implementation-level test suite. It
should establish that the implementation preserves its local invariants, but it
must not be presented as independent release validation. Independent artifact,
contract, and adversarial assurance belongs to `caretaker-validation` and
`caretaker-crucible`.

The pre-1.0 objective is to make Caretaker's own tests precise enough that a
green result cannot be obtained by an unrelated failure, a partial state change,
or an implementation shortcut.

## Recommendations for Caretaker

### 1. Add an entrypoint-level supervisor assurance path

Retain constructor and module-ownership tests, but add a bounded test through
the real `caretaker-run` startup path. It should prove:

- the configured policy is loaded and composed with the intended RepairPolicy;
- rollout and recovery settings are not silently replaced by defaults;
- worker registration and authority handoff occur in the intended order;
- startup failure leaves no child process, socket, or durable state behind;
- restart, exhaustion, and cleanup produce the documented terminal states;
- rejected control operations are correlated with durable evidence.

This closes the gap between `ApplicationRuntimeSupervisor` unit tests and the
actual process entrypoint.

### 2. Define one lifecycle assertion pattern

For each worker, repair, rollout, and durable-job state machine, tests should
record:

```text
initial state -> input/event -> admitted state -> side effect
             -> validation result -> terminal state -> persisted projection
```

Every rejection case should assert both the exact failure class and unchanged
authority, filesystem, process, and durable state. Every recovery case should
assert cleanup and idempotence.

### 3. Strengthen negative-path oracles

Replace broad assertions such as “not accepted” with exact assertions for:

- exception or protocol error type;
- validation stage;
- target, generation, incident, and digest identity;
- no handler dispatch or external side effect;
- unchanged state on rejection;
- audit/evidence fields and correlation identifiers;
- cleanup after partial admission.

### 4. Separate architectural tests from behavioral proof

Keep module ownership, wrapper identity, public export, and compatibility tests,
but label them as architectural wiring tests. Pair each with at least one
behavioral test at the boundary being claimed. A class being owned by the right
module does not prove that its lifecycle or authority behavior is correct.

### 5. Establish independent test oracles inside the implementation suite

For security-critical serialization, identity, and integrity tests, do not use
the same canonicalization or digest helper for both the subject and the oracle.
Recompute expected values independently in the test or use fixed, reviewed
vectors. This does not replace Validator independence; it prevents a local
implementation mistake from being mirrored by its own tests.

### 6. Make isolation claims explicit

Tests that mock Podman, Docker, Multipass, or subprocess discovery should be
named and documented as command/policy contract tests. They must not imply that
the host enforced the requested memory, PID, namespace, privilege, or network
boundary. Add separate integration seams for observable enforcement where the
product contract requires it, and record unavailable enforcement as an
environmental limitation.

### 7. Add a test-to-invariant map

Maintain a small repository-owned map for critical Caretaker invariants:

```text
invariant -> implementation owner -> unit tests -> entrypoint tests
          -> expected rejection -> cleanup/recovery test -> external handoff
```

At minimum cover authority non-escalation, failed-validation fencing,
monotonic terminal states, bounded retries, path confinement, provenance
binding, durable schema rejection, advisory-only provider output, and
evidence-only audit behavior.

### 8. Test packaging-facing smoke behavior without owning release proof

Add a minimal package smoke layer that verifies public imports, entry points,
embedded schemas, and built-package resource access. Keep artifact identity,
signature, and independent source/package parity as Validator responsibilities.

### 9. Keep current scope explicit

Do not use these recommendations to expand Caretaker into Host or
Infrastructure Caretaker. The purpose is to make the application-scoped
architecture and its existing guarantees easier to prove before 1.0.

## 1.0 completion criteria for this repository

Before 1.0, Caretaker should be able to show:

- every critical invariant has a precise implementation test and a lifecycle or
  entrypoint test where applicable;
- rejection tests assert exact failure and no unintended mutation;
- recovery tests assert cleanup, bounded retry, terminality, and idempotence;
- source-level tests do not claim artifact, host-enforcement, or independent
  validation properties;
- test names and documentation distinguish wiring, behavior, and security
  invariants;
- the critical-invariant map has no unowned or testless rows.

These are architectural readiness criteria, not a requirement to complete every
future feature before 1.0.
