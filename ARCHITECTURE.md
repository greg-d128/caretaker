# Caretaker architecture

## Application-scoped runtime

Caretaker 0.6.0a1 contains four cooperating top-level subsystems over a shared evidence and runtime-control foundation:

```text
                              Application process tree
                                      │
                         lightweight in-process emitters
                                      │ local IPC
                                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Caretaker application supervisor                  │
│                                                                     │
│  Logging ── Evidence ── Runtime control plane ── Work registry      │
│     ▲              ▲                ▲                    ▲           │
│     │              │                │                    │           │
│   Guard ───────────┘              Repair ────────────────┘           │
│     ▲                               ▲                                │
│     └──────────── Integrity ────────┘                                │
│                                                                     │
│  optional system collector · attachment store · local control socket│
└─────────────────────────────────────────────────────────────────────┘
```

Caretaker is scoped to one application or service. It runs with the application account, follows the application process tree, and shuts down when the application terminates. It may collect host-level records when configured, but does not become a general host-management daemon.

## Dependency and authority rules

- Logging is the lowest-dependency subsystem and must operate without Guard, Repair, LLM, GPG, or module-routing imports.
- Guard and Repair communicate through shared evidence, facades, normalized signals, decisions, and actions rather than calling one another's internals.
- Integrity restrictions have precedence over Guard, Repair, statistical, and LLM recommendations.
- Operator policy is unsigned deployment configuration. Signed Caretaker code defines how the policy is parsed and reconciled.
- Caretaker-owned code is never eligible for generated self-repair.
- LLM results are advisory except where standing automatic Repair authority has been explicitly enabled and all deterministic gates pass.

## Adaptive repair lifecycle

Caretaker separates **lifecycle stage** from **instrumentation intensity**. The
operator-facing repaired-function lifecycle is:

```text
LIGHTWEIGHT
    ↓ problem threshold
BEHAVIOR                 pre-repair evidence gathering
    ↓ evidence sufficient
REPAIR                   candidate generation/activation
    ↓ candidate activated
BEHAVIOR                 post-repair candidate observation
    ↓ probation criteria satisfied
VALIDATION               short-term accepted; continued validation
    ↓ long-term criteria satisfied
LONG_TERM_ACCEPTANCE
```

`FunctionSlot` is authoritative after candidate activation. Adaptive instrumentation
mirrors the slot's candidate state rather than maintaining a second repair-acceptance
state machine. `ACTIVE_PROBATION`/`DEGRADED` map to post-repair BEHAVIOR,
`INITIALLY_VALIDATED` maps to VALIDATION, and `LONG_TERM_ACCEPTED` maps to
LONG_TERM_ACCEPTANCE.

Observation intensity is orthogonal. For example, policy may return a long-term
accepted target to LIGHTWEIGHT observation without changing its lifecycle history or
accepted candidate identity. Repair candidate observation and adaptive demotion share
one `AcceptanceCriteria` definition for success counts, duration, failure budgets, and
failure rate; lifecycle-specific actions remain separate.

## Behavior generations and restart reconstruction

Guard keeps an updateable statistical accumulator separate from immutable trust decisions. A behavior generation is keyed by target identity, code hash, monitoring-configuration fingerprint, and statistics schema version. Runtime transitions between LIGHTWEIGHT and BEHAVIOR are recorded as sampling strata inside the generation; changing the configured monitoring semantics seals the old generation.

```text
behavior samples
      ↓
active statistical snapshot          mutable/checkpointed
      ↓ seal/materialize
sealed behavior snapshot             immutable + hash + runtime signature
      ↓ accept
accepted Guard baseline              immutable reference
```

Numeric distributions maintain exact online count/min/max/mean/variance plus a bounded reservoir used to derive p10/p50/p90/p95/p99. Categorical resources retain bounded frequency information and explicitly report incomplete coverage when truncated.

On restart, Guard computes the current code and monitoring fingerprints, loads the exact accepted-baseline reference, verifies the sealed snapshot and signing identity chain, and hydrates `BaselineManager` directly. It never promotes a merely observed active accumulator into an accepted baseline because the process restarted.

## Runtime artifact signing

Secure event manifests, sealed behavior snapshots, accepted-baseline references, and behavior archives share the runtime artifact signing service. External signing mode requires the configured external signer and does not silently fall back to ephemeral keys. Ephemeral mode uses the current key-evolution identity. Public identities and old-key-signed transitions are retained in the independent Signing Identity Journal so event-log retention can differ from signature-identity retention.

## Validation isolation

Repair policy expresses a minimum isolation capability: PROCESS, CONTAINER, VM, or EXTERNAL. Backend product selection is deployment configuration, not policy semantics. The development tree includes the subprocess PROCESS backend, a rootless Podman CONTAINER backend, and a Multipass VM backend. If the installed backend cannot satisfy policy, Caretaker fails, remains proposal-only, or enters an explicit operator-override workflow according to policy. That override can currently authorize activation without the requested isolation and is not evidence that validation at that tier passed.

Multipass whole-subject deployment and Multipass candidate validation are distinct. Candidate validation transfers only request/result artifacts into a pre-provisioned guest, refuses host-directory mounts, can restore a clean snapshot between ordinary validations, and can use a disposable clone for more suspicious candidates.

## Preferred process topology

The supervised entry point starts before application imports:

```text
supervisor process
    ├── logging writer thread and event socket
    ├── local administrative socket
    ├── optional system collector
    ├── temporary analysis workers
    └── application process tree
            └── lightweight remote emitters
```

Multiple application processes send framed records through a Unix-domain socket. They do not append to shared files or write SQLite. One writer owns event segments and the derived index. Supplemental attachments and system records have separate streams.

This centralized logging topology does not make Repair application-wide. Each application process owns its decorated targets, active runtime replacements, adaptive thresholds, regression corpus, pending approvals, and candidate lifecycle. The default `RepairEngine` uses an in-memory store. A restart therefore discards executable runtime replacements and actionable workflow state even when historical events were logged; pending work is not reconstructed automatically from the SQLite Repair store.

The alpha uses a supervised service process and bounded worker threads for some permanent functions. The worker registry, heartbeat, active-work registry, and watchdog contracts are process-neutral and permit later extraction into separate worker processes without changing public evidence contracts.

## Source of truth

```text
Primary event segment files        authoritative event record
Attachment segment files           authoritative supplemental bodies
System-data streams                 authoritative raw system captures
SQLite indexes                      derived and rebuildable
Sealed behavior snapshots           immutable signed derived artifacts
Accepted Guard baselines             immutable references to sealed snapshots
Active behavior statistics           checkpointed mutable accumulators
LLM assessments                      interpretations only
```

A damaged index can be rebuilt from complete segment records. A derived baseline never replaces its source records.

## Logging fast path

```text
logging call or decorator
    → bind call context
    → mask and redact
    → construct <= 4096-byte envelope
    → bounded queue or local IPC
    → batched append-only writer
    → segment rotation
    → optional compression
    → derived SQLite index
```

No SQLite operation, compression, baseline analysis, or LLM call occurs on an ordinary application logging thread.

## Capture policy

The operator can select any supported signal category, including application logs, warnings, stdout/stderr adapters, exceptions, function calls, inputs, results, imports, filesystem, network, subprocess, dynamic-code, Guard, Repair, Integrity, system records, and future system metrics.

Higher modes define minimum capabilities rather than arbitrary verbosity. Guard may require behavior references and code identity without forcing all application loggers to DEBUG.

## Mode reconciliation and leases

```text
unsigned operator base policy
    + standing mode requirements
    + temporary mode leases
    = immutable effective-policy generation
```

Each override records the operator value, effective value, requiring mode, reason, operational effect, expected cost, policy generation, and lease identity. A released lease removes only its own overlay. Policy changes during a repair invalidate the pending candidate until it is explicitly revalidated.

## Record and attachment integrity

Every primary record carries a format version and writer version. Unknown TLV fields can be skipped. Complete records before a truncated final frame remain readable.

Segments are hashed and chained. Optional runtime signing uses an Ed25519 identity generated at startup. Signing keys evolve on a policy schedule, one day by default; each transition is signed by the prior key before that prior key is discarded. Closed event manifests bind the run identity, sequence range, segment hash, previous segment hash, and attachment-manifest commitment.

The runtime public identity may be:

- self-recorded;
- exported by an operator;
- externally witnessed; or
- covered by an external signer.

A separate external signer remains the strongest option because the application process never possesses the persistent signing identity.

## Supplemental attachments

Large evidence does not inflate the primary record. An attachment reference binds:

- primary event ID and global event sequence;
- attachment ID, schema, and content type;
- uncompressed and compressed hashes and sizes;
- segment and offset;
- sampling decision and signature status.

Attachments are compressed by default, independently rotated and retained, and may use probabilistic sampling after a policy-defined rate threshold. Critical categories can always be preserved.

## System-data collector

The collector uses one timestamp and cycle ID for all sources in a collection cycle. It follows the application PID and descendants, distinguishes PID reuse through process start ticks, and writes nearly raw `/proc` and `/sys` bodies to a separate output tree. It never invokes `sudo`; inaccessible sources are recorded as unavailable.

Semantic parsers and the advanced metrics provider are deferred. The current contract deliberately preserves source bodies for later specialized parsers.

## Work registry and loop control

Logging, Guard, Repair, Integrity, System, and Interrogation publish active and recently completed work. Before treating a change as anomalous, Guard can determine whether the scope and expected code fingerprint match a repair or other known operation.

Runtime control includes:

- duplicate-signal suppression;
- per-scope rate limits;
- maximum cross-subsystem action depth;
- recent-change windows;
- internal-change cooldowns;
- explicit interrogation when observed changes conflict with active work.

Caretaker internal anomalies may cause evidence capture, verification, worker restart, degradation, or application termination. They never cause Caretaker-generated source activation.

## Repair authority

```text
ANALYZE_ONLY
PROPOSE_ONLY
REQUIRE_OPERATOR_APPROVAL
AUTOMATIC_ELIGIBLE_REPAIRS
```

A temporary incident escalation normally uses `REQUIRE_OPERATOR_APPROVAL`. A standing automatic mode can deploy only candidates that pass functional tests, security gates, regression replay, behavioral comparison, integrity eligibility, policy-generation checks, and observation requirements.

## Root-cause and LLM authority

Interrogation constructs a bounded evidence bundle containing timelines, template distributions, deterministic outliers, behavior deviations, dependency changes, integrity findings, and representative redacted records. An LLM can propose hypotheses and confidence levels but cannot rewrite baselines, retention, policy, or evidence.

The administrator makes final root-cause determinations. In automatic Repair mode, the LLM may participate in candidate selection, but deterministic policy and validation remain authoritative.

## External log replication

Local logging provides low latency and allows operation without a network dependency. For higher assurance, operators should also ship records or closed manifests through an independent logging agent to a separate log collection system. Compromising both systems is materially more difficult than rewriting a local corpus. The future `LogSink` and external-manifest-signer protocols preserve this deployment path without making network shipping mandatory in the alpha.
