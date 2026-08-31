# Caretaker Future Work and Long-Term Roadmap

This roadmap records proposed evolution beyond the initial Application Caretaker
release. These are design directions, not current capabilities or guarantees.
Caretaker should first make its application-scoped trust model measurable,
reproducible, efficient, secure, testable, and reliable before it requests
broader authority.

## Scope and trust boundaries

The initial implementation is **Application Caretaker**. It operates inside an
application, understands its functions, exceptions, validators, configuration,
state, and source-level repairs, and has the narrowest authority.

Longer term, independently installable and independently trusted components may
be researched:

1. **Application Caretaker** — application semantics, instrumentation, diagnosis,
   repair, validation, and post-repair observation.
2. **Host Caretaker** — processes, services, packages, filesystems, logs,
   coredumps, resource pressure, networking, and host instrumentation.
3. **Infrastructure Caretaker** — virtual machines, containers, orchestration,
   storage, networks, load balancers, managed services, and cloud resources.

These scopes must not share authority implicitly. Caretakers may exchange
observations, evidence, hypotheses, repair outcomes, and validation results, but
a request from one Caretaker is evidence, not authorization. Each component
must independently evaluate an action under its own policy and authority.
Cross-layer repairs require validation by the layers that depend on them; when a
Caretaker reaches its boundary it escalates rather than granting itself more
authority.

The intended escalation shape is:

```text
application failure -> Application Caretaker
                   -> Host Caretaker when outside application scope
                   -> Infrastructure Caretaker when outside host scope
                   -> host validation -> application validation
```

## Near-term Application Caretaker priorities

### Testing environments and failure corpus

Expand the testing environment with additional example applications, isolated
launch/reset/destroy tooling, realistic demonstrations, policy/autonomy
variants, successful and unsuccessful repairs, and cases where escalation is
correct. Build a reusable corpus of exceptions, timeouts, invalid output,
dependency/configuration failures, corruption, resource/worker exhaustion,
intermittent failures, bad deployments, concurrency failures, failed or
misleading repairs, malicious evidence, unavailable LLM/network services, and
secondary repair failures. Every useful scenario should become a regression
case, including historical and adversarial incidents.

The first repository slice now provides a bounded, metadata-only scenario
manifest, read-only loader, and explicit trusted-runner harness in
`examples/failure_corpus/` and `caretaker.failure_corpus`. It records bounded
observed results separately in a content-hashed local store when a caller
supplies a runner, and can produce bounded deterministic outcome reports, but
its policy gate defaults to least-friction PROCESS execution and can require a
stronger declared isolation tier. It does not provide a sandbox or claim broad
observed coverage. An explicit process runner now provides temporary-workspace
and process-group lifecycle handling, while repository-owned mappings, stronger
isolated lifecycle tooling, and reviewed container/VM scenario mappings,
captured incident fixtures, and broad cross-version outcome coverage remain
required before this priority can be considered complete. The current
container and VM runners require pre-provisioned trusted environments and do
not discover or execute commands from corpus metadata. Repository-owned oracle
mappings now cover the reviewed manifest, but do not establish real observed
application coverage.

### Incident Capsules and post-mortem capture

Extend the initial bounded, immutable **Incident Capsule** implementation for
sufficiently serious incidents. A capsule may contain incident/application/policy metadata, execution
and exception state, decorated call history, relevant source and hashes,
bounded selected arguments/locals/globals, package and environment metadata,
Caretaker observations/hypotheses/repair attempts/validation results, and
integrity seals.

Capture must be explicitly policy-controlled. Proposed levels are `MINIMAL`,
`STANDARD`, `DIAGNOSTIC`, and `FORENSIC`. Policies must control arguments,
locals, globals, environment variables, object types, object/collection/capsule
size, and name/type/application-specific redaction. Diagnostic capture must not
silently expand the deployment's authority to retain information.

Capsules must use bounded safe representations rather than executable Python
serialization. Unknown objects become type information and safe bounded
representations; large collections become samples, sizes, and hashes; files,
sockets, and threads become metadata. Opening a capsule must never execute
captured application or capsule code.

### Incident Explorer and replay

Extend the initial read-only explorer with incident, timeline, failure,
call-tree, function-state, variables, threads, source, evidence, repair,
validation, system-state, and integrity views. It must distinguish complete,
partial, interrupted, corrupt, redacted, truncated, and missing data and display
capsule integrity, source-hash, policy, and redaction status.

Reconstruction and inspection remain separate. Replay must occur only in an
isolated environment, allowing historical incidents to become permanent
regression cases and releases to answer: “How would this version have handled
each significant incident previously observed?”

### Audience-aware incident communications

Add policy-governed communication drafts derived from the same canonical
incident state used for operator inspection. Audience profiles may tailor detail,
terminology, permitted evidence, redaction, cadence, and required fields for
operators, engineers, security teams, leadership, support, customers, public
status readers, or regulated reviewers without changing the underlying facts.

Drafts should distinguish confirmed observation, supported inference,
hypothesis, and unknown; link statements to evidence; disclose freshness,
omissions, validation gaps, and attempted/rolled-back interventions; and never
invent root cause, impact, recovery, or ETA. Draft generation must remain
separate from delivery authority. External communication should require explicit
authorized review by default, while narrowly scoped internal automation may be
enabled by policy.

Start with console or file exports. Add authenticated ticket, chat, email,
paging, status-page, or regulatory adapters only after redaction, idempotency,
retry, receipt, correction, and failure semantics are defined. Communication
must not modify policy, authorize Repair, satisfy validation, close an incident,
or expand Caretaker authority.

## Performance and operational maturity

Reduce observation overhead through event fingerprints, representative samples,
counts, first/last-seen values, repeated stack compression, rolling aggregation,
bounded queues, buffering, coalescing, sampling, prioritization, and deferred
low-priority processing. Distinguish authoritative evidence from derived
reasoning context: summarization may reduce reasoning input but must not alter
the authoritative record or conceal provenance.

Define resource budgets for memory, queued observations, evidence, LLM context,
parallel diagnoses, repairs/retries, CPU, storage, and capsule size. Test
degradation behavior: coalesce repeated events, defer optional work, preserve
critical incident evidence, and escalate when limits are exhausted.

Prefer deterministic paths for known validated failure signatures and repairs,
while keeping them inside the same authority, validation, audit, and
post-repair-observation lifecycle as LLM-assisted paths.

## Security, compatibility, and upgrades

Expand adversarial testing for malicious or conflicting evidence, prompt
injection, authority/validation bypass, policy modification, uncontrolled
retries, resource exhaustion, malformed/stale/replayed artifacts, corrupt
capsules, cross-component trust confusion, and failures during concurrent
incidents.

Turn security claims into executable invariants. In particular: models and
repairs cannot enlarge authority; failed validation cannot be bypassed; evidence
does not become trusted through repetition; exhaustion escalates; invalid
authority remains non-authoritative; policy changes cannot retroactively
authorize actions; redaction cannot be bypassed; and capsule viewing cannot
execute application code.

Expand the matrix across Python versions, Linux distributions, containerized and
non-containerized environments, filesystems, read-only deployments, LLM
backends/unavailability, network conditions, policy/autonomy profiles,
concurrency, and resource-constrained systems. Test upgrades against historical
policies, signed profiles/manifests, authority layers, incident records,
capsules, evidence formats, configuration schemas, changed defaults, migrations,
and removed settings without reinterpreting historical authority unexpectedly.

## Multi-scope research

Host Caretaker should be considered only after the Application Caretaker
maturity gate is met. It may eventually observe processes, systemd, packages,
configuration, filesystems, kernel/service logs, OOM/coredump events, network
state, descriptors, process trees, and dependency versions. Privilege must be
split between unprivileged observation/diagnosis/planning and a small,
deterministic, policy-checked, auditable executor. Operations such as service
restart, package rollback, configuration restore, file restore, process signal,
and narrowly scoped tracing must not become arbitrary root-shell execution.

Infrastructure Caretaker is a still longer-term possibility for VM/container
orchestration, cloud compute, storage, DNS, load balancers, managed databases,
placement, host replacement, and infrastructure rollback. It requires its own
policy and authority boundary and must not inherit application authority.

## Application Caretaker maturity gate

Broader scopes should not begin merely because they are technically possible.
Before considering host-level authority, the project should have:

- repeatable isolated testing and several realistic applications;
- a substantial synthetic, historical, and adversarial failure corpus;
- retained incident inspection and replay;
- mature adversarial tests and executable security invariants;
- supported Python and operating-environment coverage;
- defined performance/resource budgets and overload behavior;
- upgrade compatibility testing and stable policy/authority concepts; and
- meaningful real-world deployment experience.

At every scope the lifecycle remains:

```text
observe -> diagnose -> evaluate candidate -> check authority/policy
        -> validate -> repair when permitted -> observe again
```

What changes is what can be observed, understood, modified, and validated—not
the requirement for policy-constrained authority and evidence-based escalation.
