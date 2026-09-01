# Guard security analysis

## Intended property

Guard records, compares, and explains observable Python runtime behavior. It can enforce selected deterministic policies where supported hooks provide a reliable decision point.

It does not prove that a package is benign or contain arbitrary hostile code in the same interpreter.

## Strongest current capabilities

- exact package/module/function identity;
- signed-source correlation where Integrity is configured;
- import-time and periodic Python runtime fingerprints;
- audit events for many standard operations;
- explicit behavior baselines;
- deterministic novelty and magnitude detection;
- bounded sensitive-file to outbound-network sequence evidence;
- candidate behavioral gates and rollback;
- module quarantine and pre-import fallback routing;
- queryable evidence and post-mortem records.

## Operator access to sequence evidence

After selecting a Guard-enabled target in the Caretaker console, an operator
can use **File/network sequences** to request the bounded sensitive-file to
outbound-network correlation report. The action is read-only and displays the
same evidence exposed by the runtime control plane; it does not change a
baseline, policy, incident, or Repair state. Each result is explicitly marked
as sampled evidence and does not make an absence claim. The control-plane
command is `guard-sensitive-file-network-sequences` for scripted or other
trusted operator tooling.

## Bypass and ambiguity risks

- native extensions can call operating-system APIs below Python wrappers;
- `ctypes` can access native capabilities;
- subprocess activity moves into another process;
- background threads and callbacks complicate attribution;
- an attacker may imitate accepted behavior;
- sparse workloads may fail to exercise dormant malicious logic;
- a compromised interpreter can tamper with Python-level monitoring;
- same-user or root compromise can observe or modify the process;
- a malicious first observation can poison an unreviewed candidate baseline.
- sensitive-file/network sequence results are correlations over observed
  Python-level events only. Sampling, missing call attribution, native code,
  subprocesses, and other unobserved activity prevent them from proving that
  no sequence occurred; the result is evidence and does not authorize action.

## Baseline safeguards

- baseline acceptance is explicit by default, but policy can deliberately enable `automatic_acceptance=True`; automatic acceptance increases poisoning risk and is not an independent trust decision;
- baselines include exact code identity;
- optional workload and environment identity;
- accepted baselines are immutable and versioned;
- changes create new candidate baselines;
- integrity status may be required before acceptance.

## LLM safeguards

- deterministic extraction precedes LLM review;
- evidence is bounded and marked untrusted;
- structured output is required;
- LLM assessment remains advisory;
- explicit integrity and Guard policies have higher precedence;
- assessments preserve provider, model, prompt, and response hashes.

## Import routing safeguards

- alternatives must be pre-registered;
- source hashes and integrity state can be required;
- accepted behavior baselines can be required;
- substitution occurs before load;
- already loaded variants normally require restart;
- no automatic third-party code rewriting.

## Future stronger boundaries

The architecture is designed to accept stronger backends:

- CPython native audit hooks installed before interpreter initialization;
- a dedicated low-privilege worker;
- containers or VMs;
- network namespaces and firewalls;
- seccomp and Landlock;
- eBPF or operating-system tracing;
- TPM-backed or externally witnessed state;
- signed transparency logs;
- hardware or interpreter-level attestation.
