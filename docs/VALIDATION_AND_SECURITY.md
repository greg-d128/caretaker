# Candidate validation and security

## Isolation boundary

Candidates are parsed, compiled, and exercised in a child process. This protects the main interpreter from many crashes and state mutations but is not a hostile-code sandbox.

The worker may still inherit access available to the operating-system account. Future backends should add containers, dedicated users, network isolation, filesystem restrictions, and resource controls.

## Hard static gates

Automatic activation rejects candidates containing or requiring prohibited capabilities, including dangerous dynamic execution, process creation, global/nonlocal mutation declarations, unsafe dunder access, and executable definition-time default or annotation expressions.

Imports and new concurrency are treated as review-required changes and are not automatically activated in the strict V1 profile.

## Definition-time safety

A function definition can execute annotation and default expressions. Caretaker validates defaults as safe literal structures and strips candidate annotations before the main-process definition is compiled. The original function annotations remain attached to the activated callable.

## Generated tests

Generated tests run only in the isolated worker with restricted built-ins. They are recorded as advisory evidence because the same model may misunderstand both code and tests.

## Provider input

Source, exception messages, tracebacks, logs, and values are untrusted evidence. Repair requests use bounded context and basic secret redaction. Applications should add domain-specific redaction before connecting Caretaker to any remote provider.

## Fail-open and fail-closed validators

Output-validator exceptions fail closed by default. A fail-open policy must be selected explicitly and is appropriate only when availability is more important than enforcing the output contract.

## Behavioral candidate validation

When Guard is enabled, candidate validation has a second dimension:

- static detection of new network, filesystem, subprocess, import, or dynamic-code capabilities;
- comparison with the original accepted behavior baseline where available;
- live probation monitoring after activation;
- rollback when significant candidate-specific deviations exceed policy.

Functional correctness cannot compensate for a prohibited behavioral capability. Behavioral hard gates make the candidate ineligible rather than applying a small scoring penalty.

## Guard is not a sandbox

Python audit hooks and introspection increase observability but do not prevent native extensions, `ctypes`, or a compromised interpreter from bypassing Python-level evidence. See `GUARD_SECURITY.md`.


## Validation-process side-effect restrictions

The default validation policy now blocks network use, subprocess creation, and filesystem writes inside the validation worker. These controls use Python audit hooks and are defense in depth only. The worker still executes under the application OS account; use the documented container/VM isolation when candidate code must be treated as actively hostile. Each capability can be explicitly enabled through `ValidationPolicy` when validation genuinely requires it.
