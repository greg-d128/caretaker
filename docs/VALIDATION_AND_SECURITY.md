# Candidate validation and security

## Isolation boundary

Candidates are parsed, compiled, and exercised in a child process. This protects the main interpreter from many crashes and state mutations but is not a hostile-code sandbox.

The PROCESS worker may still inherit access available to the operating-system account. Caretaker also includes rootless Podman CONTAINER and Multipass VM validation backends with stronger configured boundaries. These reduce exposure but do not guarantee containment; see `ISOLATED_EXECUTION.md`.

## Current validation trust boundaries

Validation reports are trusted backend input. The parent currently rejects reported mandatory failures, but it does not prove that a backend returned every mandatory successful check. A custom, defective, or compromised backend can therefore overstate completion. Backend results must not be treated as independently attested evidence.

Validation requests use a versioned JSON envelope and an explicit data-only
codec. Registered cases may contain bounded JSON-compatible primitives,
tuples, and string-keyed mappings; unsupported application objects are
rejected. Only trusted Caretaker components should create, transport, or
deserialize these requests, and the request/result channel is not an
authenticated protocol for mutually untrusted peers.

When the requested isolation backend is unavailable, `REQUIRE_OPERATOR_APPROVAL` retains the candidate for explicit operator review but cannot authorize activation without that isolation. Use `FAIL_REPAIR` when missing isolation should also prevent a pending review item.

## Hard static gates

Automatic activation rejects statically recognizable prohibited capabilities, including dangerous dynamic execution, process creation, global/nonlocal mutation declarations, direct unsafe dunder access, and executable definition-time default or annotation expressions. Dynamic construction or lookup of prohibited names, such as a dunder name passed to `getattr`, is not comprehensively detected.

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
