# Policy truthfulness and runtime semantics

Caretaker treats an accepted policy as an executable contract. A public setting must not be accepted merely because it can be parsed, serialized, signed, or displayed. If the running release cannot honor a requested semantic, policy validation fails before the affected subsystem begins.

This rule is separate from policy authority. Authority answers **who may request or constrain a setting**. Policy truthfulness answers **whether this Caretaker build actually implements the requested setting**.

## Rules

1. Implemented settings must have behavioral tests showing that changing the setting changes runtime behavior.
2. Security/privacy controls are enforced at the final action boundary where practical. For example, Repair context controls are applied when the LLM request is built, and artifact-integrity requirements are applied when artifacts are loaded or restored.
3. A setting whose non-default behavior is not implemented is either removed from the supported surface or given an inactive/unset default and rejected explicitly when requested.
4. A stronger-sounding mode name must not imply a boundary Caretaker cannot provide. Guard uses `DISABLED`, `LEARN`, and `AUDIT`; research/forensic collection depth is policy, while actual prevention/quarantine is an explicit response capability.
5. Backend/isolation shortfalls are explicit. `FAIL_REPAIR` fails closed, while `PROPOSE_ONLY` preserves evidence without activation. `REQUIRE_OPERATOR_APPROVAL` retains a proposal for operator review, but required isolation remains non-overridable and approval cannot activate it without validation at that tier.
6. Signed artifacts cannot silently downgrade to hash-only artifacts when policy requires signatures.

## Reviewed policy-surface fingerprint

`caretaker.policy_semantics` computes a deterministic schema fingerprint over the public policy dataclasses in:

- Repair policy;
- Guard policy and bindings;
- operator logging policy and bindings;
- system collection policy;
- lightweight adaptive instrumentation policy.

The logging policy includes the run-bound, output-only audit-stream settings;
those settings are reviewed as configuration semantics. External delivery is
optional and remains output-only; it supports bounded local store-and-forward
and an optional policy-controlled acknowledgement bound to the exact record
SHA-256 digest. Transport authentication, replay protection, and independent
remote security remain future work. Per-event runtime signatures are
implemented when an approved signing mode and runtime signer are configured.

The lightweight policy's `aggregation` block is an opt-in evidence transport
control. Its default is disabled for least-friction startup. When enabled,
workers batch bounded counters for supervisor-owned merging; it does not grant
promotion, Repair, or policy-changing authority.

The fingerprint includes field path, declared type, and default. `REVIEWED_POLICY_SURFACE_HASH` is updated only as part of an explicit policy-semantics review. The test suite fails if the dataclass surface changes without that review.

This fingerprint is a **development/conformance guardrail**, not a deployment signature or authority fingerprint. Signed policy/profile provenance remains the responsibility of the policy-authority and profile systems.

The current review can be inspected programmatically:

```python
from caretaker.policy_semantics import policy_surface_review_status

print(policy_surface_review_status())
```

## Explicitly reserved settings

`caretaker.policy_semantics.RESERVED_SETTINGS` lists exposed concepts that are intentionally not implemented in this release. Validators reject requests that would rely on those semantics. Important examples include:

- Repair incident-history retrieval and automatic structural-review scheduling;
- incident-window oscillation detection and automatic regression replay before failed-version reactivation;
- Guard environment-read/general function-call collectors;
- time-based durable Guard retention;
- multi-open-segment logging and multi-worker compression;
- segment-class-aware incident/baseline retention;
- automatic logging-baseline orchestration and advanced metrics-provider
  adapters;
- cgroup process discovery and system-collector-driven Guard/mode degradation.

Defaults for these features are intentionally inactive/unset. Their presence in a dataclass is not a promise of availability.

`GuardTargetPolicy.periodic.compare_behavior` is now an executable opt-in. It
compares current same-generation statistics with an accepted baseline during
periodic function inspection and emits only bounded evidence and, when a
change is found, the normal policy-governed Guard signal. It does not accept a
baseline, rotate a generation, change policy, or grant authority. Missing,
stale, or incompatible evidence is reported explicitly rather than classified
as unchanged.

## Repair context privacy and size

`ContextPolicy` is applied before a `RepairRequest` is handed to a provider. `include_source`, `include_traceback`, `include_state_diff`, `send_argument_values`, and `send_local_values` therefore change the actual provider payload. `maximum_context_characters` bounds the combined textual context fields, not only correlated log text.

`previous_incidents` currently defaults to zero and values above zero are rejected because durable incident-history retrieval is not yet implemented.

`StatePolicy.restore_for_validation` is enforced before candidate validation by
restoring captured in-process instance and global state. This covers only
state captured under the active `StatePolicy`; external side effects require a
separate isolation or application-managed boundary and are not implied by
this setting.

## Guard semantics

`GuardMode.DISABLED` installs no Guard observation hooks. `LEARN` permits candidate-baseline learning. `AUDIT` observes and compares accepted behavior. Historical names such as `RESEARCH`, `FORENSIC`, and `ENFORCE` are compatibility aliases rather than claims of stronger enforcement.

Deterministic allow/deny rules create explicit policy-violation deviations. Response policy then determines whether Caretaker alerts, quarantines, opens Repair, or takes another implemented action. Audit observation alone is never described as a host security boundary.

## Operational configuration

`RepairEngine(validation_backends=(...))` can receive several validation backends. Caretaker selects the lowest available backend that satisfies the target's `minimum_isolation`; if none satisfies it, the configured unavailable action applies. Supplying the legacy singular `validation_backend=` remains supported.

For supervised runtime signing, `python -m caretaker.run --external-signer module:attribute ...` loads a trusted signer provider in the supervisor. `EXTERNAL_SIGNED` still fails rather than silently falling back if the provider is absent or invalid.

## Adding a policy field

A new public policy field requires all of the following before the reviewed surface hash is updated:

1. a defined runtime meaning and precedence;
2. validation of invalid/unsupported combinations;
3. at least one behavioral test proving the setting changes execution;
4. authority/profile-surface review when the setting changes a security capability;
5. operator documentation and migration notes when defaults or semantics change.

If any of those are intentionally deferred, the field must default to an inactive value and be entered in the explicit reserved-setting catalog. Recovery policy fields are reviewed with the same rule: the current defaults preserve deployed-code-only restart recovery, require authority revalidation, and reject candidate reactivation because that executor is not implemented yet.

The current review generation is 27. It includes the optional
`lightweight.AdaptiveAggregationPolicy.aggregation_scope` field and the
`transition_timeout_seconds` field. The scope is inactive by default, is
validated when supplied, and only partitions supervisor evidence. The timeout
is bounded to 1..86400 seconds, is captured in each supervisor Behavior
transition request, and only governs expiry of incomplete acknowledgements.
Neither field authorizes promotion, Repair, or policy changes. The current
surface also reviews `logging.communications.llm_tailoring_enabled`, which is
disabled by default and only permits bounded, advisory language suggestions
for already redacted incident drafts. The `logging.metrics` binding is now
active for the built-in process provider when explicitly enabled with the
output-only monitoring stream; its sampling, output, and correlation bounds
are validated and tested. Guard automatic collection can optionally prioritize
current-generation stale snapshots and recent significant deviations; the
default remains fair round-robin scheduling.

The aggregation policy also includes `backpressure_action`, which defaults to
`RETAIN` for least-loss behavior and may be set to `DROP`, `REDUCE`, or
`INCIDENT`. These choices control only bounded worker evidence handling when
submission is unavailable; they do not change application results, policy, or
authority. `INCIDENT` uses an application-owned
`backpressure_incident_callback` and retains the pending batch after reporting
the bounded incident context. A callback must explicitly return an accepted
incident identifier; callback absence, rejection, or failure is reported and
does not discard the evidence. In a supervised run, the configured logging
runtime supplies this callback by default: the supervisor validates the
output-only request, creates a minimal Incident Capsule, and records an
important `INCIDENT_CAPTURED` audit event. This implicit path is unavailable
when capsule capture is disabled or no supervisor control socket is active;
an explicit callback still takes precedence. An optional
`backpressure_audit_callback` receives a bounded output-only audit envelope;
the callback is not a command channel and cannot grant authority. When
Caretaker logging is configured, its enabled audit emitter supplies the
default callback; an explicit callback still takes precedence. An unconfigured
or disabled audit stream leaves the adaptive path least-friction and local.
