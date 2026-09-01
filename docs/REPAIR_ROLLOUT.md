# Repair rollout authority and lifecycle

`RepairRolloutLedger` records the authority lifecycle of a runtime Repair
candidate. It is an evidence and coordination boundary; it does not activate a
`FunctionSlot` or grant authority to a candidate. The embedding application
remains responsible for performing the authorized operation. An optional
`RepairRolloutCoordinator` can allocate application-wide route decisions within
one supervisor/control-plane context, but it does not provide cross-host or
multi-supervisor coordination.

## Lifecycle

The ledger permits the following states:

```text
PROPOSED -> VALIDATED -> SHADOW -> CANARY -> ACTIVE -> RETIRED
                                      \-> REVOKED
```

Any non-terminal state can be revoked. Direct `VALIDATED -> ACTIVE` is allowed
only for an explicit operator-authorized field repair when policy permits it.
The direct path is recorded as a field-repair release; it is not a deployment
promotion.

Entering `VALIDATED` requires a validation evidence hash. A stale policy or
authority fingerprint prevents further transitions. An expired authority may
not advance a rollout, but an expired rollout can still be retired or revoked
for safety.

## Field repairs and permanent deployment

An operator may release a validated candidate as:

```python
from caretaker import (
    RepairRolloutAuthority,
    RepairRolloutLedger,
    RepairRolloutPolicy,
    RepairRolloutStage,
)

ledger = RepairRolloutLedger(
    policy=RepairRolloutPolicy(enabled=True),
    store=repair_store,
)
field_fix = ledger.advance(
    rollout.rollout_id,
    to_stage=RepairRolloutStage.ACTIVE,
    authority_type=RepairRolloutAuthority.OPERATOR,
    authority_id="operator-invocation-id",
    reason="release bounded field fix",
    policy_fingerprint=rollout.policy_fingerprint,
    authority_fingerprint=rollout.authority_fingerprint,
)
```

The record remains `release_kind=field-repair` and the candidate remains
runtime-only. To become permanent, a separate deployment-authority transition
is required:

```python
permanent = ledger.promote_permanent(
    field_fix.rollout_id,
    authority_type=RepairRolloutAuthority.DEPLOYMENT,
    authority_id="deployment-authority-id",
    deployment_artifact_hash="reviewed-deployment-artifact-sha256",
    reason="deployment accepted the field repair",
    policy_fingerprint=field_fix.policy_fingerprint,
    authority_fingerprint=field_fix.authority_fingerprint,
)
```

Validation success alone never changes authority. Adaptive or advisory actors
cannot advance a rollout under the default policy. Active revocation requires a
new incident by default because reversing an accepted runtime change is a new
transaction.

## Deterministic routing decisions

`decide_rollout_routing()` provides the policy-controlled selection boundary for
an embedding application. It hashes a caller-provided routing key together with
an explicit population scope and rollout ID, then selects from the configured
percentage using a bounded bucket. The raw key is never included in the result;
only its digest is retained as evidence.

The routing policy is deliberately conservative:

- shadow sampling selects whether the candidate should run, but the deployed
  implementation remains authoritative;
- canary percentage may select the candidate as authoritative for that call;
- active candidate percentage applies only to a field repair whose record says
  the candidate is authoritative;
- a permanent deployment record remains deployed-authoritative even if an old
  candidate percentage is configured.
- `candidate_mirror_percentage` optionally samples candidate-authoritative
  canary or active field-repair calls for a deployed comparison. It defaults to
  `0`, so the additional invocation is disabled unless policy explicitly opts
  in. Mirror sampling uses a separate deterministic bucket and does not change
  which implementation is authoritative.

An application may define a `RolloutRampPolicy` containing ordered
`RolloutRampStep` values for the shadow, canary, and active stages. When an
authorized stage transition enters one of those stages, the step's declared
percentages are applied to the rollout record and included in the transition
evidence. Omitted percentages retain their previous value. A ramp never
advances a stage automatically or grants authority; the normal lifecycle and
readiness checks still apply. If a step increases any percentage, readiness is
required unless the operator explicitly overrides it, and the override is
recorded. An empty ramp preserves the existing manual percentage controls.
When `allow_adaptive_stage_progression` is enabled, a supervisor may call
`RepairRolloutCoordinator.advance_if_ready()` during its control cycle. The
method advances only validated/shadow/canary rollouts whose configured
readiness result is `READY`; it uses adaptive authority, records the same
transition chain, and never validates a proposal, skips a stage, or grants
execution authority. Unready, unavailable, or unconfigured evidence produces
no mutation.

Readiness thresholds may be supplied globally through
`RolloutReadinessRequirements` or overridden per executable stage with
ordered `RolloutStageReadiness` entries in `stage_readiness`. The override is
selected for the next stage under review; stages without an entry use the
global requirements. Per-stage thresholds affect only the readiness decision
and never bypass validation, authority, pause, expiry, or lifecycle checks.

The decision checks that the current policy fingerprint matches the rollout,
rejects expired or terminal records, and returns a decision hash with the
selected implementation. It does not invoke either implementation, activate a
function slot, or provide fleet-wide percentage guarantees. The caller must
still apply normal Repair, Integrity, Guard, isolation, and authority checks.

`execute_rollout()` is the corresponding narrow invocation adapter. It consumes
the decision and invokes the caller-supplied, already-authorized deployed or
candidate callable. A sampled shadow call delegates to `shadow_execute()` and
returns the deployed result; canary and active selections return the candidate
only when the decision makes it authoritative. A mirror-selected
candidate-authoritative call runs the candidate first and returns its result,
then runs deployed code with an independent input copy as comparison evidence.
A mismatch or deployed comparison exception is retained as evidence and never
triggers an automatic switch. If the contract and complete effect evidence do
not establish safe duplicate execution, the deployed comparison requires a
verified application-owned isolation adapter. It does not mutate a slot,
install a repair, grant authority, or choose an isolation-unavailable fallback.

An embedding application may pass a `RepairRolloutCoordinator` together with
the worker ID and process ID. In that mode, the adapter obtains the route only
after the worker has acknowledged the exact current rollout context. Missing,
stale, or mismatched worker acknowledgement fails closed. Omitting the
coordinator preserves the direct process-local path for unsupervised runs.

When an audit callback is supplied, direct deployed/candidate invocations and
shadow outcomes also emit bounded execution-outcome evidence. It records the
implementation class, selection state, decision hash, and exception type when
present; raw outputs and exception messages are never included.

Callers may also supply a `RepairStore` as `execution_store` to retain one
bounded `RolloutExecutionObservation` per invocation. The record binds the
rollout, candidate, stage, routing decision hash, policy fingerprint, selected
implementation, success state, shadow equivalence, and bounded mirror outcome
without retaining return values or exception messages. An optional `execution_id` identifies an
observation for idempotent re-submission; conflicting reuse is rejected. These
observations are evidence for
operator review and future staged decisions only. They do not advance a stage,
activate a slot, or grant authority.

The supervised application exposes this evidence through the read-only
`repair-rollout-status` control request. The response is bounded by `limit` and
`transition_limit`, includes lifecycle records and transition history, and
embeds an integrity-checked execution summary for each returned rollout. A
summary whose policy fingerprint is stale, or whose execution store is not
available, is reported as `STALE_OR_UNAVAILABLE`; it is never counted as
successful evidence. The response explicitly reports `read_only: true` and
`authority_granted: false`. This is an operator projection only: it does not
advance a rollout, change routing percentages, activate a FunctionSlot, or
grant execution authority.

The Caretaker Console's `Rollouts` tab requests this projection and displays the
current stage, bounded candidate/shadow/mirror counts, current worker
acknowledgement counts, and readiness state. An operator can select a rollout
and request one of the legal next lifecycle stages through the authenticated
control plane. The form requires a non-empty reason and explicit confirmation;
it offers no validation bypass for proposed rollouts, requires a separate
incident UUID when revoking an active rollout, and exposes readiness override as
an explicit operator choice. The console refreshes the projection after a
recorded transition and shows the returned signed/audited transition evidence.

This is intentionally narrower than general rollout control. The console does
not activate a FunctionSlot or grant execution authority. The supervisor and
ledger remain authoritative for policy, readiness, lifecycle, expiry, and
incident checks.

## Policy-governed routing percentage changes

An operator may change the shadow, canary, active-candidate, and candidate-mirror percentages
only when `allow_operator_routing_changes` is enabled in the rollout policy.
The policy separately controls whether an increase is allowed through
`allow_operator_routing_increases`; both settings default to `false`. The
bucket count and routing scope do not change as part of this operation, so an
update cannot silently reshuffle the population by changing the hashing
space.

The supervisor accepts only an explicitly confirmed request with a reason and
the current policy and authority fingerprints. Increases additionally require
ready rollout evidence by default, or an explicitly recorded operator
readiness override. The ledger stores the effective percentages on the
rollout record and records the prior and new values in a same-stage,
hash-chained `routing-update` transition. A percentage update does not change
the lifecycle stage, activate a FunctionSlot, or make the candidate
authoritative outside the existing stage rules. The percentages remain
process-local routing configuration; exact application-wide percentages still
require supervisor-wide atomic coordination.

Worker acknowledgements include a deterministic fingerprint of the effective
routing policy. Changing any rollout percentage therefore preserves the old
acknowledgement as stale evidence and requires each worker to acknowledge the
new routing configuration before it can request a route.

The Rollouts console displays the bound percentages and enables the update
control only when the supervisor policy advertises operator routing changes.
The same reason and confirmation controls are shared with lifecycle and
pause/resume actions, and the response is refreshed from the supervisor after
the transition.

Pause and resume are separate control actions over an executable stage. A
paused rollout retains its lifecycle stage and transition history, but routing
fails closed until an authorized operator resumes it. Pausing does not require
readiness; resuming does, unless the operator explicitly records a readiness
override. A paused rollout cannot advance or become a permanent deployment
until it is resumed, while safety retirement or revocation remains available.

## Supervisor worker coordination

`RepairRolloutCoordinator` adds a narrow supervisor-owned context gate for
application workers. Before requesting a route, a worker must acknowledge the
current rollout record, including its target, candidate, lifecycle stage, policy
fingerprint, authority fingerprint, effective routing-policy fingerprint,
worker identity, and process identity. The acknowledgement is durably stored as
bounded evidence and is restored after a supervisor restart. A percentage
change makes earlier acknowledgements stale. When the rollout advances, earlier
acknowledgements remain
available for analysis but become stale and cannot be used for routing.

The supervised runtime exposes two authenticated worker requests:
`repair-rollout-worker-ack` records the worker acknowledgement, and
`repair-rollout-route` returns a deterministic routing decision only after the
acknowledgement and current worker packet/process checks succeed. A request may
set `application_wide=true` and provide an application-generated
`assignment_id`; the supervisor then allocates the next bounded routing bucket
from its durable application sequence and returns the assignment evidence.
Reusing an assignment ID is idempotent only when the rollout context, worker
process, routing scope, and routing-key digest all match.
The route response contains a digest of the routing key, never the raw key.
Neither request advances a rollout, changes policy, activates a FunctionSlot,
or grants execution authority. These requests are a coordination/evidence
boundary; the application still owns invocation and failure handling.

Application-wide assignments are content-hashed, durably persisted when a
rollout store is configured, restored after supervisor restart, and exposed as
read-only status counts. Their sequence is scoped to the current
supervisor/coordinator and rollout policy/authority context. This provides
application-wide allocation for a single application control plane; exact
atomic percentages across hosts or independent supervisors remain outside this
capability.

The coordinator status projection also includes a bounded execution-evidence
summary from the durable rollout store: completed and failed calls, candidate
and shadow counts, comparison outcomes, invalid evidence, and an evidence hash.
If the store is unavailable or the policy/authority context is stale, the
projection reports that state instead of treating missing evidence as success.

`RolloutReadinessRequirements` provides optional, explicit thresholds for
reviewing the next lifecycle stage. It can require minimum total, completed,
shadow, candidate-authoritative, or current-worker counts, and maximum failure,
mismatch, candidate-failure, or invalid-observation counts. The coordinator
reports `READY`, `NOT_READY`, `UNAVAILABLE`, `NOT_CONFIGURED`, or
`NOT_APPLICABLE` with each check and the evidence hash. Thresholds are disabled
by default, and a `READY` result is advisory evidence only: an authorized
operator or deployment must still call the normal ledger transition.

The current runtime's built-in writer, event server, control server, and system
collector are not automatically admitted as rollout workers because they do
not yet receive deployment-specific worker authority packets. Deployment-owned
worker admission, process spawning, fleet-wide counters, atomic staged
advancement, and cross-host coordination remain future work.

The supervised control plane also accepts `repair-rollout-advance` for an
explicitly confirmed operator transition. The OS-authenticated control peer is
recorded as the operator identity, a reason is required, promotion into
shadow/canary/active is checked against configured readiness thresholds, and an
operator may explicitly override an unmet or unavailable readiness result.
Proposed rollouts cannot skip the validation workflow through this command.
Retirement and incident-backed revocation remain available as safety actions
without a readiness override. The resulting transition is still subject to
the ledger's current policy, authority fingerprint, expiry, lifecycle, and
incident checks, and is recorded in the transition chain and audit stream.

The invocation helpers also accept a Guard behavior capture directly through
`behavior_capture`. Caretaker converts its retained event and resource
evidence into the shadow eligibility check before execution. A normal capture
is incomplete by default, and callers must explicitly provide an already
validated `EffectObservation` when a collector can justify complete coverage.
Supplying both forms is rejected so stale and current effect evidence cannot be
silently merged.

`execute_slot_rollout()` adds the FunctionSlot binding boundary. For a field
repair it requires the record target, candidate ID, candidate source hash, and
previous deployed source hash to match the slot. For a permanent record it
uses the current slot version as deployed code and does not re-route it as a
candidate. Mismatches fail closed. The helper does not mutate the slot or
advance candidate acceptance counters; the normal application lifecycle still
owns those actions.

When supplied with the existing `ObservationManager`, `execute_slot_rollout()`
records authoritative candidate outcomes using the rollout ID and routing
decision hash. Candidate failures follow the configured observation rollback
policy. By default they are re-raised. A policy may explicitly select
`candidate_failure_action="fallback-to-deployed"` for a `PURE` contract when
supplied effect evidence does not report externally visible effects. A
`READ_ONLY` contract may use the same fallback only when
`allow_read_only_candidate_fallback=true` is explicitly enabled and the
application supplies complete effect evidence with no observed externally
visible effects. Incomplete evidence always fails closed. The candidate
failure and deployed fallback are both recorded, and the failure still goes
through observation rollback/accounting. There is no silent fallback for
side-effecting or incompletely trusted execution. Shadow outcomes remain
non-authoritative evidence and are not counted toward acceptance.

The Rollouts console displays fallback counts separately from candidate success
and failure counts, so a deployed result returned after a candidate failure
remains visibly distinct from candidate acceptance.

For applications using a `RepairEngine`, `engine.invoke_rollout()` is the
registry-aware invocation boundary:

```python
result = engine.invoke_rollout(
    rollout,
    policy=rollout_policy,
    policy_fingerprint=current_policy_fingerprint,
    routing_scope="tenant",
    routing_key=tenant_id,
    args=(request,),
)
```

The engine resolves the rollout's target ID through the current registry and
then delegates to `execute_slot_rollout()`. This means the installed
`FunctionSlot` candidate and its preceding deployed version are checked on
every invocation, rather than being captured by a long-lived application
closure. Candidate-authoritative calls are recorded through the engine's
existing `ObservationManager` by default; callers that already account for
outcomes elsewhere may set `record_observation=False`. The method does not
activate a slot, change lifecycle state, or create authority, and applications
remain responsible for choosing the routing key and deciding when to use this
boundary. Automatic replacement of an existing decorated callable with a
rollout-aware path, fleet-wide routing, and deployment-owned worker lifecycle
remain future work. The application-owned `engine.bind_rollout_callable()`
adapter can replace a decorated function at an explicit application traffic
boundary while preserving its raw return-value contract.

`engine.bind_rollout()` provides a convenience wrapper for applications that
want an ordinary callable at their traffic boundary. Its `routing_key` may be
a fixed safe key or an application-owned function of `(args, kwargs)`. Its
rollout argument may also be a zero-argument provider; that provider is
evaluated for every invocation so the application can reload the current
immutable record after an operator transition:

```python
invoke = engine.bind_rollout(
    lambda: rollout_store.current(rollout_id),
    policy=rollout_policy,
    policy_fingerprint=current_policy_fingerprint,
    routing_scope="tenant",
    routing_key=lambda args, kwargs: kwargs["tenant_id"],
)
result = invoke(request)
```

The binding is an application integration convenience, not a background
traffic controller. It does not infer routing identity, cache mutable rollout
state as authoritative, activate a slot, or grant authority.

When the traffic boundary expects the function's result directly rather than
a `RolloutExecutionResult` envelope, applications may use
`engine.bind_rollout_callable(decorated_function, ...)`. The adapter requires
that the function was decorated and registered by the same engine, resolves
the current slot on each call, and preserves the existing rollout policy,
worker-context, authority, and effect-isolation gates.

For example:

```python
from caretaker import decide_rollout_routing

decision = decide_rollout_routing(
    field_fix,
    policy=policy,
    policy_fingerprint=current_policy_fingerprint,
    routing_scope="tenant",
    routing_key=tenant_id,
)
if decision.candidate_selected:
    # The embedding application invokes its already-authorized path here.
    ...
```

## Transition evidence

Each transition records:

- rollout, target, candidate, incident, policy, and authority identities;
- prior and resulting lifecycle states and the transition reason;
- authority type and actor identity;
- a content hash and chained transition hash;
- an optional runtime-signed artifact when a signing service is configured;
- the effective deployment artifact hash when permanence is accepted.

Transitions are persisted in the Repair store and also emitted as
`repair.rollout.transition` Repair events. Runtime signing is optional and does
not replace external secure audit delivery. An unsigned transition is still
explicitly marked `UNSIGNED`.

## Policy defaults

`RepairRolloutPolicy` is disabled by default so existing Repair behavior does
not change. When enabled, validation is required, direct field activation is
allowed only for an operator, active revocation requires a new incident, and
permanent promotion requires deployment authority. The routing decision and
single-supervisor application-wide allocation are implemented, while
side-effect isolation and cross-host/multi-supervisor traffic coordination
remain separate capabilities and are not implied by this ledger.
Candidate failures default to `raise`. The explicit
`fallback-to-deployed` option is a conservative application-level escape hatch,
restricted to a `PURE` execution contract with no observed externally visible
effects; it does not grant authority, change policy, or advance rollout state.
The execution-contract/effect-evidence layer does
provide a partial safety signal: a rollout adapter can pass a Guard behavior
capture through `EffectObservation.from_behavior_capture()` before requesting
shadow execution. Positive network, filesystem, subprocess, import, or
dynamic-code evidence is then considered by the shadow gate. Missing evidence
still requires isolation because a bounded capture cannot prove that no effect
occurred.
