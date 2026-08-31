# Repair rollout authority and lifecycle

`RepairRolloutLedger` records the authority lifecycle of a runtime Repair
candidate. It is an evidence and coordination boundary; it does not activate a
`FunctionSlot`, route application traffic, or grant authority to a candidate.
The embedding application remains responsible for performing the authorized
operation.

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

The decision checks that the current policy fingerprint matches the rollout,
rejects expired or terminal records, and returns a decision hash with the
selected implementation. It does not invoke either implementation, activate a
function slot, or provide fleet-wide percentage guarantees. The caller must
still apply normal Repair, Integrity, Guard, isolation, and authority checks.

`execute_rollout()` is the corresponding narrow invocation adapter. It consumes
the decision and invokes the caller-supplied, already-authorized deployed or
candidate callable. A sampled shadow call delegates to `shadow_execute()` and
returns the deployed result; canary and active selections return the candidate
only when the decision makes it authoritative. It does not mutate a slot,
install a repair, grant authority, or choose an isolation-unavailable fallback.

When an audit callback is supplied, direct deployed/candidate invocations and
shadow outcomes also emit bounded execution-outcome evidence. It records the
implementation class, selection state, decision hash, and exception type when
present; raw outputs and exception messages are never included.

Callers may also supply a `RepairStore` as `execution_store` to retain one
bounded `RolloutExecutionObservation` per invocation. The record binds the
rollout, candidate, stage, routing decision hash, policy fingerprint, selected
implementation, success state, and shadow equivalence without retaining return
values or exception messages. An optional `execution_id` identifies an
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

The Caretaker Console's `Rollouts` tab requests this projection, displays the
current stage and bounded candidate/shadow counts, and lets an operator inspect
the complete returned record as read-only evidence. It provides no pause,
resume, percentage-change, activation, or rollback action yet.

## Supervisor worker coordination

`RepairRolloutCoordinator` adds a narrow supervisor-owned context gate for
application workers. Before requesting a route, a worker must acknowledge the
current rollout record, including its target, candidate, lifecycle stage, policy
fingerprint, authority fingerprint, worker identity, and process identity. The
acknowledgement is durably stored as bounded evidence and is restored after a
supervisor restart. When the rollout advances, earlier acknowledgements remain
available for analysis but become stale and cannot be used for routing.

The supervised runtime exposes two authenticated worker requests:
`repair-rollout-worker-ack` records the worker acknowledgement, and
`repair-rollout-route` returns the existing deterministic routing decision only
after the acknowledgement and current worker packet/process checks succeed.
The route response contains a digest of the routing key, never the raw key.
Neither request advances a rollout, changes policy, activates a FunctionSlot,
or grants execution authority. These requests are a coordination/evidence
boundary; the application still owns invocation and failure handling.

The coordinator status projection also includes a bounded execution-evidence
summary from the durable rollout store: completed and failed calls, candidate
and shadow counts, comparison outcomes, invalid evidence, and an evidence hash.
If the store is unavailable or the policy/authority context is stale, the
projection reports that state instead of treating missing evidence as success.

The current runtime's built-in writer, event server, control server, and system
collector are not automatically admitted as rollout workers because they do
not yet receive deployment-specific worker authority packets. Deployment-owned
worker admission, process spawning, fleet-wide counters, atomic staged
advancement, and cross-host coordination remain future work.

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
policy and are re-raised. Shadow outcomes remain non-authoritative evidence and
are not counted toward acceptance.

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
permanent promotion requires deployment authority. The routing decision itself
is implemented, while application traffic integration, side-effect isolation,
and supervisor-wide traffic coordination remain separate capabilities and are
not implied by this ledger. The execution-contract/effect-evidence layer does
provide a partial safety signal: a rollout adapter can pass a Guard behavior
capture through `EffectObservation.from_behavior_capture()` before requesting
shadow execution. Positive network, filesystem, subprocess, import, or
dynamic-code evidence is then considered by the shadow gate. Missing evidence
still requires isolation because a bounded capture cannot prove that no effect
occurred.
