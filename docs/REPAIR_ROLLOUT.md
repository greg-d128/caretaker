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

`execute_slot_rollout()` adds the FunctionSlot binding boundary. For a field
repair it requires the record target, candidate ID, candidate source hash, and
previous deployed source hash to match the slot. For a permanent record it
uses the current slot version as deployed code and does not re-route it as a
candidate. Mismatches fail closed. The helper does not mutate the slot or
advance candidate acceptance counters; the normal application lifecycle still
owns those actions.

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
not implied by this ledger.
