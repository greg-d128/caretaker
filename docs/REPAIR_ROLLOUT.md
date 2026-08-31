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
permanent promotion requires deployment authority. Shadow execution, canary
routing, side-effect isolation, and supervisor-wide traffic coordination are
separate capabilities and are not implied by this ledger.
