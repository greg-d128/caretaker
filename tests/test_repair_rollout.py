from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from caretaker import (
    InMemoryRepairStore,
    RepairReleaseKind,
    RepairRolloutAuthority,
    RepairRolloutError,
    RepairRolloutLedger,
    RepairRolloutPolicy,
    RepairRolloutStage,
    RolloutRampPolicy,
    RolloutRampStep,
    SQLiteRepairStore,
)


def _ids() -> dict[str, object]:
    return {
        "incident_id": uuid4(),
        "candidate_id": uuid4(),
        "candidate_source_hash": "candidate-hash",
        "base_source_hash": "base-hash",
        "policy_fingerprint": "policy-hash",
        "authority_fingerprint": "authority-hash",
    }


def _ledger(*, clock=None, **changes) -> RepairRolloutLedger:
    policy = RepairRolloutPolicy(enabled=True, **changes)
    return RepairRolloutLedger(policy=policy, clock=clock)


def _proposed(ledger: RepairRolloutLedger):
    return ledger.create(
        target_id="example.target",
        proposed_by="advisory-engine",
        **_ids(),
    )


def _validated(ledger: RepairRolloutLedger):
    record = _proposed(ledger)
    return ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.VALIDATED,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="validation passed",
        policy_fingerprint=record.policy_fingerprint,
        authority_fingerprint=record.authority_fingerprint,
        validation_evidence_hash="validation-hash",
    )


def test_disabled_rollout_cannot_create_records() -> None:
    ledger = RepairRolloutLedger(policy=RepairRolloutPolicy())

    with pytest.raises(RepairRolloutError, match="disabled"):
        _proposed(ledger)


def test_invalid_rollout_enum_input_raises_bounded_rollout_error() -> None:
    with pytest.raises(RepairRolloutError, match="invalid rollout stage"):
        RolloutRampPolicy().step_for("not-a-stage")


def test_rollout_milestone_commit_is_idempotent() -> None:
    store = InMemoryRepairStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        store=store,
    )
    record = _proposed(ledger)
    transition = ledger.transitions(record.rollout_id)[0]
    event = store.events[-1]
    before = (len(store.rollouts), len(store.rollout_transitions), len(store.events))

    store.commit_rollout_transition(record, transition, event)

    assert (len(store.rollouts), len(store.rollout_transitions), len(store.events)) == before
    assert event.details["persistence"]["schema_version"] == 1
    assert event.details["persistence"]["idempotency_key"] == (
        f"rollout-transition:{transition.transition_id}"
    )


def test_rollout_milestone_commit_failure_does_not_publish_transition() -> None:
    class FailingStore(InMemoryRepairStore):
        def commit_rollout_transition(self, record, transition, event):
            raise RuntimeError("injected milestone commit failure")

    store = FailingStore()
    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        store=store,
    )

    with pytest.raises(RuntimeError, match="milestone commit failure"):
        _proposed(ledger)

    rollout_id = next(iter(store.rollouts))
    assert store.rollout_transitions == {}
    assert ledger.transitions(rollout_id) == ()


def test_proposal_is_non_authoritative_and_advisory_cannot_advance() -> None:
    ledger = _ledger()
    record = _proposed(ledger)

    assert record.stage is RepairRolloutStage.PROPOSED
    assert record.release_kind is RepairReleaseKind.FIELD
    assert record.authoritative_implementation.value == "deployed"
    assert len(ledger.transitions(record.rollout_id)) == 1

    with pytest.raises(RepairRolloutError, match="advisory"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.VALIDATED,
            authority_type=RepairRolloutAuthority.ADVISORY,
            authority_id="advisory-engine",
            reason="not an approval",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
            validation_evidence_hash="validation-hash",
        )


def test_validation_requires_bound_evidence() -> None:
    ledger = _ledger()
    record = _proposed(ledger)

    with pytest.raises(RepairRolloutError, match="validation evidence"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.VALIDATED,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="missing evidence",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
        )


def test_operator_can_release_a_validated_field_fix_directly() -> None:
    ledger = _ledger()
    record = _validated(ledger)

    active = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.ACTIVE,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="release field fix",
        policy_fingerprint=record.policy_fingerprint,
        authority_fingerprint=record.authority_fingerprint,
    )

    assert active.stage is RepairRolloutStage.ACTIVE
    assert active.release_kind is RepairReleaseKind.FIELD
    assert active.authoritative_implementation.value == "candidate"
    assert active.transition_count == 3
    transitions = ledger.transitions(active.rollout_id)
    assert transitions[-1].previous_transition_hash == transitions[-2].transition_hash
    assert transitions[-1].signature_status == "UNSIGNED"


def test_direct_field_activation_requires_operator_authority() -> None:
    ledger = _ledger()
    record = _validated(ledger)

    with pytest.raises(RepairRolloutError, match="operator authority"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.ACTIVE,
            authority_type=RepairRolloutAuthority.ADAPTIVE,
            authority_id="adaptive-1",
            reason="automatic release",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
        )


def test_staged_rollout_requires_shadow_then_canary_then_active() -> None:
    ledger = _ledger()
    record = _validated(ledger)
    common = {
        "authority_type": RepairRolloutAuthority.OPERATOR,
        "authority_id": "operator-1",
        "policy_fingerprint": record.policy_fingerprint,
        "authority_fingerprint": record.authority_fingerprint,
    }

    shadow = ledger.advance(record.rollout_id, to_stage=RepairRolloutStage.SHADOW, reason="begin shadow", **common)
    canary = ledger.advance(record.rollout_id, to_stage=RepairRolloutStage.CANARY, reason="begin canary", **common)
    active = ledger.advance(record.rollout_id, to_stage=RepairRolloutStage.ACTIVE, reason="complete canary", **common)

    assert (shadow.stage, canary.stage, active.stage) == (
        RepairRolloutStage.SHADOW,
        RepairRolloutStage.CANARY,
        RepairRolloutStage.ACTIVE,
    )


def test_policy_defined_ramp_applies_stage_routing_and_records_evidence() -> None:
    ledger = _ledger(
        ramp=RolloutRampPolicy(
            steps=(
                RolloutRampStep(
                    RepairRolloutStage.SHADOW,
                    shadow_sample_percentage=100,
                    candidate_mirror_percentage=10,
                ),
                RolloutRampStep(
                    RepairRolloutStage.CANARY,
                    canary_percentage=10,
                    candidate_mirror_percentage=20,
                ),
                RolloutRampStep(
                    RepairRolloutStage.ACTIVE,
                    active_candidate_percentage=100,
                    candidate_mirror_percentage=40,
                ),
            )
        ),
    )
    record = _validated(ledger)
    common = {
        "authority_type": RepairRolloutAuthority.OPERATOR,
        "authority_id": "operator-1",
        "policy_fingerprint": record.policy_fingerprint,
        "authority_fingerprint": record.authority_fingerprint,
        "readiness_status": "READY",
    }

    shadow = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.SHADOW,
        reason="begin policy-defined shadow ramp",
        **common,
    )
    assert shadow.routing_policy is not None
    assert shadow.routing_policy.candidate_mirror_percentage == 10
    assert shadow.routing_policy.canary_percentage == 0
    assert ledger.transitions(record.rollout_id)[-1].details["ramp_applied"] is True

    canary = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.CANARY,
        reason="begin policy-defined canary ramp",
        **common,
    )
    assert canary.routing_policy is not None
    assert canary.routing_policy.canary_percentage == 10
    assert canary.routing_policy.candidate_mirror_percentage == 20

    active = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.ACTIVE,
        reason="complete policy-defined ramp",
        **common,
    )
    assert active.routing_policy is not None
    assert active.routing_policy.active_candidate_percentage == 100
    assert active.routing_policy.candidate_mirror_percentage == 40


def test_policy_defined_ramp_increase_requires_readiness_or_override() -> None:
    ledger = _ledger(
        ramp=RolloutRampPolicy(
            steps=(RolloutRampStep(RepairRolloutStage.CANARY, canary_percentage=25),)
        )
    )
    record = _validated(ledger)

    with pytest.raises(RepairRolloutError, match="staged routing increase"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.CANARY,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="canary without readiness",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
            readiness_status="NOT_READY",
        )

    advanced = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.CANARY,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="operator overrides canary readiness",
        policy_fingerprint=record.policy_fingerprint,
        authority_fingerprint=record.authority_fingerprint,
        readiness_status="NOT_READY",
        override_readiness=True,
    )
    assert advanced.routing_policy is not None
    assert advanced.routing_policy.canary_percentage == 25
    assert ledger.transitions(record.rollout_id)[-1].details["readiness_overridden"] is True


def test_ramp_policy_rejects_duplicate_or_out_of_order_stages() -> None:
    with pytest.raises(ValueError, match="more than one step"):
        RolloutRampPolicy(
            steps=(
                RolloutRampStep(RepairRolloutStage.SHADOW, shadow_sample_percentage=10),
                RolloutRampStep(RepairRolloutStage.SHADOW, shadow_sample_percentage=20),
            )
        )
    with pytest.raises(ValueError, match="ordered"):
        RolloutRampPolicy(
            steps=(
                RolloutRampStep(RepairRolloutStage.CANARY, canary_percentage=10),
                RolloutRampStep(RepairRolloutStage.SHADOW, shadow_sample_percentage=10),
            )
        )


def test_disabled_stages_and_invalid_skips_are_rejected() -> None:
    ledger = _ledger(allow_shadow_stage=False)
    record = _validated(ledger)

    with pytest.raises(RepairRolloutError, match="shadow stage"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.SHADOW,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="shadow",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
        )

    with pytest.raises(RepairRolloutError, match="invalid rollout transition"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.RETIRED,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="skip active",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
        )


def test_active_field_fix_requires_new_incident_for_revocation() -> None:
    ledger = _ledger()
    record = _validated(ledger)
    active = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.ACTIVE,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="release",
        policy_fingerprint=record.policy_fingerprint,
        authority_fingerprint=record.authority_fingerprint,
    )
    common = {
        "to_stage": RepairRolloutStage.REVOKED,
        "authority_type": RepairRolloutAuthority.OPERATOR,
        "authority_id": "operator-1",
        "reason": "revoke after regression",
        "policy_fingerprint": active.policy_fingerprint,
        "authority_fingerprint": active.authority_fingerprint,
    }

    with pytest.raises(RepairRolloutError, match="new incident"):
        ledger.advance(active.rollout_id, **common)

    revoked = ledger.advance(active.rollout_id, incident_id=uuid4(), **common)
    assert revoked.stage is RepairRolloutStage.REVOKED


def test_only_deployment_authority_can_promote_field_fix_to_permanent() -> None:
    ledger = _ledger()
    record = _validated(ledger)
    active = ledger.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.ACTIVE,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="field release",
        policy_fingerprint=record.policy_fingerprint,
        authority_fingerprint=record.authority_fingerprint,
    )

    with pytest.raises(RepairRolloutError, match="deployment"):
        ledger.promote_permanent(
            active.rollout_id,
            authority_id="operator-1",
            authority_type=RepairRolloutAuthority.OPERATOR,
            policy_fingerprint=active.policy_fingerprint,
            authority_fingerprint=active.authority_fingerprint,
            deployment_artifact_hash="deployment-hash",
            reason="operator cannot make permanent",
        )

    permanent = ledger.promote_permanent(
        active.rollout_id,
        authority_id="deployment-1",
        policy_fingerprint=active.policy_fingerprint,
        authority_fingerprint=active.authority_fingerprint,
        deployment_artifact_hash="deployment-hash",
        reason="signed deployment accepted",
    )
    assert permanent.stage is RepairRolloutStage.ACTIVE
    assert permanent.release_kind is RepairReleaseKind.PERMANENT
    assert permanent.deployment_artifact_hash == "deployment-hash"
    assert permanent.authoritative_implementation.value == "deployed"


def test_stale_context_and_expired_authority_fail_closed() -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    current_time = [now]
    ledger = _ledger(clock=lambda: current_time[0])
    record = ledger.create(expires_at=now + timedelta(minutes=1), target_id="example.target", proposed_by="operator-1", **_ids())

    with pytest.raises(RepairRolloutError, match="policy fingerprint"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.VALIDATED,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="stale policy",
            policy_fingerprint="different",
            authority_fingerprint=record.authority_fingerprint,
            validation_evidence_hash="validation-hash",
        )

    current_time[0] = now + timedelta(minutes=2)
    with pytest.raises(RepairRolloutError, match="expired"):
        ledger.advance(
            record.rollout_id,
            to_stage=RepairRolloutStage.VALIDATED,
            authority_type=RepairRolloutAuthority.OPERATOR,
            authority_id="operator-1",
            reason="late validation",
            policy_fingerprint=record.policy_fingerprint,
            authority_fingerprint=record.authority_fingerprint,
            validation_evidence_hash="validation-hash",
        )


def test_sqlite_store_rehydrates_rollout_and_immutable_transition_history(tmp_path) -> None:
    store = SQLiteRepairStore(tmp_path / "repair.sqlite")
    first = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        store=store,
    )
    record = _validated(first)
    first.advance(
        record.rollout_id,
        to_stage=RepairRolloutStage.ACTIVE,
        authority_type=RepairRolloutAuthority.OPERATOR,
        authority_id="operator-1",
        reason="field release",
        policy_fingerprint=record.policy_fingerprint,
        authority_fingerprint=record.authority_fingerprint,
    )

    reopened = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        store=SQLiteRepairStore(tmp_path / "repair.sqlite"),
    )

    restored = reopened.get(record.rollout_id)
    assert restored.stage is RepairRolloutStage.ACTIVE
    assert restored.release_kind is RepairReleaseKind.FIELD
    assert len(reopened.transitions(record.rollout_id)) == 3


def test_runtime_signer_is_attached_to_rollout_transitions_when_configured(tmp_path) -> None:
    from caretaker.logging import (
        RuntimeArtifactSigningService,
        RuntimeRecordIntegrityMode,
        RuntimeSigningPolicy,
    )

    signer = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="rollout-test",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    try:
        ledger = RepairRolloutLedger(
            policy=RepairRolloutPolicy(enabled=True),
            signer=signer,
        )
        record = _proposed(ledger)
        transition = ledger.transitions(record.rollout_id)[0]
        assert transition.signature_status == "EPHEMERAL_SIGNED"
        assert transition.signature is not None
    finally:
        signer.close()


def test_rollout_transitions_can_be_emitted_to_the_registered_audit_stream() -> None:
    events: list[tuple[str, dict[str, object]]] = []

    def audit_event(event_type: str, **fields: object) -> None:
        events.append((event_type, fields))

    ledger = RepairRolloutLedger(
        policy=RepairRolloutPolicy(enabled=True),
        audit_event=audit_event,
    )
    record = _proposed(ledger)

    assert len(events) == 1
    event_type, fields = events[0]
    assert event_type == "REPAIR_ROLLOUT_TRANSITION"
    assert fields["scope"]["rollout_id"] == str(record.rollout_id)
    assert fields["scope"]["transition_id"]
    assert fields["outcome"]["state"] == "proposed"
    assert fields["details"]["transition_hash"]
