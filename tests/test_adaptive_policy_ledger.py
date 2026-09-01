from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from caretaker.adaptive_aggregation import (
    AdaptiveAggregationError,
    SupervisorAdaptiveAggregationStore,
    verify_adaptive_policy_acceptance_signature,
    verify_adaptive_policy_transition_signature,
)
from caretaker.logging import RuntimeArtifactSigningService, RuntimeRecordIntegrityMode, RuntimeSigningPolicy


def _approved_proposal(store: SupervisorAdaptiveAggregationStore) -> dict[str, object]:
    context = {
        "current_generations": {"payments.charge": "generation-1"},
        "policy_fingerprints": {"payments.charge": "policy-old"},
        "authority_policy_generation": "4",
        "authority_policy_fingerprint": "authority-old",
    }
    proposal = store.create_threshold_proposal(
        target_id="payments.charge",
        generation_id="generation-1",
        code_hash="code-1",
        monitoring_fingerprint="monitoring-1",
        policy_fingerprint="policy-old",
        authority_policy_generation="4",
        authority_policy_fingerprint="authority-old",
        changes={"exception.occurrences": 4},
        requested_by="operator:1001",
        reason="reviewed threshold adjustment",
        effective_after_seconds=0,
        expires_in_seconds=3600,
    )
    created = datetime.fromisoformat(str(proposal["created_at"]))
    store.review_threshold_proposal(
        str(proposal["request_id"]),
        decision="APPROVE",
        reviewed_by="uid:1001",
        reason="approved for staged application",
        now=created,
        **context,
    )
    return proposal


def _transition(
    store: SupervisorAdaptiveAggregationStore,
    *,
    now: datetime,
    artifact_signer: object | None = None,
) -> dict[str, object]:
    proposal = _approved_proposal(store)
    return store.create_threshold_policy_transition(
        str(proposal["request_id"]),
        applied_policy_fingerprint="policy-new",
        current_generations={"payments.charge": "generation-1"},
        current_policy_fingerprints={"payments.charge": "policy-new"},
        authority_policy_generation="5",
        authority_policy_fingerprint="authority-new",
        required_workers=[{"worker_id": "worker-a", "worker_pid": 101}],
        applied_by="uid:1001",
        reason="apply reviewed threshold",
        authority_type="operator",
        authority_lease_id="00000000-0000-0000-0000-000000000005",
        authority_expires_at="2030-01-02T00:00:00+00:00",
        now=now,
        effective_at=now,
        artifact_signer=artifact_signer,
    )


def test_runtime_signer_binds_adaptive_transition_and_identity_journal(tmp_path: Path) -> None:
    service = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="payments",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path,
    )
    transition = _transition(
        SupervisorAdaptiveAggregationStore(tmp_path / "ledger"),
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        artifact_signer=service,
    )

    assert transition["signature_status"] == "EPHEMERAL_SIGNED"
    assert isinstance(transition["signature"], dict)
    verified = verify_adaptive_policy_transition_signature(
        transition,
        identity_journal=service.journal,
    )
    assert verified["valid"] is True, verified
    assert verified["signer_mode"] == "EPHEMERAL_SIGNED"

    tampered = dict(transition)
    tampered["change_description"] = "forged change"
    assert verify_adaptive_policy_transition_signature(
        tampered,
        identity_journal=service.journal,
    )["valid"] is False
    service.close()


def test_policy_ledger_records_lineage_and_survives_restart(tmp_path: Path) -> None:
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=now)

    pending = store.list_policy_transition_ledger(
        transition_id=str(transition["transition_id"])
    )
    assert len(pending) == 1
    assert pending[0]["status"] == "PENDING"
    assert pending[0]["authority_type"] == "operator"
    assert pending[0]["prior_policy_id"]
    assert pending[0]["policy_id"]
    assert pending[0]["prior_policy_fingerprint"] == "policy-old"
    assert pending[0]["policy_fingerprint"] == "policy-new"
    assert pending[0]["fields_affected"] == ["exception.occurrences"]
    assert pending[0]["signature_status"] == "UNSIGNED"
    assert pending[0]["effective_at"] == now.isoformat()

    acknowledgement = store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations={"payments.charge": "generation-1"},
        policy_fingerprints={"payments.charge": "policy-new"},
        authority_policy_generation="5",
        authority_policy_fingerprint="authority-new",
    )
    assert acknowledgement["transition_status"] == "APPLIED"
    records = SupervisorAdaptiveAggregationStore(tmp_path).list_policy_transition_ledger(
        transition_id=str(transition["transition_id"])
    )
    assert {str(item["status"]) for item in records} == {"PENDING", "APPLIED"}
    assert next(item for item in records if item["status"] == "APPLIED")["acknowledgement_count"] == 1


def test_adaptive_actor_cannot_activate_policy_transition(tmp_path: Path) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    proposal = _approved_proposal(store)
    with pytest.raises(PermissionError, match="cannot activate"):
        store.create_threshold_policy_transition(
            str(proposal["request_id"]),
            applied_policy_fingerprint="policy-new",
            current_generations={"payments.charge": "generation-1"},
            current_policy_fingerprints={"payments.charge": "policy-new"},
            authority_policy_generation="5",
            authority_policy_fingerprint="authority-new",
            required_workers=[{"worker_id": "worker-b", "worker_pid": 102}],
            applied_by="adaptive:proposal",
            reason="not authorized",
            authority_type="adaptive",
        )


def test_operator_acceptance_is_durable_signed_and_does_not_mutate_policy(
    tmp_path: Path,
) -> None:
    service = RuntimeArtifactSigningService(
        policy=RuntimeSigningPolicy(
            mode=RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED,
            run_signer_in_separate_process=False,
        ),
        application_id="payments",
        run_id=uuid4(),
        process_start_id=uuid4(),
        root=tmp_path / "signing",
    )
    store = SupervisorAdaptiveAggregationStore(tmp_path / "ledger")
    transition = _transition(
        store,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
        artifact_signer=service,
    )
    assert store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations={"payments.charge": "generation-1"},
        policy_fingerprints={"payments.charge": "policy-new"},
        authority_policy_generation="5",
        authority_policy_fingerprint="authority-new",
    )["transition_status"] == "APPLIED"

    acceptance = store.record_policy_transition_acceptance(
        str(transition["transition_id"]),
        accepted_by="uid:1001",
        reason="operator accepted for deployment handoff",
        policy_allows_persistent_acceptance=True,
        current_generations={"payments.charge": "generation-1"},
        current_policy_fingerprints={"payments.charge": "policy-new"},
        authority_policy_generation="5",
        authority_policy_fingerprint="authority-new",
        now=datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        artifact_signer=service,
    )
    assert acceptance["policy_mutated"] is False
    assert acceptance["authority_granted"] is False
    assert acceptance["signature_status"] == "EPHEMERAL_SIGNED"
    assert verify_adaptive_policy_transition_signature(
        transition, identity_journal=service.journal
    )["valid"] is True
    assert verify_adaptive_policy_acceptance_signature(
        acceptance, identity_journal=service.journal
    )["valid"] is True
    assert store.list_policy_transition_acceptances(
        transition_id=str(transition["transition_id"])
    )[0]["acceptance_id"] == acceptance["acceptance_id"]
    visible = store.list_transition_requests(request_id=str(transition["request_id"]))[0]
    assert visible["acceptance_status"] == "ACCEPTED"
    assert visible["acceptance"]["acceptance_id"] == acceptance["acceptance_id"]

    duplicate = store.record_policy_transition_acceptance(
        str(transition["transition_id"]),
        accepted_by="uid:1001",
        reason="different retry text is ignored",
        policy_allows_persistent_acceptance=True,
        current_generations={"payments.charge": "generation-1"},
        current_policy_fingerprints={"payments.charge": "policy-new"},
        authority_policy_generation="5",
        authority_policy_fingerprint="authority-new",
        now=datetime(2030, 1, 1, 0, 0, 31, tzinfo=timezone.utc),
    )
    assert duplicate["duplicate"] is True
    service.close()


def test_persistent_acceptance_requires_policy_and_live_authority(tmp_path: Path) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    with pytest.raises(PermissionError, match="disabled by policy"):
        store.record_policy_transition_acceptance(
            str(transition["transition_id"]),
            accepted_by="uid:1001",
            reason="not enabled",
            policy_allows_persistent_acceptance=False,
            current_generations={"payments.charge": "generation-1"},
            current_policy_fingerprints={"payments.charge": "policy-new"},
            authority_policy_generation="5",
            authority_policy_fingerprint="authority-new",
        )
    with pytest.raises(PermissionError, match="must be APPLIED"):
        store.record_policy_transition_acceptance(
            str(transition["transition_id"]),
            accepted_by="uid:1001",
            reason="not applied",
            policy_allows_persistent_acceptance=True,
            current_generations={"payments.charge": "generation-1"},
            current_policy_fingerprints={"payments.charge": "policy-new"},
            authority_policy_generation="5",
            authority_policy_fingerprint="authority-new",
        )

    expired_store = SupervisorAdaptiveAggregationStore(tmp_path / "expired")
    expired = _transition(
        expired_store,
        now=datetime(2030, 1, 1, tzinfo=timezone.utc),
    )
    expired_store.acknowledge_transition(
        {
            **expired,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations={"payments.charge": "generation-1"},
        policy_fingerprints={"payments.charge": "policy-new"},
        authority_policy_generation="5",
        authority_policy_fingerprint="authority-new",
    )
    with pytest.raises(PermissionError, match="authority has expired"):
        expired_store.record_policy_transition_acceptance(
            str(expired["transition_id"]),
            accepted_by="uid:1001",
            reason="too late",
            policy_allows_persistent_acceptance=True,
            current_generations={"payments.charge": "generation-1"},
            current_policy_fingerprints={"payments.charge": "policy-new"},
            authority_policy_generation="5",
            authority_policy_fingerprint="authority-new",
            now=datetime(2030, 1, 3, tzinfo=timezone.utc),
        )


def test_deployment_installs_accepted_policy_through_explicit_callback(
    tmp_path: Path,
) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    context = {
        "current_generations": {"payments.charge": "generation-1"},
        "current_policy_fingerprints": {"payments.charge": "policy-new"},
        "authority_policy_generation": "5",
        "authority_policy_fingerprint": "authority-new",
    }
    store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations=context["current_generations"],
        policy_fingerprints=context["current_policy_fingerprints"],
        authority_policy_generation=context["authority_policy_generation"],
        authority_policy_fingerprint=context["authority_policy_fingerprint"],
    )
    acceptance = store.record_policy_transition_acceptance(
        str(transition["transition_id"]),
        accepted_by="uid:1001",
        reason="operator accepted for deployment",
        policy_allows_persistent_acceptance=True,
        now=datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        **context,
    )
    calls: list[dict[str, object]] = []

    def installer(packet: dict[str, object]) -> dict[str, object]:
        calls.append(packet)
        return {
            "accepted": True,
            "policy_fingerprint": "policy-new",
            "deployment_artifact_hash": "sha256:deployment-artifact",
        }

    installed = store.install_policy_acceptance(
        str(acceptance["acceptance_id"]),
        deployment_authority_id="deployment:production",
        deployment_authority_fingerprint="deployment-authority-fingerprint",
        installer=installer,
        reason="install reviewed policy in the next deployment",
        now=datetime(2030, 1, 1, 0, 0, 45, tzinfo=timezone.utc),
        **context,
    )

    assert installed["status"] == "INSTALLED"
    assert installed["policy_mutated"] is False
    assert installed["authority_granted"] is False
    assert installed["deployment_artifact_hash"] == "sha256:deployment-artifact"
    assert calls[0]["acceptance_id"] == acceptance["acceptance_id"]
    assert calls[0]["policy_fingerprint"] == "policy-new"
    assert "signature" not in calls[0]
    listed = store.list_policy_installations(
        acceptance_id=str(acceptance["acceptance_id"])
    )
    assert len(listed) == 2
    assert {item["status"] for item in listed} == {"PENDING", "INSTALLED"}

    def should_not_run(_packet: dict[str, object]) -> dict[str, object]:
        raise AssertionError("completed deployment installation was replayed")

    duplicate = store.install_policy_acceptance(
        str(acceptance["acceptance_id"]),
        deployment_authority_id="deployment:production",
        deployment_authority_fingerprint="deployment-authority-fingerprint",
        installer=should_not_run,
        reason="retry completed installation",
        now=datetime(2030, 1, 1, 0, 0, 50, tzinfo=timezone.utc),
        **context,
    )
    assert duplicate["status"] == "INSTALLED"
    assert duplicate["duplicate"] is True


def test_deployment_installation_rejects_bad_callback_and_stale_context(
    tmp_path: Path,
) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    context = {
        "current_generations": {"payments.charge": "generation-1"},
        "current_policy_fingerprints": {"payments.charge": "policy-new"},
        "authority_policy_generation": "5",
        "authority_policy_fingerprint": "authority-new",
    }
    store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations=context["current_generations"],
        policy_fingerprints=context["current_policy_fingerprints"],
        authority_policy_generation=context["authority_policy_generation"],
        authority_policy_fingerprint=context["authority_policy_fingerprint"],
    )
    acceptance = store.record_policy_transition_acceptance(
        str(transition["transition_id"]),
        accepted_by="uid:1001",
        reason="operator accepted for deployment",
        policy_allows_persistent_acceptance=True,
        now=datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        **context,
    )
    rejected = store.install_policy_acceptance(
        str(acceptance["acceptance_id"]),
        deployment_authority_id="deployment:production",
        deployment_authority_fingerprint="deployment-authority-fingerprint",
        installer=lambda _packet: {
            "accepted": True,
            "policy_fingerprint": "policy-forged",
            "deployment_artifact_hash": "sha256:artifact",
        },
        reason="bad callback result",
        now=datetime(2030, 1, 1, 0, 0, 45, tzinfo=timezone.utc),
        **context,
    )
    assert rejected["status"] == "REJECTED"
    assert rejected["handler_status"] == "POLICY_FINGERPRINT_MISMATCH"

    with pytest.raises(PermissionError, match="context is stale"):
        store.install_policy_acceptance(
            str(acceptance["acceptance_id"]),
            deployment_authority_id="deployment:production",
            deployment_authority_fingerprint="deployment-authority-fingerprint",
            installer=lambda _packet: {"accepted": True},
            reason="stale context",
            now=datetime(2030, 1, 1, 0, 0, 46, tzinfo=timezone.utc),
            current_generations=context["current_generations"],
            current_policy_fingerprints={"payments.charge": "policy-old"},
            authority_policy_generation=context["authority_policy_generation"],
            authority_policy_fingerprint=context["authority_policy_fingerprint"],
        )


def test_deployment_installation_audit_is_output_only(tmp_path: Path) -> None:
    events: list[tuple[str, dict[str, object]]] = []
    store = SupervisorAdaptiveAggregationStore(
        tmp_path,
        audit_event=lambda event_type, **fields: events.append(
            (str(event_type), dict(fields))
        ),
    )
    transition = _transition(store, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    context = {
        "current_generations": {"payments.charge": "generation-1"},
        "current_policy_fingerprints": {"payments.charge": "policy-new"},
        "authority_policy_generation": "5",
        "authority_policy_fingerprint": "authority-new",
    }
    store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations=context["current_generations"],
        policy_fingerprints=context["current_policy_fingerprints"],
        authority_policy_generation=context["authority_policy_generation"],
        authority_policy_fingerprint=context["authority_policy_fingerprint"],
    )
    acceptance = store.record_policy_transition_acceptance(
        str(transition["transition_id"]),
        accepted_by="uid:1001",
        reason="operator accepted for deployment",
        policy_allows_persistent_acceptance=True,
        now=datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        **context,
    )
    store.install_policy_acceptance(
        str(acceptance["acceptance_id"]),
        deployment_authority_id="deployment:production",
        deployment_authority_fingerprint="deployment-authority-fingerprint",
        installer=lambda _packet: {
            "accepted": True,
            "policy_fingerprint": "policy-new",
            "deployment_artifact_hash": "sha256:deployment-artifact",
        },
        reason="install reviewed policy",
        now=datetime(2030, 1, 1, 0, 0, 45, tzinfo=timezone.utc),
        **context,
    )
    installation_events = [
        fields for event_type, fields in events
        if event_type == "ADAPTIVE_POLICY_INSTALLATION"
    ]
    assert [item["outcome"]["state"] for item in installation_events] == [
        "PENDING",
        "INSTALLED",
    ]
    assert all(
        item["outcome"]["authority_granted"] is False
        and item["outcome"]["policy_mutated"] is False
        for item in installation_events
    )


def test_pending_deployment_installation_can_be_reconciled_without_replay(
    tmp_path: Path,
) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    context = {
        "current_generations": {"payments.charge": "generation-1"},
        "current_policy_fingerprints": {"payments.charge": "policy-new"},
        "authority_policy_generation": "5",
        "authority_policy_fingerprint": "authority-new",
    }
    store.acknowledge_transition(
        {
            **transition,
            "worker_id": "worker-a",
            "applied": True,
            "observed_level": "POLICY",
        },
        peer_pid=101,
        current_generations=context["current_generations"],
        policy_fingerprints=context["current_policy_fingerprints"],
        authority_policy_generation=context["authority_policy_generation"],
        authority_policy_fingerprint=context["authority_policy_fingerprint"],
    )
    acceptance = store.record_policy_transition_acceptance(
        str(transition["transition_id"]),
        accepted_by="uid:1001",
        reason="operator accepted for deployment",
        policy_allows_persistent_acceptance=True,
        now=datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        **context,
    )

    def interrupted_installer(_packet: dict[str, object]) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        store.install_policy_acceptance(
            str(acceptance["acceptance_id"]),
            deployment_authority_id="deployment:production",
            deployment_authority_fingerprint="deployment-authority-fingerprint",
            installer=interrupted_installer,
            reason="deployment process stopped during install",
            now=datetime(2030, 1, 1, 0, 0, 45, tzinfo=timezone.utc),
            **context,
        )
    pending = store.list_policy_installations(
        acceptance_id=str(acceptance["acceptance_id"])
    )
    assert len(pending) == 1
    installation_id = str(pending[0]["installation_id"])

    reconciled = store.reconcile_policy_installation(
        installation_id,
        deployment_authority_id="deployment:production",
        deployment_authority_fingerprint="deployment-authority-fingerprint",
        observed_state="INSTALLED",
        observed_policy_fingerprint="policy-new",
        deployment_artifact_hash="sha256:deployment-artifact",
        reason="deployment verified the artifact after restart",
        now=datetime(2030, 1, 3, tzinfo=timezone.utc),
    )
    assert reconciled["status"] == "RECONCILED"
    assert reconciled["observed_state"] == "INSTALLED"
    assert reconciled["external_install_observed"] is True
    assert reconciled["authority_granted"] is False

    duplicate = store.reconcile_policy_installation(
        installation_id,
        deployment_authority_id="deployment:production",
        deployment_authority_fingerprint="deployment-authority-fingerprint",
        observed_state="INSTALLED",
        observed_policy_fingerprint="policy-new",
        deployment_artifact_hash="sha256:deployment-artifact",
        reason="deployment verified the artifact after restart",
        now=datetime(2030, 1, 3, 0, 0, 1, tzinfo=timezone.utc),
    )
    assert duplicate["duplicate"] is True

    with pytest.raises(AdaptiveAggregationError, match="conflicting"):
        store.reconcile_policy_installation(
            installation_id,
            deployment_authority_id="deployment:production",
            deployment_authority_fingerprint="deployment-authority-fingerprint",
            observed_state="UNKNOWN",
            reason="conflicting retry",
            now=datetime(2030, 1, 3, 0, 0, 2, tzinfo=timezone.utc),
        )


def test_tampered_policy_ledger_is_not_returned(tmp_path: Path) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=datetime.now(timezone.utc))
    path = next((tmp_path / "adaptive" / "policy-ledger").glob("*.json"))
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["record"]["status"] = "FORGED"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(AdaptiveAggregationError, match="hash is invalid"):
        store.list_policy_transition_ledger(transition_id=str(transition["transition_id"]))
