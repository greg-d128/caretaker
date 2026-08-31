from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from caretaker.adaptive_aggregation import (
    AdaptiveAggregationError,
    SupervisorAdaptiveAggregationStore,
)


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


def _transition(store: SupervisorAdaptiveAggregationStore, *, now: datetime) -> dict[str, object]:
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
        authority_expires_at="2030-01-01T00:00:00+00:00",
        now=now,
        effective_at=now,
    )


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


def test_tampered_policy_ledger_is_not_returned(tmp_path: Path) -> None:
    store = SupervisorAdaptiveAggregationStore(tmp_path)
    transition = _transition(store, now=datetime.now(timezone.utc))
    path = next((tmp_path / "adaptive" / "policy-ledger").glob("*.json"))
    envelope = json.loads(path.read_text(encoding="utf-8"))
    envelope["record"]["status"] = "FORGED"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(AdaptiveAggregationError, match="hash is invalid"):
        store.list_policy_transition_ledger(transition_id=str(transition["transition_id"]))
