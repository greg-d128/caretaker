from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from caretaker import (
    ComparisonWorkerComparisonReport,
    ComparisonWorkerResult,
    InMemoryRepairStore,
    SQLiteRepairStore,
    RepairRecoveryPolicy,
    create_comparison_worker_assignment,
    create_comparison_worker_result,
    create_recovery_authority_packet,
    worker_failure_recovery_status,
    compare_comparison_worker_result,
    verify_comparison_worker_assignment,
    verify_comparison_worker_result,
)
from caretaker.logging import CaretakerApplicationSupervisor, WorkerKind


class _Audit:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def emit(self, event_type: str, **kwargs: object) -> None:
        self.events.append({"event_type": event_type, **kwargs})


class _Runtime:
    def __init__(self) -> None:
        self.audit = _Audit()


def _packet(now: datetime, *, ttl: int = 3600):
    return create_recovery_authority_packet(
        target_id="app:charge",
        generation_id="generation-1",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-1",
        authority_policy_fingerprint="authority-hash",
        capabilities=("observe",),
        policy_state={"mode": "observe"},
        approvals={"operator": True},
        supervisor_time=now,
        policy=RepairRecoveryPolicy(approval_packet_ttl_seconds=ttl),
    )


def _assignment(now: datetime):
    packet = _packet(now)
    assignment = create_comparison_worker_assignment(
        packet,
        scope="incident:123",
        evidence_refs=("worker-failure:1", "worker-failure:2"),
        supervisor_time=now,
        policy=RepairRecoveryPolicy(),
    )
    return packet, assignment


def test_comparison_assignment_is_context_bound_and_content_hashed() -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)

    verified = verify_comparison_worker_assignment(
        assignment,
        packet,
        supervisor_time=now + timedelta(seconds=1),
        target_id="app:charge",
        generation_id="generation-1",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-1",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )

    assert verified["valid"] is True
    assert verified["authority_granted"] is False
    assert assignment.expires_at == packet.expires_at

    stale = verify_comparison_worker_assignment(
        assignment,
        packet,
        supervisor_time=now + timedelta(seconds=1),
        target_id="app:other",
        generation_id="generation-1",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-1",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
    )
    assert stale["valid"] is False
    assert "CONTEXT_MISMATCH:target_id" in stale["failures"]


def test_expired_packet_cannot_issue_comparison_assignment() -> None:
    now = datetime.now(timezone.utc)
    packet = _packet(now, ttl=1)

    with pytest.raises(PermissionError, match="packet rejected"):
        create_comparison_worker_assignment(
            packet,
            scope="incident:123",
            supervisor_time=now + timedelta(seconds=1),
        )


def test_comparison_result_is_bounded_and_tamper_evident() -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)
    result = create_comparison_worker_result(
        assignment,
        worker_id="worker-1",
        evidence={"comparison": "compatible", "sample_count": 42},
        observed_at=now,
    )

    verified = verify_comparison_worker_result(
        result,
        assignment=assignment,
        worker_id="worker-1",
        supervisor_time=now + timedelta(seconds=1),
    )
    assert verified["valid"] is True
    assert verified["authority_granted"] is False

    tampered = {
        "result_id": result.result_id,
        "assignment_id": result.assignment_id,
        "worker_id": result.worker_id,
        "status": result.status,
        "evidence": {"comparison": "different"},
        "observed_at": result.observed_at,
        "content_sha256": result.content_sha256,
        "schema_version": result.schema_version,
    }
    invalid = verify_comparison_worker_result(
        tampered,
        assignment=assignment,
        worker_id="worker-1",
    )
    assert invalid["valid"] is False
    assert "RESULT_CONTENT_HASH_MISMATCH" in invalid["failures"]

    with pytest.raises(ValueError, match="JSON-shaped"):
        create_comparison_worker_result(
            assignment,
            worker_id="worker-1",
            evidence={"not_json": object()},
        )


def test_comparison_assignment_and_result_store_round_trip(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)
    result = create_comparison_worker_result(
        assignment,
        worker_id="worker-1",
        evidence={"comparison": "compatible"},
        observed_at=now,
    )
    for store in (InMemoryRepairStore(), SQLiteRepairStore(tmp_path / "repair.sqlite")):
        store.record_comparison_worker_assignment(assignment)
        store.record_comparison_worker_result(result)
        assert len(store.all_comparison_worker_assignments()) == 1
        assert len(store.all_comparison_worker_results()) == 1
        stored_assignment = store.all_comparison_worker_assignments()[0]
        stored_result = store.all_comparison_worker_results()[0]
        assignment_check = verify_comparison_worker_assignment(
            stored_assignment,
            packet,
            supervisor_time=now + timedelta(seconds=1),
            target_id="app:charge",
            generation_id="generation-1",
            code_hash="code-hash",
            policy_fingerprint="policy-hash",
            authority_policy_generation="authority-1",
            authority_policy_fingerprint="authority-hash",
            allowed_capabilities={"observe"},
        )
        result_check = verify_comparison_worker_result(
            stored_result,
            assignment=stored_assignment,
            worker_id="worker-1",
        )
        assert assignment_check["valid"] is True
        assert result_check["valid"] is True


def test_supervisor_accepts_only_registered_packet_bound_comparison_worker() -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)
    runtime = _Runtime()
    store = InMemoryRepairStore()
    supervisor = CaretakerApplicationSupervisor(runtime, failure_store=store)
    worker = supervisor.workers.register_authorized(
        WorkerKind.REPAIR_ANALYZER,
        4321,
        packet,
        supervisor_time=now,
        target_id="app:charge",
        generation_id="generation-1",
        code_hash="code-hash",
        policy_fingerprint="policy-hash",
        authority_policy_generation="authority-1",
        authority_policy_fingerprint="authority-hash",
        allowed_capabilities={"observe"},
        policy=RepairRecoveryPolicy(),
    )
    supervisor.issue_comparison_worker_assignment(
        packet,
        scope=assignment.scope,
        evidence_refs=assignment.evidence_refs,
        supervisor_time=now,
        policy=RepairRecoveryPolicy(),
        store=store,
    )
    result = create_comparison_worker_result(
        assignment,
        worker_id=str(worker.worker_id),
        evidence={"comparison": "compatible", "sample_count": 30},
        observed_at=now,
    )

    accepted = supervisor.accept_comparison_worker_result(
        assignment,
        packet,
        result,
        supervisor_time=now + timedelta(seconds=1),
        worker_process_id=worker.process_id,
        worker_process_start_id=worker.process_start_id,
        allowed_capabilities={"observe"},
        policy=RepairRecoveryPolicy(),
        store=store,
    )

    assert accepted["accepted"] is True
    assert accepted["authority_granted"] is False
    assert len(store.all_comparison_worker_results()) == 1
    assert [item["event_type"] for item in runtime.audit.events] == [
        "WORKER_AUTHORITY_ISSUED",
        "WORKER_COMPARISON_ASSIGNMENT",
        "WORKER_COMPARISON_RESULT",
    ]

    with pytest.raises(PermissionError, match="process identity"):
        supervisor.accept_comparison_worker_result(
            assignment,
            packet,
            result,
            supervisor_time=now + timedelta(seconds=1),
            worker_process_id=9999,
            worker_process_start_id=worker.process_start_id,
            allowed_capabilities={"observe"},
            policy=RepairRecoveryPolicy(),
            store=store,
        )


def _signature(mean: float, *, source_id: str) -> dict[str, object]:
    return {
        "source_id": source_id,
        "behavior_signature": {
            "sample_count": 30,
            "metrics": {
                "duration_ms": {
                    "mean": mean,
                    "standard_deviation": 1.0,
                }
            },
        },
    }


def test_comparison_worker_signatures_combine_or_retain_outliers() -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)
    result = create_comparison_worker_result(
        assignment,
        worker_id="worker-independent",
        evidence={
            "behavior_signature": {
                "sample_count": 30,
                "metrics": {
                    "duration_ms": {
                        "mean": 10.05,
                        "standard_deviation": 1.0,
                    }
                },
            }
        },
        observed_at=now,
    )

    combined = compare_comparison_worker_result(
        result,
        assignment=assignment,
        baseline_signatures=(_signature(10.0, source_id="worker-a"), _signature(10.1, source_id="worker-b")),
    )
    assert isinstance(combined, ComparisonWorkerComparisonReport)
    assert combined.status == "COMBINED"
    assert combined.baseline_count == 2
    assert combined.outliers == ()
    assert combined.content_sha256
    assert combined.comparison_id

    conflict = compare_comparison_worker_result(
        result,
        assignment=assignment,
        baseline_signatures=(_signature(100.0, source_id="worker-a"),),
    )
    assert conflict.status == "CONFLICT"
    assert len(conflict.outliers) == 2


def test_comparison_worker_signature_gaps_are_incomplete_not_agreement() -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)
    result = create_comparison_worker_result(
        assignment,
        worker_id="worker-independent",
        evidence={"summary": "no signature"},
        observed_at=now,
    )
    report = compare_comparison_worker_result(
        result,
        assignment=assignment,
        baseline_signatures=(_signature(10.0, source_id="worker-a"),),
    )
    assert report.status == "INCOMPLETE_EVIDENCE"
    assert report.outliers == ()
    assert any("behavior_signature" in reason for reason in report.reasons)


def test_supervisor_persists_comparison_report_and_status_is_bounded() -> None:
    now = datetime.now(timezone.utc)
    packet, assignment = _assignment(now)
    runtime = _Runtime()
    store = InMemoryRepairStore()
    supervisor = CaretakerApplicationSupervisor(runtime, failure_store=store)
    result = create_comparison_worker_result(
        assignment,
        worker_id="worker-independent",
        evidence={
            "behavior_signature": {
                "sample_count": 30,
                "metrics": {
                    "duration_ms": {"mean": 10.0, "standard_deviation": 1.0}
                },
            }
        },
        observed_at=now,
    )
    report = supervisor.compare_comparison_worker_result(
        assignment,
        result,
        baseline_signatures=(_signature(10.0, source_id="worker-a"),),
        compared_at=now,
        store=store,
    )
    assert report.status == "COMBINED"
    assert len(store.all_comparison_worker_comparisons()) == 1
    status = worker_failure_recovery_status(store)
    assert status["comparison_report_count"] == 1
    assert status["comparison_reports"][0]["status"] == "COMBINED"
    assert status["comparison_reports"][0]["outlier_count"] == 0
    assert runtime.audit.events[-1]["event_type"] == "WORKER_COMPARISON_RECONCILED"
