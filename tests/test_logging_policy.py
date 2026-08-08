from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from caretaker.logging import (
    CapturePolicy,
    LoggingCapability,
    LoggingMode,
    ModeLeaseManager,
    OperatorLoggingPolicy,
    PolicyConflictAction,
)
from caretaker.logging.policy import policy_snapshot, reconcile_policy


def test_higher_mode_applies_explicit_required_overrides():
    policy = OperatorLoggingPolicy(
        capture=CapturePolicy(capabilities=frozenset({LoggingCapability.APPLICATION_LOGS})),
        modes=(LoggingMode.APPLICATION,),
        conflict_action=PolicyConflictAction.APPLY_REQUIRED_OVERRIDES,
    )
    snapshot = policy_snapshot(policy)
    effective = reconcile_policy(policy, snapshot, requested_modes=(LoggingMode.APPLICATION, LoggingMode.GUARD))
    assert LoggingCapability.GUARD_DECISIONS in effective.effective_policy.capture.capabilities
    assert effective.overrides
    assert any(LoggingMode.GUARD in override.required_by_modes for override in effective.overrides)


def test_refuse_higher_mode_does_not_silently_degrade():
    policy = OperatorLoggingPolicy(
        capture=CapturePolicy(capabilities=frozenset({LoggingCapability.APPLICATION_LOGS})),
        modes=(LoggingMode.APPLICATION,),
        conflict_action=PolicyConflictAction.REFUSE_HIGHER_MODE,
    )
    effective = reconcile_policy(policy, policy_snapshot(policy), requested_modes=(LoggingMode.APPLICATION, LoggingMode.REPAIR))
    assert LoggingMode.REPAIR not in effective.effective_modes
    assert effective.warnings


def test_mode_lease_reverts_only_lease_overlay():
    policy = OperatorLoggingPolicy(
        capture=CapturePolicy(capabilities=frozenset({LoggingCapability.APPLICATION_LOGS})),
    )
    manager = ModeLeaseManager(policy, policy_snapshot(policy))
    lease = manager.acquire(LoggingMode.RESEARCH, requested_by="admin", reason="incident")
    assert LoggingMode.RESEARCH in manager.effective.effective_modes
    manager.release(lease.lease_id)
    assert LoggingMode.RESEARCH not in manager.effective.effective_modes
    assert manager.effective.effective_modes == (LoggingMode.APPLICATION,)


def test_expired_mode_lease_is_removed():
    policy = OperatorLoggingPolicy()
    manager = ModeLeaseManager(policy, policy_snapshot(policy))
    lease = manager.acquire(
        LoggingMode.REPAIR,
        requested_by="admin",
        reason="temporary repair",
        duration_seconds=0.001,
    )
    expired = manager.expire(datetime.now(timezone.utc) + timedelta(seconds=1))
    assert lease.lease_id in expired
    assert LoggingMode.REPAIR not in manager.effective.effective_modes


def test_policy_snapshot_is_unsigned_but_attributable(tmp_path):
    path = tmp_path / "logging.toml"
    path.write_text('[logging]\napplication_id="demo"\ndirectory="./data"\n')
    from caretaker.logging.policy import load_operator_policy
    policy, snapshot = load_operator_policy(path)
    assert policy.application_id == "demo"
    assert snapshot.source_path == str(path)
    assert len(snapshot.content_hash) == 64


def test_storage_unavailable_does_not_stop_application_by_default() -> None:
    from caretaker.logging.models import EmergencyAction
    from caretaker.logging.policy import StorageEmergencyPolicy

    assert StorageEmergencyPolicy().unavailable_action is EmergencyAction.STOP_LOGGING


def test_runtime_integrity_assurance_distinguishes_hash_chain_from_external_anchor() -> None:
    from caretaker.logging.policy import RuntimeSigningPolicy, runtime_integrity_assurance
    from caretaker.logging.models import RuntimeRecordIntegrityMode

    chained = runtime_integrity_assurance(RuntimeSigningPolicy())
    assert chained["record_integrity_mode"] == "HASH_CHAINED"
    assert chained["corpus_replacement_resistant"] is False

    external = runtime_integrity_assurance(
        RuntimeSigningPolicy(mode=RuntimeRecordIntegrityMode.EXTERNAL_SIGNED)
    )
    assert external["corpus_replacement_resistant"] is True
