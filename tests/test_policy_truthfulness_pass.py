from __future__ import annotations

import os
from dataclasses import replace

import pytest

from caretaker.guard.engine import GuardEngine
from caretaker.guard.policy import (
    CollectorPolicy,
    GuardPolicy,
    GuardPolicyConfigurationError,
)
from caretaker.logging.models import CompressionAlgorithm
from caretaker.logging.policy import (
    CompressionPolicy,
    LoggingBaselinePolicy,
    LoggingPolicyConfigurationError,
    OperatorLoggingPolicy,
    RetentionPolicy,
    validate_operator_logging_policy,
)
from caretaker.policy import (
    LoggingBinding,
    PolicyConfigurationError,
    RepairPolicy,
    validate_policy,
)
from caretaker.system.collector import SystemDataCollector
from caretaker.system.policy import (
    SystemCollectionPolicy,
    SystemOutputPolicy,
    SystemRedactionPolicy,
    SystemSourceDefinition,
    SystemTimestampMode,
)


def test_guard_rejects_declared_but_unimplemented_collector() -> None:
    with pytest.raises(GuardPolicyConfigurationError, match="environment_reads"):
        GuardEngine(policy=GuardPolicy(collectors=CollectorPolicy(environment_reads=True)))


def test_logging_rejects_reserved_automatic_baseline_policy(tmp_path) -> None:
    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        baseline=LoggingBaselinePolicy(enabled=True),
    )
    with pytest.raises(LoggingPolicyConfigurationError, match="baseline"):
        validate_operator_logging_policy(policy)


def test_logging_rejects_false_retention_guarantee(tmp_path) -> None:
    policy = OperatorLoggingPolicy(
        directory=str(tmp_path),
        retention=RetentionPolicy(preserve_incident_segments=True),
    )
    with pytest.raises(LoggingPolicyConfigurationError, match="preserve_incident_segments"):
        validate_operator_logging_policy(policy)


def test_repair_binding_rejects_unimplemented_result_capture() -> None:
    with pytest.raises(PolicyConfigurationError, match="capture_results"):
        validate_policy(RepairPolicy(logging=LoggingBinding(capture_results=True)))


def test_system_policy_can_omit_body_mask_path_and_timestamp_per_source(tmp_path) -> None:
    source = tmp_path / "secret-source.txt"
    source.write_text("sensitive body\n", encoding="utf-8")
    policy = SystemCollectionPolicy(
        enabled=True,
        host_sources=(SystemSourceDefinition("demo", str(source)),),
        process_sources=(),
        timestamp_mode=SystemTimestampMode.PER_SOURCE_TIMESTAMP,
        output=SystemOutputPolicy(
            directory=str(tmp_path / "system"),
            preserve_source_body=False,
        ),
        redaction=SystemRedactionPolicy(path_masker=lambda _value: "<masked-path>"),
        compression=CompressionPolicy(enabled=True, algorithm=CompressionAlgorithm.NONE),
    )
    collector = SystemDataCollector(policy, application_pid=os.getpid())
    cycle = collector.collect_once()
    collector.close()

    result = cycle.source_results[0]
    assert result.path == "<masked-path>"
    assert result.content_hash is not None
    persisted = next((tmp_path / "system").rglob("*.ctsys")).read_text(encoding="utf-8")
    assert "source=<masked-path>" in persisted
    assert "body_preserved=false" in persisted
    assert "sensitive body" not in persisted
    assert "<source body omitted by policy>" in persisted
    assert not list((tmp_path / "system").rglob("*.gz"))
