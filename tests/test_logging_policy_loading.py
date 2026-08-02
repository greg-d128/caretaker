from __future__ import annotations

from pathlib import Path

from caretaker.logging import (
    AttachmentOverloadAction,
    BackpressureAction,
    CompressionAlgorithm,
    EvidencePriority,
    LoggingCapability,
    LoggingMode,
    RuntimeRecordIntegrityMode,
)
from caretaker.logging.policy import load_operator_policy
from caretaker.system import load_system_policy


def test_complete_operator_toml_is_loaded(tmp_path: Path) -> None:
    policy_file = tmp_path / "caretaker.toml"
    policy_file.write_text(
        """
[logging]
application_id = "payments"
directory = "./data"
modes = ["application", "guard"]
conflict_action = "apply_required_overrides"

[logging.capture]
capabilities = ["application_logs", "warnings"]
capture_arguments = true
maximum_value_characters = 300

[logging.sampling]
debug_rate = 0.1
info_rate = 0.5

[logging.buffering]
queue_capacity = 2048
batch_records = 64

[logging.backpressure]
action = "sample"
high_priority_action = "emergency_sync_write"

[logging.compression]
algorithm = "gzip"
level = 4

[logging.attachments]
maximum_rate_per_minute = 10
overload_action = "probabilistic_sample"
always_preserve_priorities = ["important", "critical"]

[logging.attachments.compression]
enabled = true
algorithm = "gzip"
level = 3

[logging.signing]
mode = "ephemeral_signed"
key_epoch_maximum_seconds = 86400

[logging.reload]
check_interval_seconds = 5

[logging.worker_restart]
maximum_restarts = 3
exhaustion_action = "stop_application"
""",
        encoding="utf-8",
    )
    policy, snapshot = load_operator_policy(policy_file)
    assert policy.application_id == "payments"
    assert policy.modes == (LoggingMode.APPLICATION, LoggingMode.GUARD)
    assert policy.capture.capabilities == frozenset({LoggingCapability.APPLICATION_LOGS, LoggingCapability.WARNINGS})
    assert policy.backpressure.action is BackpressureAction.SAMPLE
    assert policy.compression.algorithm is CompressionAlgorithm.GZIP
    assert policy.attachments.overload_action is AttachmentOverloadAction.PROBABILISTIC_SAMPLE
    assert policy.attachments.always_preserve_priorities == frozenset({EvidencePriority.IMPORTANT, EvidencePriority.CRITICAL})
    assert policy.signing.mode is RuntimeRecordIntegrityMode.EPHEMERAL_SIGNED
    assert policy.signing.key_epoch_maximum_seconds == 86_400
    assert policy.worker_restart.maximum_restarts == 3
    assert policy.worker_restart.exhaustion_action.name == "STOP_APPLICATION"
    assert snapshot.source_path == str(policy_file)


def test_system_policy_uses_separate_output_and_source_selection(tmp_path: Path) -> None:
    policy_file = tmp_path / "caretaker.toml"
    policy_file.write_text(
        """
[system_data]
enabled = true
interval_seconds = 2.5
host_sources = ["meminfo", "/proc/loadavg"]
process_sources = ["stat", "status"]
sys_paths = ["/sys/class/net"]
timestamp_mode = "shared_cycle_timestamp"

[system_data.output]
preserve_source_body = true

[system_data.rotation]
maximum_segment_bytes = 1048576

[system_data.retention]
maximum_age_days = 3

[system_data.process_selector]
include_descendants = true
command_regexes = ["worker"]
""",
        encoding="utf-8",
    )
    policy = load_system_policy(policy_file, default_directory=str(tmp_path / "system"))
    assert policy.enabled
    assert policy.interval_seconds == 2.5
    assert policy.output.directory == str(tmp_path / "system")
    assert [item.source_id for item in policy.host_sources] == ["meminfo", "proc_loadavg"]
    assert [item.source_id for item in policy.process_sources] == ["stat", "status"]
    assert policy.process_selector.command_regexes == ("worker",)
    assert policy.retention.maximum_age_days == 3
