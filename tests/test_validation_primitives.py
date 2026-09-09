from __future__ import annotations

import math
from dataclasses import replace

import pytest

from caretaker.authority import PolicyAuthoritySupervisor
from caretaker.control_plane import RuntimeInteractionPolicy
from caretaker.logging.policy import load_operator_policy
from caretaker.policy import PolicyConfigurationError, RepairPolicy, RetryPolicy, validate_policy
from caretaker.system.policy import load_system_policy


@pytest.mark.parametrize(
    "policy",
    (
        RepairPolicy(retry=RetryPolicy(backoff_seconds=math.nan)),
        RepairPolicy(retry=RetryPolicy(backoff_seconds=math.inf)),
        RepairPolicy(observation=replace(RepairPolicy().observation, long_term_failure_rate="0.1")),
    ),
)
def test_repair_policy_rejects_non_finite_or_wrong_boundary_values(policy) -> None:
    with pytest.raises(PolicyConfigurationError):
        validate_policy(policy)


def test_runtime_interaction_policy_rejects_non_finite_job_duration() -> None:
    with pytest.raises(ValueError, match="finite positive"):
        RuntimeInteractionPolicy(maximum_job_duration_seconds=math.nan)


def test_authority_lease_duration_rejects_boolean() -> None:
    authority = PolicyAuthoritySupervisor()
    with pytest.raises(ValueError, match="integer"):
        authority.acquire_runtime_lease(
            settings=(),
            requested_by="operator",
            reason="test",
            duration_seconds=True,
        )


def test_logging_loader_rejects_string_boolean(tmp_path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text('[logging]\nenabled = "false"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="logging.enabled must be a boolean"):
        load_operator_policy(path)


def test_system_loader_rejects_string_boolean(tmp_path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text('[system_data]\nenabled = "false"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="system_data.enabled must be a boolean"):
        load_system_policy(path)
