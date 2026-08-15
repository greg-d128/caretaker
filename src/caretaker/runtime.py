from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from uuid import UUID


current_target_id: ContextVar[str | None] = ContextVar("caretaker_target_id", default=None)
current_call_id: ContextVar[UUID | None] = ContextVar("caretaker_call_id", default=None)
current_incident_id: ContextVar[UUID | None] = ContextVar("caretaker_incident_id", default=None)
current_episode_id: ContextVar[UUID | None] = ContextVar("caretaker_episode_id", default=None)
current_attempt_id: ContextVar[UUID | None] = ContextVar("caretaker_attempt_id", default=None)
current_candidate_id: ContextVar[UUID | None] = ContextVar("caretaker_candidate_id", default=None)
current_operation: ContextVar[str | None] = ContextVar("caretaker_operation", default=None)
current_observation_stage: ContextVar[str | None] = ContextVar("caretaker_observation_stage", default=None)
current_monitoring_fingerprint: ContextVar[str | None] = ContextVar("caretaker_monitoring_fingerprint", default=None)
repair_depth: ContextVar[int] = ContextVar("caretaker_repair_depth", default=0)


@dataclass
class RuntimeTokens:
    values: list[tuple[ContextVar[Any], object]]

    def reset(self) -> None:
        for variable, token in reversed(self.values):
            variable.reset(token)


def set_runtime_context(**values: object) -> RuntimeTokens:
    mapping = {
        "target_id": current_target_id,
        "call_id": current_call_id,
        "incident_id": current_incident_id,
        "episode_id": current_episode_id,
        "attempt_id": current_attempt_id,
        "candidate_id": current_candidate_id,
        "operation": current_operation,
        "observation_stage": current_observation_stage,
        "monitoring_fingerprint": current_monitoring_fingerprint,
    }
    tokens: list[tuple[ContextVar[Any], object]] = []
    for name, value in values.items():
        variable = mapping[name]
        tokens.append((variable, variable.set(value)))
    return RuntimeTokens(tokens)


def snapshot_context() -> dict[str, object]:
    return {
        "target_id": current_target_id.get(),
        "call_id": current_call_id.get(),
        "incident_id": current_incident_id.get(),
        "episode_id": current_episode_id.get(),
        "attempt_id": current_attempt_id.get(),
        "candidate_id": current_candidate_id.get(),
        "operation": current_operation.get(),
        "observation_stage": current_observation_stage.get(),
        "monitoring_fingerprint": current_monitoring_fingerprint.get(),
        "repair_depth": repair_depth.get(),
    }
