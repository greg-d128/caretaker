from __future__ import annotations

"""Machine-checkable review boundary for Caretaker's public policy surface.

The policy dataclasses are intentionally broad, but accepted configuration must never
silently request behavior that the runtime ignores.  This module fingerprints the
reviewed dataclass surface so adding/removing/changing a policy field requires an
explicit update to the review generation and tests.
"""

import dataclasses
import hashlib
import json
from enum import Enum
from types import ModuleType
from typing import Any

from . import adaptive as adaptive_policy
from . import communications as communication_policy
from . import control_plane as control_plane_policy
from . import llm as llm_policy
from . import policy as repair_policy
from .guard import policy as guard_policy
from .logging import policy as logging_policy
from .system import policy as system_policy


POLICY_SEMANTICS_REVIEW_GENERATION = 33
# Updated only after the policy truthfulness suite reviews every changed field.
REVIEWED_POLICY_SURFACE_HASH = "5cef8a4f943b52647d9952d01ba411c60420847a6aff4aaa66cb0e00d6236b2b"


RESERVED_SETTINGS: dict[str, str] = {
    "repair.context.previous_incidents": "incident-history retrieval is not implemented",
    "repair.limits.structural_review_after_repairs": "automatic structural-review scheduling is not implemented",
    "repair.stability.oscillation_window_incidents": "incident-window oscillation detection is not implemented",
    "repair.stability.require_regression_replay_before_reactivation": "automatic regression replay before reactivation is not implemented",
    "repair.guard.baseline_name": "named Guard baselines are not implemented",
    "guard.collectors.environment_reads": "environment-read audit attribution is not implemented",
    "guard.collectors.function_calls": "general Python function-call collection is not implemented",
    "guard.retention.raw_event_seconds": "durable time-based raw-event pruning is not implemented",
    "guard.retention.aggregate_seconds": "durable aggregate retention is not implemented",
    "guard.targets[].function_patterns": "periodic inspection currently operates at module scope",
    "guard.targets[].periodic.execution_window": "execution-window periodic scheduling is not implemented",
    "logging.rotation.maximum_open_segments": "the writer currently owns exactly one open segment",
    "logging.compression.compression_workers": "compression is single-worker",
    "logging.retention.preserve_incident_segments": "segment-class-aware retention is not implemented",
    "logging.retention.preserve_baseline_segments": "segment-class-aware retention is not implemented",
    "logging.baseline.enabled": "automatic logging-baseline generation is not implemented; Guard behavior snapshots are used instead",
    "system.selector.include_same_cgroup": "cgroup process discovery is future work",
    "system.unavailable_source_action.DEGRADE_HIGHER_MODE": "system-collector-driven mode degradation is not implemented",
    "system.unavailable_source_action.REFUSE_MODE": "system-collector-driven mode refusal is not implemented",
    "system.collection_failure_action.DEGRADE_GUARD": "system-collector-driven Guard degradation is not implemented",
    "system.collection_failure_action.REFUSE_RESEARCH_MODE": "system-collector-driven research-mode refusal is not implemented",
}


def _policy_classes(module: ModuleType, *, adaptive: bool = False) -> list[type[Any]]:
    classes: list[type[Any]] = []
    for value in vars(module).values():
        if not isinstance(value, type) or not dataclasses.is_dataclass(value):
            continue
        if getattr(value, "__module__", None) != module.__name__:
            continue
        if adaptive and not value.__name__.endswith("Policy"):
            continue
        classes.append(value)
    return sorted(classes, key=lambda item: item.__qualname__)


def _canonical_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return f"{type(value).__module__}.{type(value).__qualname__}.{value.name}"
    if isinstance(value, type):
        return f"{value.__module__}.{value.__qualname__}"
    if isinstance(value, tuple):
        return [_canonical_default(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_canonical_default(item) for item in value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if callable(value):
        return f"{getattr(value, '__module__', '')}.{getattr(value, '__qualname__', type(value).__qualname__)}"
    return repr(value)


def policy_surface_schema() -> tuple[str, ...]:
    roots = (
        ("repair", repair_policy, False),
        ("guard", guard_policy, False),
        ("logging", logging_policy, False),
        ("logging.communications", communication_policy, False),
        ("logging.control_plane", control_plane_policy, True),
        ("logging.llm_usage", llm_policy, True),
        ("system", system_policy, False),
        ("lightweight", adaptive_policy, True),
    )
    rows: list[str] = []
    for prefix, module, adaptive in roots:
        for cls in _policy_classes(module, adaptive=adaptive):
            for field in dataclasses.fields(cls):
                if field.default is not dataclasses.MISSING:
                    default: Any = _canonical_default(field.default)
                elif field.default_factory is not dataclasses.MISSING:  # type: ignore[comparison-overlap]
                    factory = field.default_factory
                    default = f"<factory:{getattr(factory, '__module__', '')}.{getattr(factory, '__qualname__', type(factory).__qualname__)}>"
                else:
                    default = "<required>"
                rows.append(
                    json.dumps(
                        {
                            "path": f"{prefix}.{cls.__name__}.{field.name}",
                            "type": str(field.type),
                            "default": default,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
    return tuple(sorted(rows))


def current_policy_surface_hash() -> str:
    payload = "\n".join(policy_surface_schema()).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def policy_surface_review_status() -> dict[str, Any]:
    current = current_policy_surface_hash()
    return {
        "review_generation": POLICY_SEMANTICS_REVIEW_GENERATION,
        "reviewed_hash": REVIEWED_POLICY_SURFACE_HASH,
        "current_hash": current,
        "matches_review": current == REVIEWED_POLICY_SURFACE_HASH,
        "reserved_settings": dict(RESERVED_SETTINGS),
    }
