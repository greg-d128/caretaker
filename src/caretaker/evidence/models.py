from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID, uuid4

from ..domain import ValueSnapshot


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BehaviorEventKind(Enum):
    IMPORT = auto()
    NETWORK_DNS = auto()
    NETWORK_CONNECT = auto()
    NETWORK_SEND = auto()
    FILE_OPEN = auto()
    FILE_READ = auto()
    FILE_WRITE = auto()
    DIRECTORY_LIST = auto()
    DIRECTORY_WALK = auto()
    SUBPROCESS = auto()
    ENVIRONMENT_READ = auto()
    DYNAMIC_CODE = auto()
    FUNCTION_CALL = auto()
    LOG_ACTIVITY = auto()
    OTHER = auto()


class EventOutcome(Enum):
    OBSERVED = auto()
    SUCCEEDED = auto()
    FAILED = auto()
    DENIED = auto()
    UNKNOWN = auto()


class InspectionKind(Enum):
    PRE_LOAD = auto()
    POST_LOAD = auto()
    PERIODIC = auto()
    EVENT_DRIVEN = auto()
    FUNCTION_CALL = auto()
    CANDIDATE_PROBATION = auto()


class InspectionDifferenceKind(Enum):
    ADDED = auto()
    REMOVED = auto()
    CHANGED = auto()
    REPLACED = auto()


@dataclass(frozen=True, slots=True)
class CodeIdentity:
    distribution_name: str | None
    distribution_version: str | None
    module_name: str
    qualified_name: str | None = None
    source_path: str | None = None
    source_hash: str | None = None
    bytecode_hash: str | None = None
    native_extension: bool = False
    integrity_manifest_hash: str | None = None
    loader_name: str | None = None

    @property
    def logical_name(self) -> str:
        if self.qualified_name:
            return f"{self.module_name}:{self.qualified_name}"
        return self.module_name


@dataclass(frozen=True, slots=True)
class ResourceIdentity:
    kind: str
    value: str
    category: str | None = None
    sensitive: bool = False


@dataclass(frozen=True, slots=True)
class FrameIdentity:
    module_name: str | None
    qualified_name: str | None
    filename: str | None
    line_number: int | None
    distribution_name: str | None = None


@dataclass(frozen=True, slots=True)
class BehaviorEvent:
    event_id: UUID
    occurred_at: datetime
    event_kind: BehaviorEventKind
    operation: str
    code_identity: CodeIdentity
    initiating_identity: CodeIdentity | None
    executing_identity: CodeIdentity | None
    run_id: UUID
    call_id: UUID | None
    target_id: str | None
    process_id: int
    thread_id: int
    task_id: str | None
    resource: ResourceIdentity | None
    attributes: Mapping[str, ValueSnapshot] = field(default_factory=dict)
    duration_seconds: float | None = None
    outcome: EventOutcome = EventOutcome.OBSERVED
    stack_summary: tuple[FrameIdentity, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        event_kind: BehaviorEventKind,
        operation: str,
        code_identity: CodeIdentity,
        run_id: UUID,
        process_id: int,
        thread_id: int,
        initiating_identity: CodeIdentity | None = None,
        executing_identity: CodeIdentity | None = None,
        call_id: UUID | None = None,
        target_id: str | None = None,
        task_id: str | None = None,
        resource: ResourceIdentity | None = None,
        attributes: Mapping[str, ValueSnapshot] | None = None,
        duration_seconds: float | None = None,
        outcome: EventOutcome = EventOutcome.OBSERVED,
        stack_summary: tuple[FrameIdentity, ...] = (),
    ) -> "BehaviorEvent":
        return cls(
            event_id=uuid4(),
            occurred_at=utcnow(),
            event_kind=event_kind,
            operation=operation,
            code_identity=code_identity,
            initiating_identity=initiating_identity,
            executing_identity=executing_identity,
            run_id=run_id,
            call_id=call_id,
            target_id=target_id,
            process_id=process_id,
            thread_id=thread_id,
            task_id=task_id,
            resource=resource,
            attributes=attributes or {},
            duration_seconds=duration_seconds,
            outcome=outcome,
            stack_summary=stack_summary,
        )


@dataclass(frozen=True, slots=True)
class MetricSummary:
    count: int
    minimum: float | None = None
    maximum: float | None = None
    mean: float | None = None
    total: float | None = None


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    resource: ResourceIdentity
    count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True, slots=True)
class BehaviorWindow:
    window_id: UUID
    subject: CodeIdentity
    started_at: datetime
    completed_at: datetime
    call_count: int
    event_count: int
    metrics: Mapping[str, MetricSummary]
    resources: tuple[ResourceSummary, ...]
    event_kind_counts: Mapping[str, int]
    representative_event_ids: tuple[UUID, ...] = ()
    environment_fingerprint: str | None = None
    workload_label: str | None = None
    return_category_counts: Mapping[str, int] = field(default_factory=dict)
    return_shape_counts: Mapping[str, int] = field(default_factory=dict)
    return_observations_available: bool = False
    success_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class InspectionDifference:
    path: str
    kind: InspectionDifferenceKind
    before: str | None
    after: str | None
    significant: bool = True


@dataclass(frozen=True, slots=True)
class ModuleStateSummary:
    module_name: str
    source_path: str | None
    loader_name: str | None
    global_names: tuple[str, ...]
    function_fingerprints: Mapping[str, str]
    class_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FunctionStateSummary:
    module_name: str
    qualified_name: str
    source_hash: str | None
    bytecode_hash: str | None
    defaults_hash: str | None
    annotations_hash: str | None
    referenced_globals: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class RuntimeInspection:
    inspection_id: UUID
    subject: CodeIdentity
    inspection_kind: InspectionKind
    occurred_at: datetime
    source_fingerprint: str | None
    runtime_fingerprint: str | None
    dependency_fingerprints: Mapping[str, str]
    module_state_summary: ModuleStateSummary | None
    function_state_summary: FunctionStateSummary | None
    behavior_window_id: UUID | None
    differences_from_load: tuple[InspectionDifference, ...]
    differences_from_previous: tuple[InspectionDifference, ...]


@dataclass(frozen=True, slots=True)
class DependencyIdentity:
    distribution_name: str
    distribution_version: str | None
    files: tuple[str, ...]
    file_hashes: Mapping[str, str]
    dependencies: tuple[str, ...]
    entry_points: tuple[str, ...]
    native_extensions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DependencyChange:
    distribution_name: str
    before_version: str | None
    after_version: str | None
    added_files: tuple[str, ...] = ()
    removed_files: tuple[str, ...] = ()
    changed_files: tuple[str, ...] = ()
    added_dependencies: tuple[str, ...] = ()
    removed_dependencies: tuple[str, ...] = ()
