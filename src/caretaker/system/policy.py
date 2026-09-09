from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Mapping

from ..logging.policy import CompressionPolicy, RetentionPolicy, RotationPolicy
from ..validation_primitives import declared_primitive_errors, exact_bool, finite_number, integer


class SystemTimestampMode(Enum):
    SHARED_CYCLE_TIMESTAMP = auto()
    PER_SOURCE_TIMESTAMP = auto()


class UnavailableSourceAction(Enum):
    RECORD_AND_CONTINUE = auto()
    DEGRADE_HIGHER_MODE = auto()
    REFUSE_MODE = auto()
    STOP_APPLICATION = auto()


class SystemCollectionFailureAction(Enum):
    CONTINUE_WITH_WARNING = auto()
    DEGRADE_GUARD = auto()
    REFUSE_RESEARCH_MODE = auto()
    STOP_APPLICATION = auto()


@dataclass(frozen=True, slots=True)
class SystemSourceDefinition:
    source_id: str
    path_template: str
    per_process: bool = False
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class ProcessSelector:
    include_application_root: bool = True
    include_descendants: bool = True
    command_regexes: tuple[str, ...] = ()
    executable_paths: tuple[str, ...] = ()
    explicit_pids: tuple[int, ...] = ()
    include_same_cgroup: bool = False
    exclude_command_regexes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SystemRedactionPolicy:
    capture_cmdline: bool = False
    capture_environment: bool = False
    environment_name_allowlist: tuple[str, ...] = ()
    mask_cmdline: Callable[[str], str] | None = None
    path_masker: Callable[[str], str] | None = None


@dataclass(frozen=True, slots=True)
class SystemOutputPolicy:
    directory: str = "./caretaker-data/system"
    preserve_source_body: bool = True
    file_extension: str = ".ctsys"

    def __post_init__(self) -> None:
        from pathlib import Path

        object.__setattr__(
            self, "directory", str(Path(self.directory).expanduser().resolve())
        )


DEFAULT_HOST_SOURCES = (
    SystemSourceDefinition("schedstat", "/proc/schedstat"),
    SystemSourceDefinition("zoneinfo", "/proc/zoneinfo"),
    SystemSourceDefinition("meminfo", "/proc/meminfo"),
    SystemSourceDefinition("vmstat", "/proc/vmstat"),
    SystemSourceDefinition("diskstats", "/proc/diskstats"),
    SystemSourceDefinition("pressure_cpu", "/proc/pressure/cpu"),
    SystemSourceDefinition("pressure_memory", "/proc/pressure/memory"),
    SystemSourceDefinition("pressure_io", "/proc/pressure/io"),
)

DEFAULT_PROCESS_SOURCES = tuple(
    SystemSourceDefinition(name, f"/proc/{{pid}}/{name}", per_process=True)
    for name in ("cmdline", "io", "sched", "schedstat", "stat", "statm", "status")
)


@dataclass(frozen=True, slots=True)
class SystemCollectionPolicy:
    enabled: bool = False
    interval_seconds: float = 5.0
    host_sources: tuple[SystemSourceDefinition, ...] = DEFAULT_HOST_SOURCES
    process_sources: tuple[SystemSourceDefinition, ...] = DEFAULT_PROCESS_SOURCES
    process_selector: ProcessSelector = field(default_factory=ProcessSelector)
    sys_paths: tuple[str, ...] = ()
    timestamp_mode: SystemTimestampMode = SystemTimestampMode.SHARED_CYCLE_TIMESTAMP
    output: SystemOutputPolicy = field(default_factory=SystemOutputPolicy)
    rotation: RotationPolicy = field(default_factory=lambda: RotationPolicy(maximum_segment_bytes=256 * 1024 * 1024))
    compression: CompressionPolicy = field(default_factory=CompressionPolicy)
    retention: RetentionPolicy = field(default_factory=lambda: RetentionPolicy(maximum_age_days=14))
    redaction: SystemRedactionPolicy = field(default_factory=SystemRedactionPolicy)
    unavailable_source_action: UnavailableSourceAction = UnavailableSourceAction.RECORD_AND_CONTINUE
    failure_action: SystemCollectionFailureAction = SystemCollectionFailureAction.CONTINUE_WITH_WARNING


def _enum(enum_type, value):
    if isinstance(value, enum_type):
        return value
    return enum_type[str(value).upper()]


def _source_selection(
    values: object,
    defaults: tuple[SystemSourceDefinition, ...],
    *,
    per_process: bool,
) -> tuple[SystemSourceDefinition, ...]:
    """Resolve a TOML source list.

    Entries may be built-in source ids, absolute paths, or tables containing
    source_id/path_template/enabled.  This keeps the first collector useful for
    nearly raw /proc and /sys capture without hard-coding one application.
    """
    if values is None:
        return defaults
    by_id = {item.source_id: item for item in defaults}
    resolved: list[SystemSourceDefinition] = []
    for item in values:
        if isinstance(item, str):
            if item in by_id:
                resolved.append(by_id[item])
            else:
                source_id = item.strip("/").replace("/", "_") or "root"
                path_template = item
                resolved.append(SystemSourceDefinition(source_id, path_template, per_process=per_process))
            continue
        if not isinstance(item, Mapping):
            raise TypeError("system source entries must be strings or tables")
        source_id = str(item.get("source_id") or item.get("id") or "source")
        path_template = str(item.get("path_template") or item.get("path"))
        if not path_template or path_template == "None":
            raise ValueError(f"system source {source_id!r} requires path_template")
        resolved.append(SystemSourceDefinition(
            source_id=source_id,
            path_template=path_template,
            per_process=(
                exact_bool(item["per_process"], name="system source per_process")
                if "per_process" in item else per_process
            ),
            enabled=(
                exact_bool(item["enabled"], name="system source enabled")
                if "enabled" in item else True
            ),
        ))
    return tuple(resolved)


def load_system_policy(
    path: str | "Path",
    *,
    default_directory: str | None = None,
) -> SystemCollectionPolicy:
    """Load the optional ``[system_data]`` section from an operator TOML file."""
    from pathlib import Path
    import tomllib

    document = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    raw = dict(document.get("system_data", {}))
    if not raw:
        return SystemCollectionPolicy(
            enabled=False,
            output=SystemOutputPolicy(directory=default_directory or "./caretaker-data/system"),
        )

    selector_data = dict(raw.get("process_selector", {}))
    output_data = dict(raw.get("output", {}))
    rotation_data = dict(raw.get("rotation", {}))
    compression_data = dict(raw.get("compression", {}))
    retention_data = dict(raw.get("retention", {}))
    redaction_data = dict(raw.get("redaction", {}))

    if default_directory and "directory" not in output_data:
        output_data["directory"] = default_directory
    if "algorithm" in compression_data:
        from ..logging.models import CompressionAlgorithm
        compression_data["algorithm"] = _enum(CompressionAlgorithm, compression_data["algorithm"])

    enabled = (
        exact_bool(raw["enabled"], name="system_data.enabled")
        if "enabled" in raw else False
    )
    interval_seconds = (
        finite_number(
            raw["interval_seconds"],
            name="system_data.interval_seconds",
            minimum=0.0,
        )
        if "interval_seconds" in raw else 5.0
    )
    if interval_seconds <= 0:
        raise ValueError("system_data.interval_seconds must be greater than zero")
    policy = SystemCollectionPolicy(
        enabled=enabled,
        interval_seconds=interval_seconds,
        host_sources=_source_selection(raw.get("host_sources"), DEFAULT_HOST_SOURCES, per_process=False),
        process_sources=_source_selection(raw.get("process_sources"), DEFAULT_PROCESS_SOURCES, per_process=True),
        process_selector=ProcessSelector(**{
            **selector_data,
            **({"command_regexes": tuple(selector_data["command_regexes"])} if "command_regexes" in selector_data else {}),
            **({"executable_paths": tuple(selector_data["executable_paths"])} if "executable_paths" in selector_data else {}),
            **({"explicit_pids": tuple(integer(value, name="system process selector PID", minimum=1) for value in selector_data["explicit_pids"])} if "explicit_pids" in selector_data else {}),
            **({"exclude_command_regexes": tuple(selector_data["exclude_command_regexes"])} if "exclude_command_regexes" in selector_data else {}),
        }),
        sys_paths=tuple(str(value) for value in raw.get("sys_paths", ())),
        timestamp_mode=_enum(SystemTimestampMode, raw.get("timestamp_mode", "SHARED_CYCLE_TIMESTAMP")),
        output=SystemOutputPolicy(**output_data),
        rotation=RotationPolicy(**rotation_data) if rotation_data else SystemCollectionPolicy().rotation,
        compression=CompressionPolicy(**compression_data) if compression_data else SystemCollectionPolicy().compression,
        retention=RetentionPolicy(**retention_data) if retention_data else SystemCollectionPolicy().retention,
        redaction=SystemRedactionPolicy(**{
            **redaction_data,
            **({"environment_name_allowlist": tuple(redaction_data["environment_name_allowlist"])} if "environment_name_allowlist" in redaction_data else {}),
        }),
        unavailable_source_action=_enum(
            UnavailableSourceAction,
            raw.get("unavailable_source_action", "RECORD_AND_CONTINUE"),
        ),
        failure_action=_enum(
            SystemCollectionFailureAction,
            raw.get("failure_action", "CONTINUE_WITH_WARNING"),
        ),
    )
    validate_system_policy(policy)
    return policy


class SystemPolicyConfigurationError(ValueError):
    """Raised when system collection policy requests unavailable semantics."""


def validate_system_policy(policy: SystemCollectionPolicy) -> None:
    errors: list[str] = list(declared_primitive_errors(policy, prefix="system"))
    try:
        finite_number(policy.interval_seconds, name="system.interval_seconds", minimum=0.0)
    except ValueError as exc:
        errors.append(str(exc))
    if errors:
        raise SystemPolicyConfigurationError("Invalid system collection policy:\n- " + "\n- ".join(errors))
    if policy.interval_seconds <= 0:
        errors.append("interval_seconds must be greater than zero")
    if policy.process_selector.include_same_cgroup:
        errors.append("process_selector.include_same_cgroup is reserved until cgroup-aware process discovery is implemented")
    if policy.redaction.capture_environment and not policy.redaction.environment_name_allowlist:
        errors.append("redaction.capture_environment=True requires a non-empty environment_name_allowlist")
    if policy.redaction.environment_name_allowlist and not policy.redaction.capture_environment:
        errors.append("redaction.environment_name_allowlist requires capture_environment=True")
    if policy.unavailable_source_action in {UnavailableSourceAction.DEGRADE_HIGHER_MODE, UnavailableSourceAction.REFUSE_MODE}:
        errors.append(
            f"unavailable_source_action={policy.unavailable_source_action.name} is reserved; "
            "RECORD_AND_CONTINUE and STOP_APPLICATION are implemented"
        )
    if policy.failure_action in {SystemCollectionFailureAction.DEGRADE_GUARD, SystemCollectionFailureAction.REFUSE_RESEARCH_MODE}:
        errors.append(
            f"failure_action={policy.failure_action.name} is reserved; "
            "CONTINUE_WITH_WARNING and STOP_APPLICATION are implemented"
        )
    if policy.rotation.maximum_open_segments != 1:
        errors.append("rotation.maximum_open_segments is reserved; system collection supports one open segment per source")
    if policy.compression.compression_workers != 1:
        errors.append("compression.compression_workers is reserved; system compression is single-worker")
    if policy.retention.preserve_incident_segments or policy.retention.preserve_baseline_segments:
        errors.append("system retention preserve_* segment classes are not applicable to system-source streams")
    if errors:
        raise SystemPolicyConfigurationError("Invalid system collection policy:\n- " + "\n- ".join(errors))
