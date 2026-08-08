from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Mapping

from ..logging.policy import CompressionPolicy, RetentionPolicy, RotationPolicy


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
            per_process=bool(item.get("per_process", per_process)),
            enabled=bool(item.get("enabled", True)),
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

    return SystemCollectionPolicy(
        enabled=bool(raw.get("enabled", False)),
        interval_seconds=float(raw.get("interval_seconds", 5.0)),
        host_sources=_source_selection(raw.get("host_sources"), DEFAULT_HOST_SOURCES, per_process=False),
        process_sources=_source_selection(raw.get("process_sources"), DEFAULT_PROCESS_SOURCES, per_process=True),
        process_selector=ProcessSelector(**{
            **selector_data,
            **({"command_regexes": tuple(selector_data["command_regexes"])} if "command_regexes" in selector_data else {}),
            **({"executable_paths": tuple(selector_data["executable_paths"])} if "executable_paths" in selector_data else {}),
            **({"explicit_pids": tuple(int(value) for value in selector_data["explicit_pids"])} if "explicit_pids" in selector_data else {}),
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
