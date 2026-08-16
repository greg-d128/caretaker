from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import tomllib
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Mapping
from uuid import UUID, uuid4

from .models import (
    AnchorFailureAction,
    AttachmentOverloadAction,
    BackpressureAction,
    CompressionAlgorithm,
    EffectiveLoggingPolicy,
    EmergencyAction,
    EvidencePriority,
    LoggingCapability,
    LoggingMode,
    LoggingPolicyOverride,
    LoggingPolicySnapshot,
    ModeLease,
    PolicyConflictAction,
    RuntimeRecordIntegrityMode,
    WorkerFailureAction,
)


@dataclass(frozen=True, slots=True)
class CapturePolicy:
    capabilities: frozenset[LoggingCapability] = frozenset({
        LoggingCapability.APPLICATION_LOGS,
        LoggingCapability.WARNINGS,
        LoggingCapability.EXCEPTIONS,
        LoggingCapability.CALL_CORRELATION,
        LoggingCapability.POLICY_CHANGE_RECORDS,
        LoggingCapability.HIGH_PRIORITY_EVIDENCE_CHANNEL,
    })
    capture_arguments: bool = False
    capture_results: bool = False
    maximum_value_characters: int = 512


@dataclass(frozen=True, slots=True)
class SamplingPolicy:
    debug_rate: float = 1.0
    info_rate: float = 1.0
    warning_rate: float = 1.0
    always_preserve_errors: bool = True


@dataclass(frozen=True, slots=True)
class RedactionPolicy:
    enabled: bool = True
    secret_field_names: tuple[str, ...] = (
        "password", "passwd", "token", "secret", "authorization", "api_key", "apikey",
    )
    replacement: str = "<redacted>"


@dataclass(frozen=True, slots=True)
class BufferingPolicy:
    queue_capacity: int = 8192
    batch_records: int = 256
    flush_interval_seconds: float = 0.25


@dataclass(frozen=True, slots=True)
class BackpressurePolicy:
    action: BackpressureAction = BackpressureAction.DROP_DEBUG
    high_priority_action: BackpressureAction = BackpressureAction.EMERGENCY_SYNC_WRITE
    block_timeout_seconds: float = 1.0


@dataclass(frozen=True, slots=True)
class RotationPolicy:
    maximum_segment_bytes: int = 128 * 1024 * 1024
    maximum_segment_seconds: int = 3600
    rotate_at_utc_midnight: bool = False
    maximum_open_segments: int = 1


@dataclass(frozen=True, slots=True)
class CompressionPolicy:
    enabled: bool = True
    algorithm: CompressionAlgorithm = CompressionAlgorithm.GZIP
    level: int = 6
    compress_closed_segments: bool = True
    compression_workers: int = 1


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    maximum_age_days: int | None = 90
    maximum_total_bytes: int | None = None
    maximum_segments: int | None = None
    # Segment-class-aware preservation is not yet implemented.  Keep these
    # defaults false so the public policy does not claim a guarantee the
    # retention engine cannot currently provide.
    preserve_incident_segments: bool = False
    preserve_baseline_segments: bool = False


@dataclass(frozen=True, slots=True)
class CodecPolicy:
    format_version: int = 1
    maximum_record_bytes: int = 4096


@dataclass(frozen=True, slots=True)
class IndexPolicy:
    enabled: bool = True
    sqlite_path: str | None = None


@dataclass(frozen=True, slots=True)
class InterrogationPolicy:
    enabled: bool = False
    llm_enabled: bool = False
    maximum_records: int = 10_000
    maximum_representative_records: int = 100


@dataclass(frozen=True, slots=True)
class LoggingBaselinePolicy:
    enabled: bool = False
    automatic_monthly_generation: bool = False
    automatic_monthly_acceptance: bool = False
    minimum_calls: int = 100
    compare_latest: bool = True
    compare_long_term_anchor: bool = True
    compare_same_month_prior_years: bool = True


@dataclass(frozen=True, slots=True)
class MetricsBinding:
    enabled: bool = False
    provider_name: str | None = None
    correlate_by_process: bool = True
    correlate_by_call: bool = False


@dataclass(frozen=True, slots=True)
class StorageEmergencyPolicy:
    minimum_free_bytes: int | None = 50 * 1024 * 1024
    minimum_free_percent: float | None = None
    pressure_action: EmergencyAction = EmergencyAction.DROP_LOW_PRIORITY
    emergency_action: EmergencyAction = EmergencyAction.STOP_LOGGING
    unavailable_action: EmergencyAction = EmergencyAction.STOP_LOGGING


@dataclass(frozen=True, slots=True)
class AttachmentPolicy:
    enabled: bool = True
    compression: CompressionPolicy = field(default_factory=CompressionPolicy)
    rotation: RotationPolicy = field(default_factory=lambda: RotationPolicy(maximum_segment_bytes=512 * 1024 * 1024))
    retention: RetentionPolicy = field(default_factory=lambda: RetentionPolicy(maximum_age_days=30))
    maximum_attachment_bytes: int | None = 64 * 1024 * 1024
    maximum_rate_per_minute: float | None = 120.0
    overload_action: AttachmentOverloadAction = AttachmentOverloadAction.PRESERVE_ALL
    minimum_sampling_probability: float = 0.01
    always_preserve_priorities: frozenset[EvidencePriority] = frozenset({EvidencePriority.CRITICAL})


@dataclass(frozen=True, slots=True)
class RuntimeSigningPolicy:
    mode: RuntimeRecordIntegrityMode = RuntimeRecordIntegrityMode.HASH_CHAINED
    algorithm: str = "ed25519"
    sign_closed_event_segments: bool = True
    sign_attachment_manifests: bool = True
    run_signer_in_separate_process: bool = True
    disable_signer_core_dumps: bool = True
    key_epoch_maximum_seconds: int | None = 86_400
    key_epoch_maximum_segments: int | None = None
    publish_public_key_to_log: bool = True
    publish_public_key_to_control_clients: bool = True
    # Signing identities are written to a separate append-only hash-chained
    # journal so their retention can outlive ordinary application events.
    identity_journal_enabled: bool = True
    identity_journal_maximum_age_days: int | None = 3650
    identity_journal_maximum_files: int | None = None
    require_external_anchor: bool = False
    external_anchor_failure_action: AnchorFailureAction = AnchorFailureAction.CONTINUE_SELF_RECORDED


def runtime_integrity_assurance(policy: RuntimeSigningPolicy) -> dict[str, object]:
    """Return explicit assurance properties for operator/status reporting."""
    # EXTERNAL_SIGNED is itself an externally held signing authority. Merely
    # requesting an external anchor for an ephemeral chain does not establish
    # that an anchor was actually created or verified.
    externally_anchored = policy.mode is RuntimeRecordIntegrityMode.EXTERNAL_SIGNED
    return {
        "record_integrity_mode": policy.mode.name,
        "identity_anchor_required": policy.require_external_anchor,
        "externally_anchored_expected": (
            externally_anchored or policy.require_external_anchor
        ),
        "externally_anchored_verified": externally_anchored,
        "external_anchor_requirement_satisfied": (
            not policy.require_external_anchor or externally_anchored
        ),
        "corpus_replacement_resistant": externally_anchored,
    }


@dataclass(frozen=True, slots=True)
class PolicyReloadPolicy:
    enabled: bool = True
    check_interval_seconds: float = 30.0
    require_valid_complete_document: bool = True
    retain_previous_on_failure: bool = True


@dataclass(frozen=True, slots=True)
class WorkerRestartPolicy:
    enabled: bool = True
    maximum_restarts: int = 5
    restart_window_seconds: float = 300.0
    initial_backoff_seconds: float = 0.5
    maximum_backoff_seconds: float = 30.0
    exhaustion_action: WorkerFailureAction = WorkerFailureAction.DISABLE_COMPONENT


@dataclass(frozen=True, slots=True)
class LoggingBinding:
    enabled: bool = True
    capture_calls: bool = True
    capture_exceptions: bool = True
    capture_timing: bool = True
    capture_arguments: bool = False
    capture_results: bool = False

@dataclass(frozen=True, slots=True)
class OperatorLoggingPolicy:
    enabled: bool = True
    application_id: str = "application"
    directory: str = "./caretaker-data"
    modes: tuple[LoggingMode, ...] = (LoggingMode.APPLICATION,)
    conflict_action: PolicyConflictAction = PolicyConflictAction.APPLY_REQUIRED_OVERRIDES
    capture: CapturePolicy = field(default_factory=CapturePolicy)
    sampling: SamplingPolicy = field(default_factory=SamplingPolicy)
    redaction: RedactionPolicy = field(default_factory=RedactionPolicy)
    buffering: BufferingPolicy = field(default_factory=BufferingPolicy)
    backpressure: BackpressurePolicy = field(default_factory=BackpressurePolicy)
    rotation: RotationPolicy = field(default_factory=RotationPolicy)
    compression: CompressionPolicy = field(default_factory=CompressionPolicy)
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    codec: CodecPolicy = field(default_factory=CodecPolicy)
    indexing: IndexPolicy = field(default_factory=IndexPolicy)
    interrogation: InterrogationPolicy = field(default_factory=InterrogationPolicy)
    baseline: LoggingBaselinePolicy = field(default_factory=LoggingBaselinePolicy)
    metrics: MetricsBinding = field(default_factory=MetricsBinding)
    storage_emergency: StorageEmergencyPolicy = field(default_factory=StorageEmergencyPolicy)
    attachments: AttachmentPolicy = field(default_factory=AttachmentPolicy)
    signing: RuntimeSigningPolicy = field(default_factory=RuntimeSigningPolicy)
    reload: PolicyReloadPolicy = field(default_factory=PolicyReloadPolicy)
    worker_restart: WorkerRestartPolicy = field(default_factory=WorkerRestartPolicy)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "directory", str(Path(self.directory).expanduser().resolve())
        )

    @classmethod
    def application_defaults(cls, *, directory: str, application_id: str = "application") -> "OperatorLoggingPolicy":
        return cls(directory=directory, application_id=application_id)


class LoggingPolicyConfigurationError(ValueError):
    """Raised when logging policy requests unsupported runtime semantics."""


def validate_operator_logging_policy(policy: OperatorLoggingPolicy) -> None:
    """Validate that accepted logging policy has executable semantics."""

    errors: list[str] = []
    for name, rate in (("debug_rate", policy.sampling.debug_rate), ("info_rate", policy.sampling.info_rate), ("warning_rate", policy.sampling.warning_rate)):
        if not 0.0 <= rate <= 1.0:
            errors.append(f"sampling.{name} must be between 0 and 1")
    if not policy.sampling.always_preserve_errors:
        errors.append("sampling.always_preserve_errors=False is unsupported; ERROR and higher records are always preserved")
    if policy.buffering.queue_capacity <= 0:
        errors.append("buffering.queue_capacity must be greater than zero")
    if policy.buffering.batch_records <= 0:
        errors.append("buffering.batch_records must be greater than zero")
    if policy.buffering.flush_interval_seconds <= 0:
        errors.append("buffering.flush_interval_seconds must be greater than zero")
    if policy.rotation.maximum_segment_bytes <= 0 or policy.rotation.maximum_segment_seconds <= 0:
        errors.append("rotation byte/time limits must be greater than zero")
    if policy.rotation.maximum_open_segments != 1:
        errors.append("rotation.maximum_open_segments is reserved; this writer supports exactly one open segment")
    if policy.compression.compression_workers != 1:
        errors.append("compression.compression_workers is reserved; compression is single-worker in this release")
    if not 0 <= policy.compression.level <= 9:
        errors.append("compression.level must be between 0 and 9")
    if policy.retention.preserve_incident_segments:
        errors.append("retention.preserve_incident_segments is reserved until segment-class-aware retention is implemented")
    if policy.retention.preserve_baseline_segments:
        errors.append("retention.preserve_baseline_segments is reserved until segment-class-aware retention is implemented")
    if policy.codec.format_version != 1:
        errors.append("codec.format_version is fixed at 1 in this release")
    if policy.interrogation.enabled or policy.interrogation.llm_enabled:
        errors.append("logging.interrogation policy activation is reserved; use the explicit interrogation API/console command")
    if policy.baseline.enabled:
        errors.append("logging.baseline automatic baseline policy is reserved; Guard behavior snapshots are the implemented baseline mechanism")
    if policy.metrics.enabled:
        errors.append("logging.metrics provider correlation is reserved; no metrics provider adapter is implemented")
    if not policy.reload.require_valid_complete_document:
        errors.append("reload.require_valid_complete_document=False is unsupported; reloads always require a complete valid document")
    if not policy.reload.retain_previous_on_failure:
        errors.append("reload.retain_previous_on_failure=False is unsupported; failed reloads always retain the previous policy")
    if not policy.signing.publish_public_key_to_log:
        errors.append("signing.publish_public_key_to_log=False is unsupported; signed ephemeral identities require durable public-key publication")
    if not policy.signing.publish_public_key_to_control_clients:
        errors.append("signing.publish_public_key_to_control_clients=False is reserved; signed runtime identity remains available to control clients")
    if policy.attachments.compression.compression_workers != 1:
        errors.append("attachments.compression.compression_workers is reserved; attachment compression is single-worker")
    if policy.attachments.rotation.maximum_open_segments != 1:
        errors.append("attachments.rotation.maximum_open_segments is reserved; attachment storage supports one open segment")
    if policy.attachments.retention.preserve_incident_segments or policy.attachments.retention.preserve_baseline_segments:
        errors.append("attachments retention preserve_* segment classes are reserved until class-aware retention is implemented")
    if errors:
        raise LoggingPolicyConfigurationError("Invalid logging policy:\n- " + "\n- ".join(errors))


MODE_REQUIREMENTS_VERSION = "logging-mode-requirements-v1"

_MODE_REQUIREMENTS: Mapping[LoggingMode, frozenset[LoggingCapability]] = {
    LoggingMode.APPLICATION: frozenset({
        LoggingCapability.APPLICATION_LOGS,
        LoggingCapability.POLICY_CHANGE_RECORDS,
    }),
    LoggingMode.DIAGNOSTIC: frozenset({
        LoggingCapability.CALL_CORRELATION,
        LoggingCapability.EXCEPTIONS,
        LoggingCapability.EXCEPTION_FINGERPRINTS,
        LoggingCapability.FUNCTION_TIMING,
        LoggingCapability.HIGH_PRIORITY_EVIDENCE_CHANNEL,
    }),
    LoggingMode.GUARD: frozenset({
        LoggingCapability.CALL_CORRELATION,
        LoggingCapability.BEHAVIOR_EVENT_REFERENCES,
        LoggingCapability.IMPORT_IDENTITY,
        LoggingCapability.DEPENDENCY_SNAPSHOTS,
        LoggingCapability.GUARD_DECISIONS,
        LoggingCapability.HIGH_PRIORITY_EVIDENCE_CHANNEL,
    }),
    LoggingMode.REPAIR: frozenset({
        LoggingCapability.CALL_CORRELATION,
        LoggingCapability.EXCEPTION_FINGERPRINTS,
        LoggingCapability.FUNCTION_TIMING,
        LoggingCapability.REPAIR_EPISODES,
        LoggingCapability.CANDIDATE_VALIDATION,
        LoggingCapability.ACTIVATION_AND_ROLLBACK,
        LoggingCapability.HIGH_PRIORITY_EVIDENCE_CHANNEL,
    }),
    LoggingMode.RESEARCH: frozenset({
        LoggingCapability.CALL_CORRELATION,
        LoggingCapability.DETAILED_CALL_TRACES,
        LoggingCapability.REPRESENTATIVE_STATE_SAMPLES,
        LoggingCapability.OUTLIER_FEATURES,
        LoggingCapability.BEHAVIOR_EVENT_REFERENCES,
        LoggingCapability.HIGH_PRIORITY_EVIDENCE_CHANNEL,
    }),
    LoggingMode.FORENSIC: frozenset({
        LoggingCapability.DETAILED_CALL_TRACES,
        LoggingCapability.REPRESENTATIVE_STATE_SAMPLES,
        LoggingCapability.BEHAVIOR_EVENT_REFERENCES,
        LoggingCapability.SYSTEM_RECORDS,
        LoggingCapability.HIGH_PRIORITY_EVIDENCE_CHANNEL,
    }),
    LoggingMode.BASELINE: frozenset({
        LoggingCapability.CALL_CORRELATION,
        LoggingCapability.FUNCTION_TIMING,
        LoggingCapability.DEPENDENCY_SNAPSHOTS,
        LoggingCapability.OUTLIER_FEATURES,
    }),
}


def mode_requirements(modes: tuple[LoggingMode, ...]) -> frozenset[LoggingCapability]:
    required: set[LoggingCapability] = set()
    for mode in modes:
        required.update(_MODE_REQUIREMENTS[mode])
    return frozenset(required)


def canonicalize(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: canonicalize(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(key): canonicalize(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (tuple, list, set, frozenset)):
        values = [canonicalize(item) for item in value]
        return sorted(values, key=repr) if isinstance(value, (set, frozenset)) else values
    if hasattr(value, "name") and hasattr(value, "value"):
        return value.name
    if isinstance(value, Path):
        return str(value)
    return value


def policy_snapshot(policy: OperatorLoggingPolicy, *, source_path: str | None = None) -> LoggingPolicySnapshot:
    canonical = canonicalize(policy)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    owner = permissions = None
    if source_path:
        try:
            info = os.stat(source_path)
            owner = str(info.st_uid)
            permissions = stat.filemode(info.st_mode)
        except OSError:
            pass
    return LoggingPolicySnapshot(
        snapshot_id=uuid4(),
        loaded_at=datetime.now(timezone.utc),
        source_path=source_path,
        content_hash=hashlib.sha256(encoded.encode()).hexdigest(),
        canonical_policy=canonical,
        human_readable_policy=json.dumps(canonical, indent=2, sort_keys=True),
        file_owner=owner,
        file_permissions=permissions,
        policy_version="1",
    )


def _enum(enum_type, value):
    if isinstance(value, enum_type):
        return value
    return enum_type[str(value).upper()]


def _capabilities(values: list[str] | tuple[str, ...] | None) -> frozenset[LoggingCapability]:
    if values is None:
        return CapturePolicy().capabilities
    return frozenset(_enum(LoggingCapability, item) for item in values)


def _enum_if_present(enum_type, values: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = values.get(key)
    return {key: _enum(enum_type, value)} if value is not None else {}


def _priority_set(values: list[str] | tuple[str, ...] | None) -> frozenset[EvidencePriority]:
    if values is None:
        return AttachmentPolicy().always_preserve_priorities
    return frozenset(_enum(EvidencePriority, item) for item in values)


def load_operator_policy(path: str | Path) -> tuple[OperatorLoggingPolicy, LoggingPolicySnapshot]:
    """Load the unsigned operator policy from TOML.

    Every supported section is parsed explicitly so unknown fields fail at the
    dataclass boundary instead of being silently accepted.  The policy remains
    outside Caretaker's release-signature authority; the returned snapshot is
    attribution and reproducibility evidence only.
    """
    path = Path(path)
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    log = data.get("logging", data)

    capture_data = dict(log.get("capture", {}))
    sampling_data = dict(log.get("sampling", {}))
    redaction_data = dict(log.get("redaction", {}))
    buffering_data = dict(log.get("buffering", {}))
    backpressure_data = dict(log.get("backpressure", {}))
    rotation_data = dict(log.get("rotation", {}))
    compression_data = dict(log.get("compression", {}))
    retention_data = dict(log.get("retention", {}))
    codec_data = dict(log.get("codec", {}))
    indexing_data = dict(log.get("indexing", log.get("index", {})))
    interrogation_data = dict(log.get("interrogation", {}))
    baseline_data = dict(log.get("baseline", {}))
    metrics_data = dict(log.get("metrics", {}))
    emergency_data = dict(log.get("storage_emergency", {}))
    attachment_data = dict(log.get("attachments", {}))
    signing_data = dict(log.get("signing", {}))
    reload_data = dict(log.get("reload", {}))
    worker_restart_data = dict(log.get("worker_restart", {}))

    attachment_compression_data = dict(attachment_data.pop("compression", {}))
    attachment_rotation_data = dict(attachment_data.pop("rotation", {}))
    attachment_retention_data = dict(attachment_data.pop("retention", {}))
    attachment_priorities = attachment_data.pop("always_preserve_priorities", None)

    configured_directory = Path(str(log.get("directory", "./caretaker-data"))).expanduser()
    if not configured_directory.is_absolute():
        configured_directory = path.parent / configured_directory

    policy = OperatorLoggingPolicy(
        enabled=bool(log.get("enabled", True)),
        application_id=str(log.get("application_id", "application")),
        directory=str(configured_directory),
        modes=tuple(_enum(LoggingMode, item) for item in log.get("modes", ["APPLICATION"])),
        conflict_action=_enum(PolicyConflictAction, log.get("conflict_action", "APPLY_REQUIRED_OVERRIDES")),
        capture=CapturePolicy(
            capabilities=_capabilities(capture_data.pop("capabilities", None)),
            **capture_data,
        ),
        sampling=SamplingPolicy(**sampling_data),
        redaction=RedactionPolicy(**{
            **redaction_data,
            **({"secret_field_names": tuple(redaction_data["secret_field_names"])} if "secret_field_names" in redaction_data else {}),
        }),
        buffering=BufferingPolicy(**buffering_data),
        backpressure=BackpressurePolicy(**{
            **backpressure_data,
            **_enum_if_present(BackpressureAction, backpressure_data, "action"),
            **_enum_if_present(BackpressureAction, backpressure_data, "high_priority_action"),
        }),
        rotation=RotationPolicy(**rotation_data),
        compression=CompressionPolicy(**{
            **compression_data,
            **_enum_if_present(CompressionAlgorithm, compression_data, "algorithm"),
        }),
        retention=RetentionPolicy(**retention_data),
        codec=CodecPolicy(**codec_data),
        indexing=IndexPolicy(**indexing_data),
        interrogation=InterrogationPolicy(**interrogation_data),
        baseline=LoggingBaselinePolicy(**baseline_data),
        metrics=MetricsBinding(**metrics_data),
        storage_emergency=StorageEmergencyPolicy(**{
            **emergency_data,
            **_enum_if_present(EmergencyAction, emergency_data, "pressure_action"),
            **_enum_if_present(EmergencyAction, emergency_data, "emergency_action"),
            **_enum_if_present(EmergencyAction, emergency_data, "unavailable_action"),
        }),
        attachments=AttachmentPolicy(**{
            **attachment_data,
            "compression": CompressionPolicy(**{
                **attachment_compression_data,
                **_enum_if_present(CompressionAlgorithm, attachment_compression_data, "algorithm"),
            }) if attachment_compression_data else AttachmentPolicy().compression,
            "rotation": RotationPolicy(**attachment_rotation_data) if attachment_rotation_data else AttachmentPolicy().rotation,
            "retention": RetentionPolicy(**attachment_retention_data) if attachment_retention_data else AttachmentPolicy().retention,
            "always_preserve_priorities": _priority_set(attachment_priorities),
            **_enum_if_present(AttachmentOverloadAction, attachment_data, "overload_action"),
        }),
        signing=RuntimeSigningPolicy(**{
            **signing_data,
            **_enum_if_present(RuntimeRecordIntegrityMode, signing_data, "mode"),
            **_enum_if_present(AnchorFailureAction, signing_data, "external_anchor_failure_action"),
        }),
        reload=PolicyReloadPolicy(**reload_data),
        worker_restart=WorkerRestartPolicy(**{
            **worker_restart_data,
            **_enum_if_present(WorkerFailureAction, worker_restart_data, "exhaustion_action"),
        }),
    )
    validate_operator_logging_policy(policy)
    return policy, policy_snapshot(policy, source_path=str(path))


def reconcile_policy(
    policy: OperatorLoggingPolicy,
    snapshot: LoggingPolicySnapshot,
    *,
    requested_modes: tuple[LoggingMode, ...] | None = None,
    generation: int = 1,
) -> EffectiveLoggingPolicy:
    requested = requested_modes or policy.modes
    required = mode_requirements(requested)
    missing = required - policy.capture.capabilities
    overrides: list[LoggingPolicyOverride] = []
    warnings: list[str] = []
    effective_modes = requested
    capabilities = policy.capture.capabilities
    if missing:
        if policy.conflict_action is PolicyConflictAction.APPLY_REQUIRED_OVERRIDES:
            capabilities = frozenset(set(capabilities) | set(missing))
            for capability in sorted(missing, key=lambda item: item.name):
                modes = tuple(mode for mode in requested if capability in _MODE_REQUIREMENTS[mode])
                overrides.append(LoggingPolicyOverride(
                    field_path=f"capture.capabilities.{capability.name.lower()}",
                    operator_value=False,
                    effective_value=True,
                    required_by_modes=modes,
                    required_capabilities=(capability,),
                    reason=f"{capability.name} is required for the requested Caretaker mode",
                    operational_effect="Enables the minimum structured evidence needed by the higher mode",
                    estimated_cost="mode dependent",
                ))
        elif policy.conflict_action is PolicyConflictAction.REFUSE_HIGHER_MODE:
            effective_modes = tuple(mode for mode in requested if not (_MODE_REQUIREMENTS[mode] & missing))
            warnings.append("One or more requested modes were refused because required logging capabilities are disabled")
        elif policy.conflict_action is PolicyConflictAction.FALL_BACK_TO_APPLICATION_LOGGING:
            effective_modes = (LoggingMode.APPLICATION,)
            capabilities = frozenset(set(policy.capture.capabilities) | set(_MODE_REQUIREMENTS[LoggingMode.APPLICATION]))
            warnings.append("Fell back to application logging because higher-mode requirements conflict with operator policy")
        else:
            raise PermissionError("Logging policy conflicts require interactive operator approval")
    effective_policy = replace(policy, modes=effective_modes, capture=replace(policy.capture, capabilities=capabilities))
    return EffectiveLoggingPolicy(
        operator_policy_snapshot_id=snapshot.snapshot_id,
        mode_requirements_version=MODE_REQUIREMENTS_VERSION,
        requested_modes=requested,
        effective_modes=effective_modes,
        effective_policy=effective_policy,
        overrides=tuple(overrides),
        warnings=tuple(warnings),
        conflict_action=policy.conflict_action,
        generation=generation,
    )


class ModeLeaseManager:
    def __init__(self, policy: OperatorLoggingPolicy, snapshot: LoggingPolicySnapshot) -> None:
        self._base = policy
        self._snapshot = snapshot
        self._leases: dict[UUID, ModeLease] = {}
        self._generation = 0
        self._lock = RLock()
        self._effective = reconcile_policy(policy, snapshot, generation=1)
        self._generation = 1

    @property
    def effective(self) -> EffectiveLoggingPolicy:
        with self._lock:
            return self._effective

    def acquire(
        self,
        mode: LoggingMode,
        *,
        scope: str = "application",
        requested_by: str,
        reason: str,
        duration_seconds: float | None = None,
        work_id: UUID | None = None,
    ) -> ModeLease:
        with self._lock:
            before = self._generation
            requested_modes = tuple(dict.fromkeys((*self._base.modes, *(lease.requested_mode for lease in self._leases.values()), mode)))
            self._generation += 1
            effective = reconcile_policy(self._base, self._snapshot, requested_modes=requested_modes, generation=self._generation)
            lease = ModeLease(
                lease_id=uuid4(), requested_mode=mode, scope=scope, requested_by=requested_by,
                requested_at=datetime.now(timezone.utc), reason=reason,
                expires_at=(datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)) if duration_seconds else None,
                release_condition=None, policy_generation_before=before,
                effective_policy_generation=self._generation,
                required_overrides=tuple(item for item in effective.overrides if mode in item.required_by_modes),
                work_id=work_id,
            )
            self._leases[lease.lease_id] = lease
            self._effective = effective
            return lease

    def release(self, lease_id: UUID) -> EffectiveLoggingPolicy:
        with self._lock:
            self._leases.pop(lease_id)
            requested_modes = tuple(dict.fromkeys((*self._base.modes, *(lease.requested_mode for lease in self._leases.values()))))
            self._generation += 1
            self._effective = reconcile_policy(self._base, self._snapshot, requested_modes=requested_modes, generation=self._generation)
            return self._effective

    def expire(self, now: datetime | None = None) -> tuple[UUID, ...]:
        now = now or datetime.now(timezone.utc)
        expired = tuple(lease_id for lease_id, lease in self._leases.items() if lease.expires_at and lease.expires_at <= now)
        for lease_id in expired:
            self.release(lease_id)
        return expired

    def update_base(self, policy: OperatorLoggingPolicy, snapshot: LoggingPolicySnapshot) -> EffectiveLoggingPolicy:
        with self._lock:
            self._base = policy
            self._snapshot = snapshot
            requested_modes = tuple(dict.fromkeys((*policy.modes, *(lease.requested_mode for lease in self._leases.values()))))
            self._generation += 1
            self._effective = reconcile_policy(policy, snapshot, requested_modes=requested_modes, generation=self._generation)
            return self._effective


def policy_security_warnings(
    snapshot: LoggingPolicySnapshot,
    *,
    application_uid: int | None = None,
) -> tuple[str, ...]:
    if snapshot.source_path is None:
        return ()
    application_uid = os.getuid() if application_uid is None and hasattr(os, "getuid") else application_uid
    warnings: list[str] = []
    path = Path(snapshot.source_path)
    try:
        info = path.stat()
        if application_uid is not None and info.st_uid == application_uid:
            warnings.append("The logging policy is owned by the application user and can be modified by the application process")
        if info.st_mode & 0o022:
            warnings.append("The logging policy is group- or world-writable")
        parent = path.parent
        parent_info = parent.stat()
        if parent_info.st_mode & 0o002:
            warnings.append("The logging policy directory is world-writable")
        if path.is_symlink():
            warnings.append(f"The logging policy is a symbolic link resolving to {path.resolve()}")
    except OSError as exc:
        warnings.append(f"Unable to inspect logging policy ownership and permissions: {type(exc).__name__}: {exc}")
    return tuple(warnings)


class OperatorPolicyWatcher:
    """Poll and atomically apply complete operator-policy documents."""

    def __init__(
        self,
        path: str | Path,
        *,
        on_policy: callable,
        on_error: callable | None = None,
        interval_seconds: float = 30.0,
    ) -> None:
        import threading
        self.path = Path(path)
        self.on_policy = on_policy
        self.on_error = on_error
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        try:
            self._mtime_ns = self.path.stat().st_mtime_ns
        except OSError:
            self._mtime_ns = None

    def start(self) -> None:
        import threading
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="caretaker-policy-watcher", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                mtime = self.path.stat().st_mtime_ns
                if mtime == self._mtime_ns:
                    continue
                policy, snapshot = load_operator_policy(self.path)
                self.on_policy(policy, snapshot)
                self._mtime_ns = mtime
            except Exception as exc:
                if self.on_error is not None:
                    self.on_error(exc)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=max(1.0, self.interval_seconds + 1.0))
