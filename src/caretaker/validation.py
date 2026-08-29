from __future__ import annotations

from .adaptive import lightweight_dependency
import ast
import json
import math
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from .domain import (
    CheckOutcome,
    RepairArtifactKind,
    RepairCandidate,
    ValidationCheckKind,
    ValidationCheckResult,
    ValidationBackendUnavailableAction,
    ValidationIsolationLevel,
    utcnow,
)
from .registry import RepairTarget


@dataclass(frozen=True, slots=True)
class StaticAssessment:
    hard_disqualifications: tuple[str, ...]
    review_required_findings: tuple[str, ...]
    risk_findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationReport:
    candidate_id: object
    eligible: bool
    checks: tuple[ValidationCheckResult, ...]
    measurements: dict[str, float]
    risk_findings: tuple[str, ...]
    hard_disqualifications: tuple[str, ...] = ()
    review_required_findings: tuple[str, ...] = ()
    worker_stdout: str = ""
    worker_stderr: str = ""
    backend_name: str = "process"
    isolation_level: ValidationIsolationLevel = ValidationIsolationLevel.PROCESS
    backend_available: bool = True
    requires_operator_approval: bool = False
    proposal_only: bool = False


@dataclass(frozen=True, slots=True)
class ValidationBackendCapabilities:
    name: str
    isolation_level: ValidationIsolationLevel
    separate_kernel: bool = False
    rootless: bool | None = None
    network_control: bool = False
    resource_control: bool = False
    ephemeral_workspace: bool = True
    details: dict[str, Any] | None = None


class ValidationBackend(Protocol):
    def capabilities(self) -> ValidationBackendCapabilities: ...
    def available(self) -> tuple[bool, str | None]: ...
    def validate_candidate(
        self, candidate: RepairCandidate, target: RepairTarget, *, timeout_seconds: float,
        regression_cases: tuple[Any, ...] = (),
    ) -> ValidationReport: ...


class ValidationBackendRegistry:
    """Capability-based validation backend selector.

    The lowest available backend satisfying the policy minimum is preferred so
    ordinary repairs do not pay for VM isolation unnecessarily. If no sufficient
    backend is available, the strongest configured backend is returned so its
    normal fail-closed unavailable report can explain the unmet requirement.
    """

    def __init__(self, backends: tuple[ValidationBackend, ...]) -> None:
        if not backends:
            raise ValueError("at least one validation backend is required")
        self.backends = tuple(backends)

    def select(self, minimum: ValidationIsolationLevel) -> ValidationBackend:
        ordered = sorted(
            self.backends,
            key=lambda item: int(item.capabilities().isolation_level),
        )
        sufficient = [
            item for item in ordered
            if item.capabilities().isolation_level >= minimum
        ]
        for item in sufficient:
            available, _reason = item.available()
            if available:
                return item
        if sufficient:
            return sufficient[0]
        # No configured backend can satisfy the policy. Use the strongest one so
        # validation emits the existing explicit insufficient-isolation report.
        return ordered[-1]

    def capabilities(self) -> tuple[ValidationBackendCapabilities, ...]:
        return tuple(item.capabilities() for item in self.backends)


_FUNCTION_VALIDATION_CHECKS = frozenset({
    ValidationCheckKind.RESPONSE_STRUCTURE,
    ValidationCheckKind.AST_PARSE,
    ValidationCheckKind.FUNCTION_NAME,
    ValidationCheckKind.SIGNATURE,
    ValidationCheckKind.CALLABLE_KIND,
    ValidationCheckKind.COMPILE,
    ValidationCheckKind.REGISTERED_TESTS,
    ValidationCheckKind.GENERATED_TESTS,
    ValidationCheckKind.PERFORMANCE,
})


class SubprocessValidationBackend:
    def __init__(self, python_executable: str | None = None) -> None:
        self.python_executable = python_executable or sys.executable

    def capabilities(self) -> ValidationBackendCapabilities:
        return ValidationBackendCapabilities(
            name="process",
            isolation_level=ValidationIsolationLevel.PROCESS,
            separate_kernel=False,
            rootless=None,
            network_control=False,
            resource_control=True,
            ephemeral_workspace=True,
            details={"python_executable": self.python_executable},
        )

    def available(self) -> tuple[bool, str | None]:
        return True, None

    def _backend_unavailable_report(
        self,
        candidate: RepairCandidate,
        target: RepairTarget,
        *,
        reason: str,
        assessment: StaticAssessment,
    ) -> ValidationReport:
        capabilities = self.capabilities()
        required = target.policy.validation.minimum_isolation
        action = target.policy.validation.backend_unavailable_action
        now = utcnow()
        summary = (
            f"Validation backend {capabilities.name!r} cannot satisfy required isolation "
            f"{required.name}: {reason}"
        )
        check = ValidationCheckResult(
            kind=ValidationCheckKind.STATIC_POLICY,
            outcome=CheckOutcome.FAILED,
            started_at=now,
            finished_at=now,
            summary=summary,
            details={
                "backend": capabilities.name,
                "backend_isolation": capabilities.isolation_level.name,
                "required_isolation": required.name,
                "unavailable_action": action.name,
            },
        )
        hard = list(assessment.hard_disqualifications)
        review = list(assessment.review_required_findings)
        requires_approval = False
        proposal_only = False
        if action is ValidationBackendUnavailableAction.FAIL_REPAIR:
            hard.append(summary)
        elif action is ValidationBackendUnavailableAction.PROPOSE_ONLY:
            proposal_only = True
            review.append(summary + "; candidate retained as proposal only")
        elif action is ValidationBackendUnavailableAction.REQUIRE_OPERATOR_APPROVAL:
            requires_approval = not hard
            review.append(summary + "; explicit operator approval is required to proceed without this backend")
        return ValidationReport(
            candidate_id=candidate.candidate_id,
            eligible=False,
            checks=(check,),
            measurements={},
            risk_findings=assessment.risk_findings + (summary,),
            hard_disqualifications=tuple(dict.fromkeys(hard)),
            review_required_findings=tuple(dict.fromkeys(review)),
            backend_name=capabilities.name,
            isolation_level=capabilities.isolation_level,
            backend_available=False,
            requires_operator_approval=requires_approval,
            proposal_only=proposal_only,
        )

    def validate_candidate(
        self,
        candidate: RepairCandidate,
        target: RepairTarget,
        *,
        timeout_seconds: float,
        regression_cases: tuple[Any, ...] = (),
    ) -> ValidationReport:
        if candidate.artifact.kind is not RepairArtifactKind.FUNCTION_REPLACEMENT:
            now = utcnow()
            check = ValidationCheckResult(
                kind=ValidationCheckKind.RESPONSE_STRUCTURE,
                outcome=CheckOutcome.FAILED,
                started_at=now,
                finished_at=now,
                summary=f"Unsupported repair artifact kind: {candidate.artifact.kind.name}",
            )
            return ValidationReport(
                candidate_id=candidate.candidate_id,
                eligible=False,
                checks=(check,),
                measurements={},
                risk_findings=(),
                hard_disqualifications=(check.summary,),
                backend_name=self.capabilities().name,
                isolation_level=self.capabilities().isolation_level,
            )

        source = candidate.artifact.files[0].content
        assessment = assess_candidate_source(source)
        capabilities = self.capabilities()
        available, unavailable_reason = self.available()
        if not available:
            return self._backend_unavailable_report(
                candidate, target, reason=unavailable_reason or "backend is unavailable", assessment=assessment
            )
        if capabilities.isolation_level < target.policy.validation.minimum_isolation:
            return self._backend_unavailable_report(
                candidate,
                target,
                reason=(
                    f"backend provides {capabilities.isolation_level.name}, "
                    f"policy requires at least {target.policy.validation.minimum_isolation.name}"
                ),
                assessment=assessment,
            )
        registered_cases = (
            target.registered_cases + tuple(regression_cases)
            if target.policy.validation.run_registered_tests
            else ()
        )
        generated_tests = (
            tuple(test.source for test in candidate.generated_tests)
            if target.policy.validation.run_generated_tests
            else ()
        )
        payload = {
            "mode": "function",
            "source": source,
            "entrypoint": candidate.artifact.entrypoint,
            "module_name": target.source.module_name,
            "qualified_name": target.source.qualified_name,
            "signature_text": target.contract.signature_text,
            "callable_kind": target.contract.kind.name,
            "allow_imports": target.policy.validation.allow_imports,
            "allow_network": target.policy.validation.allow_network,
            "allow_subprocesses": target.policy.validation.allow_subprocesses,
            "allow_filesystem_writes": target.policy.validation.allow_filesystem_writes,
            "registered_cases": registered_cases,
            "generated_tests": generated_tests,
            "run_registered_tests": target.policy.validation.run_registered_tests,
            "run_generated_tests": target.policy.validation.run_generated_tests,
        }
        result = self._run_worker(payload, timeout_seconds=timeout_seconds)
        protocol_findings: list[str] = []
        raw_checks = result.get("checks", [])
        checks_list: list[ValidationCheckResult] = []
        if not isinstance(raw_checks, (list, tuple)):
            protocol_findings.append("validation worker checks must be a list")
            raw_checks = []
        for item in raw_checks:
            if not isinstance(item, dict):
                protocol_findings.append("validation worker returned a malformed check")
                continue
            try:
                checks_list.append(_check_from_dict(item))
            except (KeyError, TypeError, ValueError):
                protocol_findings.append("validation worker returned an unknown or malformed check")
        checks = tuple(checks_list)
        check_kinds = [check.kind for check in checks]
        duplicate_kinds = sorted(
            {kind.name for kind in check_kinds if check_kinds.count(kind) > 1}
        )
        if duplicate_kinds:
            protocol_findings.append(
                "validation worker returned duplicate checks: " + ", ".join(duplicate_kinds)
            )
        missing_kinds = sorted(
            (kind.name for kind in _FUNCTION_VALIDATION_CHECKS if kind not in check_kinds),
        )
        if missing_kinds:
            protocol_findings.append(
                "validation worker omitted mandatory checks: " + ", ".join(missing_kinds)
            )
        mandatory_failures = [
            check
            for check in checks
            if check.outcome in {CheckOutcome.FAILED, CheckOutcome.ERROR}
            and check.kind not in {
                ValidationCheckKind.PERFORMANCE,
                ValidationCheckKind.GENERATED_TESTS,
            }
        ]
        hard = tuple(
            dict.fromkeys(
                assessment.hard_disqualifications
                + tuple(result.get("hard_disqualifications", ()))
            )
        )
        review = tuple(
            dict.fromkeys(
                assessment.review_required_findings
                + tuple(result.get("review_required_findings", ()))
            )
        )
        raw_measurements = result.get("measurements", {})
        measurements: dict[str, float] = {}
        if not isinstance(raw_measurements, dict):
            protocol_findings.append("validation worker measurements must be an object")
        else:
            for key, value in raw_measurements.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    protocol_findings.append(
                        f"validation worker measurement {key!r} is not a finite number"
                    )
                    continue
                number = float(value)
                if not math.isfinite(number):
                    protocol_findings.append(
                        f"validation worker measurement {key!r} is not a finite number"
                    )
                    continue
                measurements[str(key)] = number
        if protocol_findings:
            protocol_summary = "; ".join(dict.fromkeys(protocol_findings))
            hard = tuple(dict.fromkeys(hard + (protocol_summary,)))
        eligible = bool(result.get("eligible", False)) and not mandatory_failures and not hard and not review
        return ValidationReport(
            candidate_id=candidate.candidate_id,
            eligible=eligible,
            checks=checks,
            measurements=measurements,
            risk_findings=tuple(
                dict.fromkeys(
                    assessment.risk_findings
                    + tuple(result.get("risk_findings", ()))
                )
            ),
            hard_disqualifications=hard,
            review_required_findings=review,
            worker_stdout=result.get("worker_stdout", ""),
            worker_stderr=result.get("worker_stderr", ""),
            backend_name=capabilities.name,
            isolation_level=capabilities.isolation_level,
            backend_available=True,
        )

    def validate_auxiliary(
        self,
        *,
        source: str,
        entrypoint: str,
        valid_examples: tuple[Any, ...],
        invalid_examples: tuple[Any, ...],
        timeout_seconds: float,
        maximum_runtime_seconds: float,
    ) -> dict[str, Any]:
        payload = {
            "mode": "auxiliary_validator",
            "source": source,
            "entrypoint": entrypoint,
            "valid_examples": valid_examples,
            "invalid_examples": invalid_examples,
            "maximum_runtime_seconds": maximum_runtime_seconds,
        }
        return self._run_worker(payload, timeout_seconds=timeout_seconds)

    @lightweight_dependency(target_id="caretaker.dependency.subprocess.validation-worker")
    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="caretaker-validation-") as temporary:
            temp = Path(temporary)
            input_path, output_path = _write_worker_request(temp, payload)
            environment = {
                "PYTHONPATH": os.pathsep.join(
                    (os.getcwd() if item == "" else item)
                    for item in sys.path
                    if isinstance(item, str)
                ),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            command = [
                self.python_executable,
                "-m",
                "caretaker.validation_worker",
                str(input_path),
                str(output_path),
            ]
            return _run_worker_command(
                command,
                output_path=output_path,
                timeout_seconds=timeout_seconds,
                cwd=temporary,
                env=environment,
            )


class RootlessPodmanValidationBackend(SubprocessValidationBackend):
    """Run a validation worker in a constrained rootless Podman container.

    The backend never pulls images.  The operator must provision a trusted image
    containing Python and any application dependencies that are not provided by
    the read-only workspace/source mounts.
    """

    def __init__(
        self,
        image: str,
        *,
        podman_executable: str = "podman",
        cgroup_manager: str = "cgroupfs",
        workspace: str | Path | None = None,
        additional_read_only_paths: tuple[str | Path, ...] = (),
        memory: str = "512m",
        cpus: float = 1.0,
        pids_limit: int = 64,
        tmpfs_size: str = "64m",
    ) -> None:
        super().__init__(python_executable="python")
        if not image.strip():
            raise ValueError("A pre-provisioned Podman validation image is required")
        if cpus <= 0:
            raise ValueError("cpus must be > 0")
        if pids_limit < 1:
            raise ValueError("pids_limit must be >= 1")
        if cgroup_manager not in {"cgroupfs", "systemd"}:
            raise ValueError("cgroup_manager must be 'cgroupfs' or 'systemd'")
        self.image = image
        self.podman_executable = podman_executable
        self.cgroup_manager = cgroup_manager
        self.workspace = Path(workspace or os.getcwd()).resolve()
        self.additional_read_only_paths = tuple(
            Path(item).resolve() for item in additional_read_only_paths
        )
        self.memory = memory
        self.cpus = float(cpus)
        self.pids_limit = int(pids_limit)
        self.tmpfs_size = tmpfs_size
        self._availability_details: dict[str, Any] = {}

    def capabilities(self) -> ValidationBackendCapabilities:
        details = {
            "image": self.image,
            "workspace": str(self.workspace),
            "cgroup_manager": self.cgroup_manager,
            "network": "none",
            "read_only_root": True,
            "capabilities_dropped": "ALL",
            **self._availability_details,
        }
        return ValidationBackendCapabilities(
            name="podman-rootless",
            isolation_level=ValidationIsolationLevel.CONTAINER,
            separate_kernel=False,
            rootless=True,
            network_control=True,
            resource_control=True,
            ephemeral_workspace=True,
            details=details,
        )

    def available(self) -> tuple[bool, str | None]:
        executable = shutil.which(self.podman_executable)
        if executable is None and not Path(self.podman_executable).is_file():
            return False, f"Podman executable {self.podman_executable!r} was not found"
        try:
            info = subprocess.run(
                [self.podman_executable, "info", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Podman information query failed: {exc}"
        if info.returncode != 0:
            return False, f"Podman information query failed: {info.stderr[-1000:]}"
        try:
            payload = json.loads(info.stdout or "{}")
        except json.JSONDecodeError as exc:
            return False, f"Podman returned invalid JSON: {exc}"
        rootless = _find_json_boolean(payload, "rootless")
        if rootless is not True:
            return False, "Podman validation requires rootless mode"
        image = subprocess.run(
            [self.podman_executable, "image", "exists", self.image],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            close_fds=True,
        )
        if image.returncode != 0:
            return False, f"Podman validation image {self.image!r} is not present locally"
        digest = subprocess.run(
            [
                self.podman_executable,
                "image",
                "inspect",
                self.image,
                "--format",
                "{{.Digest}}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            close_fds=True,
        )
        if digest.returncode == 0 and digest.stdout.strip():
            self._availability_details["image_digest"] = digest.stdout.strip()
        self._availability_details["rootless_verified"] = True
        return True, None

    def _build_command(self, host_workdir: Path) -> list[str]:
        source_root = Path(__file__).resolve().parents[1]
        mounts: list[tuple[Path, str, bool]] = [
            (host_workdir, "/work", False),
            (source_root, "/opt/caretaker-src", True),
        ]
        python_paths = ["/opt/caretaker-src"]
        if self.workspace != source_root:
            mounts.append((self.workspace, "/workspace", True))
            python_paths.append("/workspace")
        for index, path in enumerate(self.additional_read_only_paths):
            destination = f"/inputs/{index}"
            mounts.append((path, destination, True))
            python_paths.append(destination)

        command = [
            self.podman_executable,
            f"--cgroup-manager={self.cgroup_manager}",
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--pids-limit={self.pids_limit}",
            f"--memory={self.memory}",
            f"--cpus={self.cpus:g}",
            "--userns=keep-id",
            f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={self.tmpfs_size}",
        ]
        for source, destination, read_only in mounts:
            options = f"type=bind,src={source},dst={destination}"
            options += ",ro=true" if read_only else ",rw=true"
            command.extend(("--mount", options))
        command.extend(
            (
                "--workdir=/work",
                "--env",
                f"PYTHONPATH={':'.join(python_paths)}",
                "--env",
                "PYTHONIOENCODING=utf-8",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
                self.image,
                "python",
                "-m",
                "caretaker.validation_worker",
                "/work/request.pickle",
                "/work/result.json",
            )
        )
        return command

    @lightweight_dependency(target_id="caretaker.dependency.podman.validation-worker")
    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="caretaker-podman-validation-") as temporary:
            temp = Path(temporary)
            _, output_path = _write_worker_request(temp, payload)
            command = self._build_command(temp)
            host_environment = {
                key: os.environ[key]
                for key in (
                    "PATH",
                    "HOME",
                    "XDG_RUNTIME_DIR",
                    "DBUS_SESSION_BUS_ADDRESS",
                    "CONTAINERS_CONF",
                    "CONTAINERS_STORAGE_CONF",
                    "REGISTRY_AUTH_FILE",
                )
                if key in os.environ
            }
            return _run_worker_command(
                command,
                output_path=output_path,
                timeout_seconds=timeout_seconds,
                cwd=temporary,
                env=host_environment,
            )


class MultipassValidationBackend(SubprocessValidationBackend):
    """Run validation in a pre-provisioned Multipass VM.

    The validator VM is expected to contain Caretaker, the target application,
    and its dependencies.  Host paths are copied with ``multipass transfer``;
    host-directory mounts are treated as an availability failure.
    """

    def __init__(
        self,
        *,
        instance_name: str = "caretaker-validator",
        multipass_executable: str = "multipass",
        python_executable: str = "/opt/caretaker/venv/bin/python",
        subject_user: str = "caretaker-subject",
        clean_snapshot: str | None = "caretaker-clean",
        restore_before_validation: bool = True,
        disposable_clone: bool = False,
        require_network_isolation: bool = True,
        network_policy_marker: str = "/etc/caretaker/validation-network-isolated",
        operation_timeout_seconds: float = 60.0,
    ) -> None:
        super().__init__(python_executable=python_executable)
        if not instance_name.strip():
            raise ValueError("instance_name cannot be empty")
        if operation_timeout_seconds <= 0:
            raise ValueError("operation_timeout_seconds must be > 0")
        self.instance_name = instance_name
        self.multipass_executable = multipass_executable
        self.subject_user = subject_user
        self.clean_snapshot = clean_snapshot
        self.restore_before_validation = bool(restore_before_validation)
        self.disposable_clone = bool(disposable_clone)
        self.require_network_isolation = bool(require_network_isolation)
        self.network_policy_marker = network_policy_marker
        self.operation_timeout_seconds = float(operation_timeout_seconds)
        self._lock = threading.RLock()
        self._availability_details: dict[str, Any] = {}

    def capabilities(self) -> ValidationBackendCapabilities:
        details = {
            "instance": self.instance_name,
            "clean_snapshot": self.clean_snapshot,
            "restore_before_validation": self.restore_before_validation,
            "disposable_clone": self.disposable_clone,
            "host_mounts_allowed": False,
            "subject_user": self.subject_user,
            "network_policy_marker": (
                self.network_policy_marker if self.require_network_isolation else None
            ),
            **self._availability_details,
        }
        return ValidationBackendCapabilities(
            name="multipass",
            isolation_level=ValidationIsolationLevel.VM,
            separate_kernel=True,
            rootless=None,
            network_control=self.require_network_isolation,
            resource_control=True,
            ephemeral_workspace=True,
            details=details,
        )

    def _host_command(
        self,
        command: list[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout or self.operation_timeout_seconds,
            check=False,
            close_fds=True,
        )

    def available(self) -> tuple[bool, str | None]:
        executable = shutil.which(self.multipass_executable)
        if executable is None and not Path(self.multipass_executable).is_file():
            return False, f"Multipass executable {self.multipass_executable!r} was not found"
        info = self._host_command(
            [self.multipass_executable, "info", "--format", "json", self.instance_name]
        )
        if info.returncode != 0:
            return False, f"Multipass validator instance {self.instance_name!r} is unavailable: {info.stderr[-1000:]}"
        try:
            payload = json.loads(info.stdout or "{}")
        except json.JSONDecodeError as exc:
            return False, f"Multipass returned invalid JSON: {exc}"
        instance = _find_multipass_instance(payload, self.instance_name)
        if instance is None:
            return False, f"Multipass did not report validator instance {self.instance_name!r}"
        mounts = instance.get("mounts")
        if mounts:
            return False, "Multipass validation refuses instances with host-directory mounts"
        self._availability_details = {
            "image_hash": instance.get("image_hash") or instance.get("image_release"),
            "state": instance.get("state"),
        }
        state = str(instance.get("state", "")).upper()
        if self.disposable_clone:
            if state not in {"STOPPED", "OFF"}:
                return False, "Multipass disposable-clone mode requires a stopped template instance"
        elif state in {"RUNNING", "STARTED"}:
            ready, reason = self._verify_guest_prerequisites(self.instance_name)
            if not ready:
                return False, reason
        if self.clean_snapshot and self.restore_before_validation and not self.disposable_clone:
            snapshot = self._host_command(
                [
                    self.multipass_executable,
                    "info",
                    f"{self.instance_name}.{self.clean_snapshot}",
                ]
            )
            if snapshot.returncode != 0:
                return False, (
                    f"Required Multipass snapshot {self.instance_name}.{self.clean_snapshot} is unavailable"
                )
        return True, None

    def _verify_guest_prerequisites(self, instance: str) -> tuple[bool, str | None]:
        ready = self._guest_command(instance, ["test", "-x", self.python_executable])
        if ready.returncode != 0:
            return False, f"Validation Python {self.python_executable!r} is unavailable in Multipass guest"
        user = self._guest_command(instance, ["id", "-u", self.subject_user])
        if user.returncode != 0:
            return False, f"Validation subject user {self.subject_user!r} is unavailable in Multipass guest"
        if self.require_network_isolation:
            marker = self._guest_command(
                instance,
                ["stat", "-c", "%u %a", self.network_policy_marker],
            )
            if marker.returncode != 0:
                return False, (
                    "Multipass validation requires the root-owned network-isolation marker "
                    f"{self.network_policy_marker!r}"
                )
            fields = marker.stdout.strip().split()
            if len(fields) != 2 or fields[0] != "0":
                return False, "Multipass network-isolation marker must be owned by root"
            try:
                permissions = int(fields[1], 8)
            except ValueError:
                return False, "Multipass network-isolation marker has invalid permissions"
            if permissions & 0o022:
                return False, "Multipass network-isolation marker must not be group/world writable"
        return True, None

    def _restore_clean_instance(self, instance: str) -> tuple[bool, str | None]:
        if not self.clean_snapshot or not self.restore_before_validation:
            return True, None
        commands = (
            [self.multipass_executable, "stop", instance],
            [
                self.multipass_executable,
                "restore",
                "--destructive",
                f"{instance}.{self.clean_snapshot}",
            ],
            [self.multipass_executable, "start", instance],
            [self.multipass_executable, "wait-ready", instance],
        )
        for command in commands:
            completed = self._host_command(command)
            if completed.returncode != 0:
                return False, f"Multipass preparation failed: {' '.join(command)}: {completed.stderr[-1000:]}"
        return True, None

    def _create_disposable_clone(self) -> tuple[str | None, str | None]:
        name = f"caretaker-val-{uuid4().hex[:12]}"
        clone = self._host_command(
            [
                self.multipass_executable,
                "clone",
                self.instance_name,
                "--name",
                name,
            ]
        )
        if clone.returncode != 0:
            return None, f"Multipass clone failed: {clone.stderr[-1000:]}"
        for command in (
            [self.multipass_executable, "start", name],
            [self.multipass_executable, "wait-ready", name],
        ):
            completed = self._host_command(command)
            if completed.returncode != 0:
                self._destroy_disposable_clone(name)
                return None, f"Multipass clone preparation failed: {completed.stderr[-1000:]}"
        return name, None

    def _destroy_disposable_clone(self, instance: str) -> None:
        self._host_command([self.multipass_executable, "delete", "--purge", instance])

    def _guest_command(
        self,
        instance: str,
        command: list[str],
        *,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._host_command(
            [self.multipass_executable, "exec", instance, "--", *command],
            timeout=timeout,
        )

    def _run_in_instance(
        self,
        instance: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        token = uuid4().hex
        guest_directory = f"/var/lib/caretaker/validation/{token}"
        guest_input = f"{guest_directory}/request.pickle"
        guest_output = f"{guest_directory}/result.json"
        guest_transfer = f"/tmp/caretaker-validation-{token}.pickle"
        with tempfile.TemporaryDirectory(prefix="caretaker-multipass-validation-") as temporary:
            temp = Path(temporary)
            input_path, output_path = _write_worker_request(temp, payload)
            setup = self._guest_command(
                instance,
                [
                    "sudo",
                    "install",
                    "-d",
                    "-o",
                    self.subject_user,
                    "-g",
                    self.subject_user,
                    "-m",
                    "0700",
                    guest_directory,
                ],
            )
            if setup.returncode != 0:
                return _worker_transport_error("Multipass guest workspace creation failed", setup)
            try:
                transfer = self._host_command(
                    [
                        self.multipass_executable,
                        "transfer",
                        str(input_path),
                        f"{instance}:{guest_transfer}",
                    ]
                )
                if transfer.returncode != 0:
                    return _worker_transport_error("Multipass request transfer failed", transfer)
                install = self._guest_command(
                    instance,
                    [
                        "sudo",
                        "install",
                        "-o",
                        self.subject_user,
                        "-g",
                        self.subject_user,
                        "-m",
                        "0600",
                        guest_transfer,
                        guest_input,
                    ],
                )
                if install.returncode != 0:
                    return _worker_transport_error("Multipass request installation failed", install)
                self._guest_command(instance, ["sudo", "rm", "-f", guest_transfer])
                command = [
                    "sudo",
                    "-u",
                    self.subject_user,
                    "--",
                    "env",
                    "HOME=/var/lib/caretaker",
                    "PYTHONIOENCODING=utf-8",
                    "PYTHONDONTWRITEBYTECODE=1",
                    self.python_executable,
                    "-m",
                    "caretaker.validation_worker",
                    guest_input,
                    guest_output,
                ]
                try:
                    completed = self._guest_command(
                        instance,
                        command,
                        timeout=timeout_seconds,
                    )
                except subprocess.TimeoutExpired as exc:
                    return _worker_timeout_result(timeout_seconds, exc)
                transfer_result = self._host_command(
                    [
                        self.multipass_executable,
                        "transfer",
                        f"{instance}:{guest_output}",
                        str(output_path),
                    ]
                )
                if transfer_result.returncode != 0 and not output_path.exists():
                    return _worker_protocol_error(
                        completed,
                        summary="Multipass validation worker did not produce a transferable result.",
                    )
                return _load_worker_result(output_path, completed)
            finally:
                self._guest_command(instance, ["sudo", "rm", "-rf", guest_directory])
                self._guest_command(instance, ["sudo", "rm", "-f", guest_transfer])

    @lightweight_dependency(target_id="caretaker.dependency.multipass.validation-worker")
    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with self._lock:
            instance = self.instance_name
            disposable = False
            if self.disposable_clone:
                instance, reason = self._create_disposable_clone()
                if instance is None:
                    return _worker_backend_error(reason or "Multipass disposable clone could not be created")
                disposable = True
            else:
                restored, reason = self._restore_clean_instance(instance)
                if not restored:
                    return _worker_backend_error(reason or "Multipass validator could not be restored")
            try:
                ready, reason = self._verify_guest_prerequisites(instance)
                if not ready:
                    return _worker_backend_error(reason or "Multipass guest prerequisites are unavailable")
                return self._run_in_instance(
                    instance,
                    payload,
                    timeout_seconds=timeout_seconds,
                )
            finally:
                if disposable:
                    self._destroy_disposable_clone(instance)


def _write_worker_request(temp: Path, payload: dict[str, Any]) -> tuple[Path, Path]:
    input_path = temp / "request.pickle"
    output_path = temp / "result.json"
    with input_path.open("wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    return input_path, output_path


def _worker_timeout_result(timeout_seconds: float, exc: subprocess.TimeoutExpired) -> dict[str, Any]:
    now = utcnow()
    timeout_check = ValidationCheckResult(
        kind=ValidationCheckKind.PERFORMANCE,
        outcome=CheckOutcome.FAILED,
        started_at=now - timedelta(seconds=timeout_seconds),
        finished_at=now,
        summary=f"Validation worker exceeded {timeout_seconds:g}s timeout.",
        error_type="TimeoutExpired",
        error_message=str(exc),
    )
    return {
        "eligible": False,
        "checks": [_check_to_dict(timeout_check)],
        "measurements": {},
        "risk_findings": ["validation worker timed out"],
        "hard_disqualifications": [],
        "review_required_findings": [],
        "worker_stdout": _bounded_stream(exc.stdout),
        "worker_stderr": _bounded_stream(exc.stderr),
    }


def _worker_protocol_error(
    completed: subprocess.CompletedProcess[str],
    *,
    summary: str = "Validation worker did not produce a result.",
) -> dict[str, Any]:
    now = utcnow()
    return {
        "eligible": False,
        "checks": [
            _check_to_dict(
                ValidationCheckResult(
                    kind=ValidationCheckKind.COMPILE,
                    outcome=CheckOutcome.ERROR,
                    started_at=now,
                    finished_at=now,
                    summary=summary,
                    details={"returncode": completed.returncode},
                    error_type="WorkerProtocolError",
                    error_message=_bounded_stream(completed.stderr, 2000),
                )
            )
        ],
        "measurements": {},
        "risk_findings": ["validation worker crashed or corrupted its protocol"],
        "hard_disqualifications": [],
        "review_required_findings": [],
        "worker_stdout": _bounded_stream(completed.stdout),
        "worker_stderr": _bounded_stream(completed.stderr),
    }


def _worker_transport_error(summary: str, completed: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    result = _worker_protocol_error(completed, summary=summary)
    result.setdefault("risk_findings", []).append("validation isolation transport failed")
    return result


def _worker_backend_error(summary: str) -> dict[str, Any]:
    now = utcnow()
    return {
        "eligible": False,
        "checks": [
            _check_to_dict(
                ValidationCheckResult(
                    kind=ValidationCheckKind.STATIC_POLICY,
                    outcome=CheckOutcome.ERROR,
                    started_at=now,
                    finished_at=now,
                    summary=summary,
                    error_type="ValidationBackendError",
                    error_message=summary,
                )
            )
        ],
        "measurements": {},
        "risk_findings": [summary],
        "hard_disqualifications": [summary],
        "review_required_findings": [],
        "worker_stdout": "",
        "worker_stderr": "",
    }


def _load_worker_result(
    output_path: Path,
    completed: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    if not output_path.exists():
        return _worker_protocol_error(completed)
    try:
        result = json.loads(output_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result = _worker_protocol_error(
            completed,
            summary=f"Validation worker produced an invalid result: {exc}",
        )
        return result
    result["worker_stdout"] = _bounded_stream(completed.stdout)
    result["worker_stderr"] = _bounded_stream(completed.stderr)
    if completed.returncode != 0:
        result["eligible"] = False
        result.setdefault("risk_findings", []).append(
            f"validation worker exited with status {completed.returncode}"
        )
    return result


def _run_worker_command(
    command: list[str],
    *,
    output_path: Path,
    timeout_seconds: float,
    cwd: str | Path | None,
    env: dict[str, str] | None,
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            close_fds=True,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        return _worker_timeout_result(timeout_seconds, exc)
    return _load_worker_result(output_path, completed)


def _bounded_stream(value: Any, limit: int = 20_000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return str(value)[-limit:]


def _find_json_boolean(payload: Any, key: str) -> bool | None:
    if isinstance(payload, dict):
        for current_key, value in payload.items():
            if str(current_key).lower() == key.lower() and isinstance(value, bool):
                return value
            found = _find_json_boolean(value, key)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _find_json_boolean(value, key)
            if found is not None:
                return found
    return None


def _find_multipass_instance(payload: Any, instance_name: str) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        info = payload.get("info")
        if isinstance(info, dict):
            direct = info.get(instance_name)
            if isinstance(direct, dict):
                return direct
        direct = payload.get(instance_name)
        if isinstance(direct, dict):
            return direct
        if payload.get("name") == instance_name:
            return payload
        for value in payload.values():
            found = _find_multipass_instance(value, instance_name)
            if found is not None:
                return found
    elif isinstance(payload, list):
        for value in payload:
            found = _find_multipass_instance(value, instance_name)
            if found is not None:
                return found
    return None


# Explicit name for new code; keep SubprocessValidationBackend for compatibility.
ProcessValidationBackend = SubprocessValidationBackend


_DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "system",
    "popen",
    "fork",
    "spawn",
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
}
_CONCURRENCY_PARTS = {"threading", "multiprocessing", "concurrent", "asyncio", "Thread", "Process"}


def assess_candidate_source(source: str) -> StaticAssessment:
    hard: list[str] = []
    review: list[str] = []
    risks: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return StaticAssessment((), (), ())
    definitions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            review.append("candidate introduces imports; manual approval is required")
            risks.append("candidate introduces imports")
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            leaf = name.split(".")[-1]
            if leaf in _DANGEROUS_CALLS:
                hard.append(f"candidate calls prohibited operation {name}")
            if any(part in _CONCURRENCY_PARTS for part in name.split(".")):
                review.append(f"candidate introduces concurrency through {name}")
                risks.append(f"candidate introduces concurrency through {name}")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            hard.append("candidate declares global or nonlocal state")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            hard.append(f"candidate accesses prohibited dunder attribute {node.attr}")
    for definition in definitions:
        defaults = tuple(definition.args.defaults) + tuple(
            item for item in definition.args.kw_defaults if item is not None
        )
        for default in defaults:
            if not _is_safe_literal(default):
                hard.append("candidate contains executable or non-literal default arguments")
        annotations: list[ast.expr] = []
        annotations.extend(
            arg.annotation
            for arg in (
                list(definition.args.posonlyargs)
                + list(definition.args.args)
                + list(definition.args.kwonlyargs)
            )
            if arg.annotation is not None
        )
        if definition.args.vararg and definition.args.vararg.annotation:
            annotations.append(definition.args.vararg.annotation)
        if definition.args.kwarg and definition.args.kwarg.annotation:
            annotations.append(definition.args.kwarg.annotation)
        if definition.returns is not None:
            annotations.append(definition.returns)
        for annotation in annotations:
            if not _is_safe_annotation(annotation):
                hard.append("candidate contains executable or unsupported annotation expressions")
    return StaticAssessment(
        hard_disqualifications=tuple(dict.fromkeys(hard)),
        review_required_findings=tuple(dict.fromkeys(review)),
        risk_findings=tuple(dict.fromkeys(risks)),
    )


def sanitized_function_tree(source: str) -> ast.Module:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.returns = None
            for arg in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                arg.annotation = None
            if node.args.vararg:
                node.args.vararg.annotation = None
            if node.args.kwarg:
                node.args.kwarg.annotation = None
    return ast.fix_missing_locations(tree)


def _is_safe_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_safe_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_safe_literal(key) and _is_safe_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_safe_literal(node.operand)
    return False


def _is_safe_annotation(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.Constant)):
        return True
    if isinstance(node, ast.Attribute):
        return not node.attr.startswith("__") and _is_safe_annotation(node.value)
    if isinstance(node, ast.Subscript):
        return _is_safe_annotation(node.value) and _is_safe_annotation(node.slice)
    if isinstance(node, ast.Tuple):
        return all(_is_safe_annotation(item) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_safe_annotation(node.left) and _is_safe_annotation(node.right)
    return False


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return "<dynamic>"


def _check_from_dict(payload: dict[str, Any]) -> ValidationCheckResult:
    return ValidationCheckResult(
        kind=ValidationCheckKind[payload["kind"]],
        outcome=CheckOutcome[payload["outcome"]],
        started_at=utcnow(),
        finished_at=utcnow(),
        summary=payload.get("summary", ""),
        details=payload.get("details", {}),
        error_type=payload.get("error_type"),
        error_message=payload.get("error_message"),
    )


def _check_to_dict(check: ValidationCheckResult) -> dict[str, Any]:
    return {
        "kind": check.kind.name,
        "outcome": check.outcome.name,
        "summary": check.summary,
        "details": dict(check.details),
        "error_type": check.error_type,
        "error_message": check.error_message,
    }
