from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from caretaker.domain import ValidationIsolationLevel
from caretaker.validation import (
    MultipassValidationBackend,
    RootlessDockerValidationBackend,
    RootlessPodmanValidationBackend,
    VALIDATION_PROTOCOL_VERSION,
    _encode_validation_data,
)


def completed(command, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def test_rootless_podman_requires_rootless_and_local_image(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        if command[1:3] == ["info", "--format"]:
            return completed(command, stdout=json.dumps({"host": {"security": {"rootless": True}}}))
        if command[1:3] == ["image", "exists"]:
            return completed(command)
        if command[1:3] == ["image", "inspect"]:
            return completed(command, stdout="sha256:trusted-image\n")
        raise AssertionError(command)

    monkeypatch.setattr("caretaker.validation.subprocess.run", fake_run)
    backend = RootlessPodmanValidationBackend("caretaker-validator:local", workspace=tmp_path)

    available, reason = backend.available()

    assert available is True
    assert reason is None
    capabilities = backend.capabilities()
    assert capabilities.isolation_level is ValidationIsolationLevel.CONTAINER
    assert capabilities.rootless is True
    assert capabilities.details["image_digest"] == "sha256:trusted-image"


def test_rootless_podman_advertises_resource_control_only_after_probe(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")

    def fake_run(command, **kwargs):
        if command[1:3] == ["info", "--format"]:
            return completed(command, stdout=json.dumps({"host": {"security": {"rootless": True}}}))
        if command[1:3] == ["image", "exists"]:
            return completed(command)
        if command[1:3] == ["image", "inspect"]:
            return completed(command, stdout="sha256:trusted-image\n")
        if command[2:3] == ["run"]:
            return completed(
                command,
                stdout=json.dumps({
                    "memory.max": str(512 * 1024 * 1024),
                    "cpu.max": "100000 100000",
                    "pids.max": "64",
                }) + "\n",
            )
        raise AssertionError(command)

    monkeypatch.setattr("caretaker.validation.subprocess.run", fake_run)
    backend = RootlessPodmanValidationBackend("caretaker-validator:local", workspace=tmp_path)

    assert backend.available() == (True, None)
    assert backend.capabilities().resource_control is True


def test_rootless_podman_does_not_advertise_unenforced_resource_control(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")

    def fake_run(command, **kwargs):
        if command[1:3] == ["info", "--format"]:
            return completed(command, stdout=json.dumps({"host": {"security": {"rootless": True}}}))
        if command[1:3] == ["image", "exists"]:
            return completed(command)
        if command[1:3] == ["image", "inspect"]:
            return completed(command, stdout="sha256:trusted-image\n")
        if command[2:3] == ["run"]:
            return completed(command, stdout=json.dumps({
                "memory.max": "max", "cpu.max": "max", "pids.max": "max",
            }) + "\n")
        raise AssertionError(command)

    monkeypatch.setattr("caretaker.validation.subprocess.run", fake_run)
    backend = RootlessPodmanValidationBackend("caretaker-validator:local", workspace=tmp_path)

    assert backend.available() == (True, None)
    assert backend.capabilities().resource_control is False


def test_rootless_podman_rejects_rootful_runtime(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")
    monkeypatch.setattr(
        "caretaker.validation.subprocess.run",
        lambda command, **kwargs: completed(command, stdout=json.dumps({"rootless": False})),
    )
    backend = RootlessPodmanValidationBackend("caretaker-validator:local", workspace=tmp_path)

    available, reason = backend.available()

    assert available is False
    assert "rootless" in reason.lower()


def test_rootless_docker_requires_rootless_daemon_and_local_image(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")

    def fake_run(command, **kwargs):
        if command[1:3] == ["info", "--format"]:
            return completed(command, stdout=json.dumps({"SecurityOptions": ["name=rootless"]}))
        if command[1:3] == ["image", "inspect"] and "--format" not in command:
            return completed(command)
        if command[1:3] == ["image", "inspect"]:
            return completed(command, stdout=json.dumps(["localhost/caretaker@sha256:trusted"]))
        raise AssertionError(command)

    monkeypatch.setattr("caretaker.validation.subprocess.run", fake_run)
    backend = RootlessDockerValidationBackend("caretaker-validator:local", workspace=tmp_path)

    available, reason = backend.available()

    assert available is True
    assert reason is None
    assert backend.capabilities().name == "docker-rootless"
    assert backend.capabilities().details["image_digest"].endswith("sha256:trusted")


def test_rootless_docker_command_preserves_container_boundary(tmp_path: Path) -> None:
    workspace = tmp_path / "application"
    workspace.mkdir()
    request = tmp_path / "request"
    request.mkdir()
    backend = RootlessDockerValidationBackend(
        "caretaker-validator:local",
        workspace=workspace,
        memory="768m",
        cpus=2,
        pids_limit=48,
    )

    command = backend._build_command(request)
    text = " ".join(command)

    assert command[:3] == ["docker", "run", "--rm"]
    assert "--pull=never" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--pids-limit=48" in command
    assert "--memory=768m" in command
    assert "--cpus=2" in command
    assert "--cgroup-manager=cgroupfs" not in command
    assert "--userns=keep-id" not in command
    assert "docker.sock" not in text
    assert f"src={workspace},dst=/workspace,readonly" in text
    assert f"src={request},dst=/work,rw" in text


def test_rootless_podman_command_has_strict_container_boundary(tmp_path: Path) -> None:
    workspace = tmp_path / "application"
    workspace.mkdir()
    backend = RootlessPodmanValidationBackend(
        "caretaker-validator:local",
        workspace=workspace,
        memory="768m",
        cpus=2,
        pids_limit=48,
    )
    request = tmp_path / "request"
    request.mkdir()

    command = backend._build_command(request)
    text = " ".join(command)

    assert command[:3] == ["podman", "--cgroup-manager=cgroupfs", "run"]
    assert "--pull=never" in command
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--userns=keep-id" in command
    assert "--pids-limit=48" in command
    assert "--memory=768m" in command
    assert "--cpus=2" in command
    assert "docker.sock" not in text
    assert f"src={workspace},dst=/workspace,ro=true" in text
    assert f"src={request},dst=/work,rw=true" in text



def test_rootless_podman_worker_preserves_rootless_host_environment(monkeypatch, tmp_path: Path) -> None:
    backend = RootlessPodmanValidationBackend("caretaker-validator:local", workspace=tmp_path)
    captured: dict[str, object] = {}

    monkeypatch.setenv("HOME", "/home/demo")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")

    def fake_run_worker(command, *, output_path, timeout_seconds, cwd, env):
        captured["env"] = dict(env)
        return {"eligible": True, "checks": []}

    monkeypatch.setattr("caretaker.validation._run_worker_command", fake_run_worker)
    result = backend._run_worker.__wrapped__(backend, {}, timeout_seconds=1.0)

    assert result["eligible"] is True
    assert captured["env"]["HOME"] == "/home/demo"
    assert captured["env"]["XDG_RUNTIME_DIR"] == "/run/user/1000"
    assert captured["env"]["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/user/1000/bus"


def test_structured_bind_mount_escapes_comma_in_host_path(tmp_path: Path) -> None:
    from caretaker.replay import RootlessPodmanReplayBackend

    workdir = tmp_path / "request,with,commas"
    validation = RootlessPodmanValidationBackend("caretaker-validator:local")
    validation_command = validation._build_command(workdir)
    assert any("src=" + str(workdir).replace(",", "\\,") in item for item in validation_command)

    replay = RootlessPodmanReplayBackend("caretaker-replay:local")
    replay_command = replay._build_replay_command(workdir)
    assert any("src=" + str(workdir).replace(",", "\\,") in item for item in replay_command)


def test_container_validation_rejects_symlinked_mount_sources(tmp_path: Path) -> None:
    real_workspace = tmp_path / "real-workspace"
    real_workspace.mkdir()
    symlink_workspace = tmp_path / "workspace-link"
    symlink_workspace.symlink_to(real_workspace, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        RootlessPodmanValidationBackend("caretaker-validator:local", workspace=symlink_workspace)
    with pytest.raises(ValueError, match="symlink"):
        RootlessPodmanValidationBackend(
            "caretaker-validator:local",
            workspace=real_workspace,
            additional_read_only_paths=(symlink_workspace,),
        )


def test_container_validation_rejects_coercive_resource_limits(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(ValueError, match="cpus"):
        RootlessPodmanValidationBackend("caretaker-validator:local", workspace=workspace, cpus="1")
    with pytest.raises(ValueError, match="pids_limit"):
        RootlessPodmanValidationBackend("caretaker-validator:local", workspace=workspace, pids_limit=2.5)
    with pytest.raises(ValueError, match="memory"):
        RootlessPodmanValidationBackend("caretaker-validator:local", workspace=workspace, memory=512)

def test_multipass_rejects_host_directory_mounts(monkeypatch) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")
    backend = MultipassValidationBackend(require_network_isolation=False)
    monkeypatch.setattr(
        backend,
        "_host_command",
        lambda command, timeout=None: completed(
            command,
            stdout=json.dumps(
                {
                    "info": {
                        "caretaker-validator": {
                            "state": "RUNNING",
                            "mounts": {"/host/source": "/guest/source"},
                            "image_hash": "vm-image",
                        }
                    }
                }
            ),
        ),
    )

    available, reason = backend.available()

    assert available is False
    assert "host-directory mounts" in reason


def test_multipass_availability_converts_permission_errors_to_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")
    backend = MultipassValidationBackend(require_network_isolation=False)

    def denied(*args, **kwargs):
        raise PermissionError("multipass socket denied")

    monkeypatch.setattr(backend, "_host_command", denied)
    available, reason = backend.available()

    assert available is False
    assert "information query failed" in reason.lower()


def test_multipass_availability_verifies_guest_and_network_marker(monkeypatch) -> None:
    monkeypatch.setattr("caretaker.validation.shutil.which", lambda executable: f"/usr/bin/{executable}")
    backend = MultipassValidationBackend(clean_snapshot="clean")
    calls: list[list[str]] = []

    def fake_host(command, timeout=None):
        calls.append(list(command))
        if command[:4] == ["multipass", "info", "--format", "json"]:
            return completed(
                command,
                stdout=json.dumps(
                    {
                        "info": {
                            "caretaker-validator": {
                                "state": "RUNNING",
                                "mounts": {},
                                "image_hash": "sha256:vm-image",
                            }
                        }
                    }
                ),
            )
        if command[:3] == ["multipass", "info", "caretaker-validator.clean"]:
            return completed(command, stdout="snapshot")
        if "stat" in command:
            return completed(command, stdout="0 644\n")
        if "nft" in command:
            return completed(
                command,
                stdout=(
                    "table inet caretaker {\n"
                    " chain output {\n"
                    "  type filter hook output priority 0; policy accept;\n"
                    "  meta skuid 22001 ip daddr 127.0.0.0/8 accept\n"
                    "  meta skuid 22001 ip6 daddr ::1 accept\n"
                    "  meta skuid 22001 reject\n"
                    " }\n"
                    "}\n"
                ),
            )
        if "ip" in command:
            return completed(command, stdout="")
        return completed(command, stdout="22001\n")

    monkeypatch.setattr(backend, "_host_command", fake_host)

    available, reason = backend.available()

    assert available is True
    assert reason is None
    assert backend.capabilities().isolation_level is ValidationIsolationLevel.VM
    assert backend.capabilities().separate_kernel is True
    assert backend.capabilities().details["image_hash"] == "sha256:vm-image"
    assert backend.capabilities().details["network_firewall_ruleset_hash"]
    assert backend.capabilities().details["network_firewall_subject_uid"] == 22001
    assert not any("mount" in command for command in calls)


def test_multipass_firewall_attestation_rejects_unapproved_accept_rule() -> None:
    output = (
        "table inet caretaker {\n"
        " chain output {\n"
        "  type filter hook output priority 0; policy accept;\n"
        "  meta skuid 22001 ip daddr 127.0.0.0/8 accept\n"
        "  meta skuid 22001 ip6 daddr ::1 accept\n"
        "  meta skuid 22001 ip daddr 8.8.8.8 accept\n"
        "  meta skuid 22001 reject\n"
        " }\n"
        "}\n"
    )

    attested, ruleset_hash, reason = MultipassValidationBackend._attest_network_ruleset(
        output,
        "22001",
    )

    assert attested is False
    assert ruleset_hash is None
    assert "unapproved accept" in reason


def test_multipass_firewall_attestation_rejects_missing_subject_reject() -> None:
    output = (
        "table inet caretaker {\n"
        " chain output {\n"
        "  type filter hook output priority 0; policy accept;\n"
        "  meta skuid 22001 ip daddr 127.0.0.0/8 accept\n"
        "  meta skuid 22001 ip6 daddr ::1 accept\n"
        " }\n"
        "}\n"
    )

    attested, ruleset_hash, reason = MultipassValidationBackend._attest_network_ruleset(
        output,
        "22001",
    )

    assert attested is False
    assert ruleset_hash is None
    assert "required egress policy" in reason


def test_multipass_firewall_attestation_requires_rules_in_output_chain() -> None:
    output = (
        "table inet caretaker {\n"
        " chain unrelated {\n"
        "  meta skuid 22001 ip daddr 127.0.0.0/8 accept\n"
        "  meta skuid 22001 ip6 daddr ::1 accept\n"
        "  meta skuid 22001 reject\n"
        " }\n"
        " chain output {\n"
        "  type filter hook output priority 0; policy accept;\n"
        "  meta skuid 22001 reject\n"
        " }\n"
        "}\n"
    )

    attested, ruleset_hash, reason = MultipassValidationBackend._attest_network_ruleset(
        output,
        "22001",
    )

    assert attested is False
    assert ruleset_hash is None
    assert "required egress policy" in reason


def test_multipass_restore_uses_clean_snapshot(monkeypatch) -> None:
    backend = MultipassValidationBackend(clean_snapshot="clean", require_network_isolation=False)
    calls: list[list[str]] = []

    def fake_host(command, timeout=None):
        calls.append(list(command))
        return completed(command)

    monkeypatch.setattr(backend, "_host_command", fake_host)

    restored, reason = backend._restore_clean_instance("caretaker-validator")

    assert restored is True
    assert reason is None
    assert calls == [
        ["multipass", "stop", "caretaker-validator"],
        ["multipass", "restore", "--destructive", "caretaker-validator.clean"],
        ["multipass", "start", "caretaker-validator"],
        ["multipass", "wait-ready", "caretaker-validator"],
    ]


def test_multipass_disposable_clone_is_destroyed(monkeypatch) -> None:
    backend = MultipassValidationBackend(
        disposable_clone=True,
        clean_snapshot=None,
        require_network_isolation=False,
    )
    destroyed: list[str] = []
    monkeypatch.setattr(backend, "_create_disposable_clone", lambda: ("caretaker-val-test", None))
    monkeypatch.setattr(backend, "_verify_guest_prerequisites", lambda instance: (True, None))
    monkeypatch.setattr(
        backend,
        "_run_in_instance",
        lambda instance, payload, timeout_seconds: {"eligible": True, "checks": []},
    )
    monkeypatch.setattr(backend, "_destroy_disposable_clone", destroyed.append)

    result = backend._run_worker.__wrapped__(backend, {}, timeout_seconds=1.0)

    assert result["eligible"] is True
    assert destroyed == ["caretaker-val-test"]


def test_multipass_worker_transfers_artifacts_without_host_mount(monkeypatch) -> None:
    backend = MultipassValidationBackend(clean_snapshot=None, require_network_isolation=False)
    calls: list[list[str]] = []

    def fake_host(command, timeout=None):
        calls.append(list(command))
        if command[:2] == ["multipass", "transfer"] and command[-2].startswith("caretaker-validator:"):
            Path(command[-1]).write_text(
                json.dumps(
                    {
                        "protocol_version": VALIDATION_PROTOCOL_VERSION,
                        "result": _encode_validation_data(
                            {
                                "eligible": True,
                                "checks": [],
                                "measurements": {},
                                "risk_findings": [],
                                "hard_disqualifications": [],
                                "review_required_findings": [],
                            }
                        ),
                    }
                ),
                encoding="utf-8",
            )
        return completed(command, stdout="")

    monkeypatch.setattr(backend, "_host_command", fake_host)

    result = backend._run_in_instance(
        "caretaker-validator",
        {"mode": "auxiliary_validator"},
        timeout_seconds=2.0,
    )

    assert result["eligible"] is True
    assert any(command[:2] == ["multipass", "transfer"] for command in calls)
    assert not any("mount" in command for command in calls)
    worker = next(command for command in calls if "caretaker.validation_worker" in command)
    assert "sudo" in worker
    assert "-u" in worker
    assert "caretaker-subject" in worker
