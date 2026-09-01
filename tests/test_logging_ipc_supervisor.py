from __future__ import annotations

import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from caretaker.logging import (
    LogChannel,
    LogEnvelope,
    OperatorLoggingPolicy,
    SegmentWriter,
    SocketLogClient,
    SocketLogServer,
    WorkRegistry,
    CaretakerComponent,
    CaretakerApplicationSupervisor,
    ControlSocketServer,
    EndpointAlreadyOwnedError,
    cleanup_stale_endpoint,
)


def test_application_shutdown_terminates_only_the_dedicated_process_group():
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    application = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess, sys, time; "
            "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "print(child.pid, flush=True); time.sleep(30)",
        ],
        start_new_session=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        descendant_pid = int(application.stdout.readline().strip())
        supervisor = CaretakerApplicationSupervisor(
            object(),
            application_pid=application.pid,
            application_process_group_id=os.getpgid(application.pid),
            application_process=application,
        )
        outcome = supervisor.stop_application(timeout_seconds=0.5)
        application.wait(timeout=2)
        assert outcome["boundary"] == "process_group"
        assert outcome["process_group_id"] == application.pid
        assert application.poll() is not None
        assert unrelated.poll() is None
        ready, _, _ = select.select([application.stdout], [], [], 2)
        assert ready == [application.stdout]
        assert application.stdout.read() == ""
        for _ in range(20):
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            pytest.fail("application descendant survived process-group shutdown")
    finally:
        if application.poll() is None:
            os.killpg(os.getpgid(application.pid), signal.SIGKILL)
            application.wait(timeout=2)
        if unrelated.poll() is None:
            unrelated.terminate()
            unrelated.wait(timeout=2)


def test_application_shutdown_escalates_only_within_the_dedicated_process_group():
    application = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal, subprocess, sys, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)']); "
            "print(child.pid, flush=True); time.sleep(30)",
        ],
        start_new_session=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        descendant_pid = int(application.stdout.readline().strip())
        supervisor = CaretakerApplicationSupervisor(
            object(),
            application_pid=application.pid,
            application_process_group_id=os.getpgid(application.pid),
            application_process=application,
        )
        outcome = supervisor.stop_application(timeout_seconds=0.1)
        application.wait(timeout=2)
        assert outcome["forced"] is True
        assert outcome["boundary_alive"] is False
        for _ in range(20):
            try:
                os.kill(descendant_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            pytest.fail("ignored application descendant survived forced shutdown")
    finally:
        if application.poll() is None:
            os.killpg(os.getpgid(application.pid), signal.SIGKILL)
            application.wait(timeout=2)


def test_unix_socket_logging_supports_multiple_emitters(tmp_path):
    policy = OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="demo")
    writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
    socket_path = tmp_path / "events.sock"
    server = SocketLogServer(socket_path, writer, allowed_uids={os.getuid()})
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    clients = [SocketLogClient(socket_path) for _ in range(2)]
    for sequence, client in enumerate(clients, start=1):
        client.write(LogEnvelope(
            schema_version=1, writer_version="0.5.0a1", record_id=uuid4(),
            occurred_at=datetime.now(timezone.utc), monotonic_ns=sequence,
            process_start_id=uuid4(), sequence_number=sequence,
            channel=LogChannel.APPLICATION, severity=20, logger_name="demo",
            message_template=None, formatted_message="hello", fields={},
            process_id=os.getpid(), thread_id=1, task_id=None, run_id=uuid4(),
            call_id=None, target_id=None, function_version=None, incident_id=None,
        ))
        client.close()
    server.stop()
    thread.join(timeout=2)
    manifest = writer.close()
    assert manifest.record_count == 2


@pytest.mark.parametrize("endpoint_kind", ["control", "log"])
def test_duplicate_ipc_endpoint_startup_fails_without_displacing_owner(
    tmp_path, endpoint_kind
):
    socket_path = tmp_path / f"{endpoint_kind}.sock"
    writer = None
    if endpoint_kind == "control":
        server = ControlSocketServer(
            socket_path,
            lambda request, credentials: {"ok": True},
            allowed_uids={os.getuid()},
        )
        duplicate = ControlSocketServer(
            socket_path,
            lambda request, credentials: {"ok": True},
            allowed_uids={os.getuid()},
        )
    else:
        policy = OperatorLoggingPolicy.application_defaults(
            directory=str(tmp_path), application_id="duplicate"
        )
        writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
        server = SocketLogServer(socket_path, writer, allowed_uids={os.getuid()})
        duplicate_writer = SegmentWriter(
            policy, run_id=uuid4(), process_start_id=uuid4()
        )
        duplicate = SocketLogServer(
            socket_path, duplicate_writer, allowed_uids={os.getuid()}
        )
    server.start()
    try:
        with pytest.raises(EndpointAlreadyOwnedError) as raised:
            duplicate.start()
        assert raised.value.owner is not None
        assert raised.value.owner["pid"] == os.getpid()
        assert raised.value.owner["process_start_id"]
        assert raised.value.owner["instance_token"]
        assert socket_path.exists()
    finally:
        server.stop()
        if writer is not None:
            writer.close()


def test_stale_socket_is_removed_only_after_owner_probe_fails(tmp_path):
    socket_path = tmp_path / "stale.sock"
    stale_owner = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale_owner.bind(str(socket_path))
    stale_owner.close()

    server = ControlSocketServer(
        socket_path,
        lambda request, credentials: {"ok": True},
        allowed_uids={os.getuid()},
    )
    try:
        server.start()
        assert socket_path.exists()
    finally:
        server.stop()


def test_explicit_stale_endpoint_cleanup_does_not_trust_reused_pid_metadata(tmp_path):
    socket_path = tmp_path / "stale.sock"
    stale_owner = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale_owner.bind(str(socket_path))
    stale_owner.close()
    (tmp_path / "stale.sock.owner").write_text(
        '{"pid": %d, "process_start_id": "different", "instance_token": "different"}'
        % os.getpid(),
        encoding="utf-8",
    )

    assert cleanup_stale_endpoint(socket_path) is True
    assert not socket_path.exists()


def test_explicit_stale_endpoint_cleanup_rejects_live_owner(tmp_path):
    socket_path = tmp_path / "live.sock"
    server = ControlSocketServer(
        socket_path,
        lambda request, credentials: {"ok": True},
        allowed_uids={os.getuid()},
    )
    server.start()
    try:
        with pytest.raises(EndpointAlreadyOwnedError):
            cleanup_stale_endpoint(socket_path)
        assert socket_path.exists()
    finally:
        server.stop()


def test_work_registry_exposes_active_and_recent_changes():
    registry = WorkRegistry(recent_seconds=60)
    work = registry.start(
        component=CaretakerComponent.REPAIR,
        work_kind="candidate-activation",
        scope="demo.module.function",
        root_signal_id=uuid4(),
        expected_code_fingerprints={"demo.module.function": "abc"},
    )
    assert registry.overlapping("demo.module")
    registry.finish(work.work_id)
    assert registry.overlapping("demo.module.function")


def test_remote_attachment_is_stored_separately_and_referenced(tmp_path):
    from caretaker.logging import AttachmentStore, AttachmentPolicy
    policy = OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="demo")
    writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
    attachments = AttachmentStore(tmp_path, AttachmentPolicy(maximum_rate_per_minute=None))
    socket_path = tmp_path / "attachments.sock"
    server = SocketLogServer(socket_path, writer, allowed_uids={os.getuid()}, attachment_store=attachments)
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = SocketLogClient(socket_path)
    event_id = uuid4()
    reference = client.store_attachment(
        event_id=event_id, event_sequence=1, content_type="text/plain", payload=b"x" * 10000,
    )
    assert reference["stored"] is True
    assert reference["event_id"] == str(event_id)
    client.close()
    server.stop()
    thread.join(timeout=2)
    attachments.close()
    writer.close()


def test_remote_runtime_emits_through_socket(tmp_path):
    from caretaker.logging import RemoteLoggingRuntime, read_segment

    policy = OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="demo")
    writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
    socket_path = tmp_path / "remote.sock"
    server = SocketLogServer(socket_path, writer, allowed_uids={os.getuid()})
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    runtime = RemoteLoggingRuntime(policy, socket_path)
    runtime.event(
        logger_name="demo.remote", severity=20, channel=LogChannel.APPLICATION,
        message="remote hello", fields={"token": "secret-value"},
    )
    runtime.close()
    server.stop()
    thread.join(timeout=2)
    manifest = writer.close()
    records = read_segment(manifest.path)
    assert records[-1].formatted_message == "remote hello"
    assert records[-1].fields["token"] == "<redacted>"


def test_long_unix_socket_path_uses_short_private_runtime_path(tmp_path):
    from caretaker.logging import unix_socket_path

    requested = tmp_path
    while len(os.fsencode(str(requested / "events.sock"))) <= 120:
        requested = requested / "deep-caretaker-project-directory"
    requested_socket = requested / "events.sock"

    resolved = unix_socket_path(requested_socket)

    assert resolved.name == "events.sock"
    assert resolved != requested_socket
    assert len(os.fsencode(str(resolved))) <= 100
    assert resolved.parent.stat().st_mode & 0o077 == 0


def test_long_unix_socket_path_logging_round_trip(tmp_path):
    policy = OperatorLoggingPolicy.application_defaults(directory=str(tmp_path), application_id="demo")
    writer = SegmentWriter(policy, run_id=uuid4(), process_start_id=uuid4())
    requested = tmp_path
    while len(os.fsencode(str(requested / "events.sock"))) <= 120:
        requested = requested / "deep-caretaker-project-directory"
    socket_path = requested / "events.sock"

    server = SocketLogServer(socket_path, writer, allowed_uids={os.getuid()})
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = SocketLogClient(socket_path)
    client.write(LogEnvelope(
        schema_version=1, writer_version="0.5.0a1", record_id=uuid4(),
        occurred_at=datetime.now(timezone.utc), monotonic_ns=1,
        process_start_id=uuid4(), sequence_number=1,
        channel=LogChannel.APPLICATION, severity=20, logger_name="demo",
        message_template=None, formatted_message="long path", fields={},
        process_id=os.getpid(), thread_id=1, task_id=None, run_id=uuid4(),
        call_id=None, target_id=None, function_version=None, incident_id=None,
    ))
    client.close()
    server.stop()
    thread.join(timeout=2)
    manifest = writer.close()
    assert manifest.record_count == 1


def test_long_unix_control_socket_path_round_trip(tmp_path):
    from caretaker.logging import ControlSocketServer, control_request

    requested = tmp_path
    while len(os.fsencode(str(requested / "control.sock"))) <= 120:
        requested = requested / "deep-caretaker-project-directory"
    socket_path = requested / "control.sock"

    server = ControlSocketServer(
        socket_path,
        lambda request, credentials: {
            "ok": True,
            "command": request.get("command"),
            "uid": credentials[1],
        },
        allowed_uids={os.getuid()},
    )
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = control_request(socket_path, {"command": "status"})
        assert response["ok"] is True
        assert response["command"] == "status"
        assert response["uid"] == os.getuid()
    finally:
        server.stop()
        thread.join(timeout=2)


def test_control_status_is_not_blocked_by_an_in_flight_request(tmp_path):
    from caretaker.logging import ControlSocketServer, control_request

    slow_started = threading.Event()
    release_slow = threading.Event()

    def handler(request, credentials):
        if request.get("command") == "slow":
            slow_started.set()
            release_slow.wait(timeout=2)
        return {"ok": True, "command": request.get("command")}

    socket_path = tmp_path / "control.sock"
    server = ControlSocketServer(socket_path, handler, allowed_uids={os.getuid()})
    server.start()
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    slow_thread = threading.Thread(
        target=control_request,
        args=(socket_path, {"command": "slow"}),
        daemon=True,
    )
    slow_thread.start()
    try:
        assert slow_started.wait(timeout=1)
        response = control_request(socket_path, {"command": "status"}, timeout=0.5)
        assert response == {"ok": True, "command": "status"}
    finally:
        release_slow.set()
        slow_thread.join(timeout=2)
        server.stop()
        server_thread.join(timeout=2)


def test_control_socket_round_trips_response_larger_than_seqpacket_limit(tmp_path):
    from caretaker.logging import ControlSocketServer, control_request

    payload = "x" * (512 * 1024)
    socket_path = tmp_path / "control.sock"
    server = ControlSocketServer(
        socket_path,
        lambda request, credentials: {"ok": True, "payload": payload},
        allowed_uids={os.getuid()},
    )
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = control_request(socket_path, {"command": "large"})
        assert response["payload"] == payload
    finally:
        server.stop()
        thread.join(timeout=2)
