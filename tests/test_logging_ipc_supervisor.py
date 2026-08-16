from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from uuid import uuid4

from caretaker.logging import (
    LogChannel,
    LogEnvelope,
    OperatorLoggingPolicy,
    SegmentWriter,
    SocketLogClient,
    SocketLogServer,
    WorkRegistry,
    CaretakerComponent,
)


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
