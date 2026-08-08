from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from uuid import UUID

from .logging import (
    CaretakerApplicationSupervisor,
    LogChannel,
    LoggingMode,
    InterrogationRequest,
    LogInterrogator,
    OllamaRootCauseProvider,
    WorkerFailureAction,
    WorkerKind,
    WorkerState,
)
from .logging.handler import LoggingRuntime
from .logging.ipc import ControlSocketServer, SocketLogServer, control_request
from .logging.policy import OperatorLoggingPolicy, load_operator_policy
from .logging.segments import read_segment
from .system import SystemCollectionPolicy, SystemDataCollector, SystemOutputPolicy, load_system_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m caretaker.run")
    parser.add_argument("--policy")
    parser.add_argument("--data-directory")
    parser.add_argument("--system-data", action="store_true")
    parser.add_argument("module")
    parser.add_argument("module_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.policy:
        policy, _ = load_operator_policy(args.policy)
    else:
        directory = args.data_directory or f"./caretaker-data/{args.module}"
        policy = OperatorLoggingPolicy.application_defaults(directory=directory, application_id=args.module)
    runtime = LoggingRuntime(policy, source_path=args.policy, supervised=True)
    run_dir = Path(policy.directory) / "run"
    event_socket = run_dir / "events.sock"
    control_socket = run_dir / "control.sock"
    runtime_control_socket = run_dir / "runtime.sock"
    server = SocketLogServer(event_socket, runtime.sink, allowed_uids={os.getuid()}, attachment_store=runtime.attachments)
    server.start()
    server_thread = threading.Thread(target=server.serve_forever, name="caretaker-event-server", daemon=True)
    server_thread.start()

    leases: dict[str, object] = {}
    child_holder: dict[str, subprocess.Popen] = {}
    supervisor_holder: dict[str, CaretakerApplicationSupervisor] = {}

    def recent_log_records(limit: int = 1000):
        event_directory = Path(policy.directory) / "application" / "events"
        paths = sorted(event_directory.glob("*.ctlog")) + sorted(event_directory.glob("*.ctlog.gz"))
        records = []
        for path in paths[-16:]:
            try:
                records.extend(read_segment(path))
            except Exception:
                continue
        return records[-max(1, limit):]

    def control_handler(request, credentials):
        command = request.get("command")
        if command in {"status", "health"}:
            child = child_holder.get("child")
            supervisor = supervisor_holder.get("supervisor")
            application_runtime = None
            if runtime_control_socket.exists():
                try:
                    application_runtime = control_request(runtime_control_socket, {"command": "status"})
                except OSError:
                    application_runtime = None
            return {"ok": True, "application_pid": child.pid if child else None,
                    "application_running": child.poll() is None if child else False,
                    "policy_generation": runtime.effective.generation,
                    "active_leases": list(leases),
                    "workers": [asdict(item) for item in supervisor.workers.all()] if supervisor else [],
                    "runtime": application_runtime}
        if isinstance(command, str) and command.startswith("runtime-"):
            forwarded = dict(request)
            forwarded["command"] = command.removeprefix("runtime-")
            try:
                return control_request(runtime_control_socket, forwarded)
            except OSError as exc:
                return {"ok": False, "error": f"application runtime control unavailable: {exc}"}
        if command == "logs":
            limit = max(1, min(int(request.get("limit", 100)), 500))
            records = recent_log_records(limit)
            return {
                "ok": True,
                "records": [
                    {
                        "occurred_at": item.occurred_at.isoformat(),
                        "severity": item.severity,
                        "channel": item.channel.name,
                        "logger": item.logger_name,
                        "message": item.formatted_message or item.message_template,
                        "target_id": str(item.target_id) if item.target_id else None,
                        "fields": dict(item.fields),
                    }
                    for item in records[-limit:]
                ],
            }
        if command == "investigate":
            target = str(request.get("target") or "").strip()
            minutes = max(1, min(int(request.get("minutes", 15)), 24 * 60))
            objective = str(request.get("objective") or "Investigate the current Caretaker incident")
            now = datetime.now(timezone.utc)
            interrogation = InterrogationRequest(
                period_start=now - timedelta(minutes=minutes),
                period_end=now,
                target_ids=(target,) if target else (),
                objective=objective,
            )
            behavior = ()
            if target and runtime_control_socket.exists():
                try:
                    response = control_request(
                        runtime_control_socket,
                        {"command": "guard-deviations", "target": target, "limit": 50},
                    )
                    behavior = tuple(
                        json.dumps(item, sort_keys=True, default=str)
                        for item in response.get("deviations", ())
                    )
                except OSError:
                    behavior = ()
            interrogator = LogInterrogator()
            bundle = interrogator.build_bundle(
                interrogation,
                tuple(recent_log_records(2000)),
                behavior_deviations=behavior,
            )
            model = str(request.get("model") or "").strip()
            if model:
                provider = OllamaRootCauseProvider(
                    model=model,
                    endpoint=str(request.get("endpoint") or "http://127.0.0.1:11434/api/generate"),
                )
                assessment = provider.assess(bundle)
            else:
                assessment = interrogator.deterministic_assessment(bundle)
            return {
                "ok": True,
                "provider": "ollama" if model else "deterministic",
                "evidence_hash": bundle.evidence_hash,
                "omitted_record_count": bundle.omitted_record_count,
                "assessment": asdict(assessment),
            }
        if command == "policy-effective":
            return {"ok": True, "requested_modes": [item.name for item in runtime.effective.requested_modes],
                    "effective_modes": [item.name for item in runtime.effective.effective_modes],
                    "overrides": [item.field_path for item in runtime.effective.overrides]}
        if command == "mode-acquire":
            mode = LoggingMode[str(request["mode"]).upper()]
            lease = runtime.acquire_mode(mode, requested_by=f"uid:{credentials[1]}", reason=str(request.get("reason", "operator request")))
            leases[str(lease.lease_id)] = lease
            return {"ok": True, "lease_id": str(lease.lease_id), "overrides": [item.field_path for item in lease.required_overrides]}
        if command == "mode-release":
            lease_id = UUID(str(request["lease_id"]))
            runtime.release_mode(lease_id)
            leases.pop(str(lease_id), None)
            return {"ok": True, "released": str(lease_id)}
        return {"ok": False, "error": "unsupported declarative command"}

    control = ControlSocketServer(control_socket, control_handler, allowed_uids={os.getuid()})
    control.start()
    control_thread = threading.Thread(target=control.serve_forever, name="caretaker-control-server", daemon=True)
    control_thread.start()

    env = os.environ.copy()
    env.update({
        "CARETAKER_SUPERVISED": "1",
        "CARETAKER_EVENT_SOCKET": str(event_socket),
        "CARETAKER_RUN_ID": str(runtime.run_id),
        "CARETAKER_APPLICATION_ID": policy.application_id,
        "CARETAKER_DATA_DIR": policy.directory,
        "CARETAKER_RUNTIME_CONTROL_SOCKET": str(runtime_control_socket),
    })
    if args.policy:
        env["CARETAKER_LOGGING_POLICY"] = str(Path(args.policy).resolve())
    child = subprocess.Popen([sys.executable, "-m", "caretaker.bootstrap", args.module, *args.module_args], env=env)
    child_holder["child"] = child
    supervisor = CaretakerApplicationSupervisor(runtime, application_pid=child.pid)
    supervisor_holder["supervisor"] = supervisor
    supervisor.start()
    writer_health = supervisor.workers.register(WorkerKind.WRITER, os.getpid())
    event_health = supervisor.workers.register(WorkerKind.EVENT_SERVER, os.getpid())
    control_health = supervisor.workers.register(WorkerKind.CONTROL_SERVER, os.getpid())

    collector = None
    collector_thread = None
    system_directory = str(Path(policy.directory) / "system")
    if args.policy:
        system_policy = load_system_policy(args.policy, default_directory=system_directory)
    else:
        system_policy = SystemCollectionPolicy(
            enabled=False,
            output=SystemOutputPolicy(directory=system_directory),
        )
    if args.system_data and not system_policy.enabled:
        system_policy = replace(system_policy, enabled=True)
    system_health = None
    if system_policy.enabled:
        collector = SystemDataCollector(system_policy, application_pid=child.pid)
        collector_thread = threading.Thread(target=collector.run, name="caretaker-system-collector", daemon=True)
        collector_thread.start()
        system_health = supervisor.workers.register(WorkerKind.SYSTEM_COLLECTOR, os.getpid())

    health_stop = threading.Event()
    system_restart_times: list[float] = []

    def health_loop() -> None:
        nonlocal collector, collector_thread
        while not health_stop.wait(1.0):
            supervisor.workers.heartbeat(supervisor.supervisor_health.worker_id, state=WorkerState.HEALTHY)
            if runtime.sink._thread.is_alive():
                state = WorkerState.DEGRADED if runtime.sink.last_error else WorkerState.HEALTHY
                supervisor.workers.heartbeat(
                    writer_health.worker_id,
                    state=state,
                    queue_depth=runtime.sink._queue.qsize(),
                )
            else:
                supervisor.workers.mark_failed(
                    writer_health.worker_id,
                    error_fingerprint=type(runtime.sink.last_error).__name__ if runtime.sink.last_error else "writer-thread-stopped",
                )
            if server_thread.is_alive():
                supervisor.workers.heartbeat(event_health.worker_id, state=WorkerState.HEALTHY)
            else:
                supervisor.workers.mark_failed(event_health.worker_id, error_fingerprint="event-server-stopped")
            if control_thread.is_alive():
                supervisor.workers.heartbeat(control_health.worker_id, state=WorkerState.HEALTHY)
            else:
                supervisor.workers.mark_failed(control_health.worker_id, error_fingerprint="control-server-stopped")
            if system_health is not None and collector_thread is not None:
                if collector_thread.is_alive():
                    supervisor.workers.heartbeat(system_health.worker_id, state=WorkerState.HEALTHY)
                else:
                    supervisor.workers.mark_failed(system_health.worker_id, error_fingerprint="system-collector-stopped")
                    restart_policy = runtime.active_policy.worker_restart
                    now = time.monotonic()
                    system_restart_times[:] = [
                        value for value in system_restart_times
                        if value >= now - restart_policy.restart_window_seconds
                    ]
                    can_restart = (
                        restart_policy.enabled
                        and child.poll() is None
                        and len(system_restart_times) < restart_policy.maximum_restarts
                    )
                    if can_restart:
                        delay = min(
                            restart_policy.maximum_backoff_seconds,
                            restart_policy.initial_backoff_seconds * (2 ** len(system_restart_times)),
                        )
                        if health_stop.wait(delay):
                            return
                        collector = SystemDataCollector(system_policy, application_pid=child.pid)
                        collector_thread = threading.Thread(
                            target=collector.run,
                            name="caretaker-system-collector",
                            daemon=True,
                        )
                        collector_thread.start()
                        system_restart_times.append(time.monotonic())
                        restarted = supervisor.workers.record_restart(system_health.worker_id, pid=os.getpid())
                        runtime.event(
                            logger_name="caretaker.watchdog",
                            severity=30,
                            channel=LogChannel.CARETAKER_INTERNAL,
                            message="Restarted failed Caretaker system collector",
                            fields={
                                "worker_id": str(system_health.worker_id),
                                "restart_count": restarted.restart_count,
                                "backoff_seconds": delay,
                            },
                        )
                    elif restart_policy.exhaustion_action is WorkerFailureAction.STOP_APPLICATION:
                        runtime.event(
                            logger_name="caretaker.watchdog",
                            severity=50,
                            channel=LogChannel.EMERGENCY,
                            message="System collector restart policy exhausted; stopping application",
                            fields={"worker_id": str(system_health.worker_id)},
                        )
                        child.terminate()

    health_thread = threading.Thread(target=health_loop, name="caretaker-health-monitor", daemon=True)
    health_thread.start()
    try:
        return child.wait()
    finally:
        health_stop.set()
        health_thread.join(timeout=3)
        if collector:
            collector.stop()
        if collector_thread:
            collector_thread.join(timeout=10)
        control.stop()
        server.stop()
        supervisor.watchdog.stop()
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
