from __future__ import annotations

import json
import os
import runpy
import sys
import threading
from pathlib import Path

from .authority import load_authority_runtime_from_environment
from .logging import (
    ControlSocketServer,
    EvidencePriority,
    LogChannel,
    configure_remote,
)
from .logging.policy import OperatorLoggingPolicy, load_operator_policy
from .operator import control_failure_response, get_operator_runtime_registry


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        raise SystemExit("Usage: python -m caretaker.bootstrap <module> [args...]")
    module, *module_args = argv
    authority_policy = load_authority_runtime_from_environment()
    policy_path = os.environ.get("CARETAKER_LOGGING_POLICY")
    if policy_path:
        policy, _ = load_operator_policy(policy_path)
    else:
        policy = OperatorLoggingPolicy.application_defaults(
            directory=os.environ.get("CARETAKER_DATA_DIR", "./caretaker-data"),
            application_id=os.environ.get("CARETAKER_APPLICATION_ID", module),
        )
    declared_policy = policy
    policy = authority_policy.apply_dataclass(policy, prefix="logging")
    socket_path = os.environ["CARETAKER_EVENT_SOCKET"]
    runtime = configure_remote(policy, socket_path)
    runtime._declared_policy = declared_policy
    registry = get_operator_runtime_registry()
    diagnostic_debug = os.environ.get(
        "CARETAKER_DIAGNOSTIC_DEBUG", ""
    ).strip().lower() in {"1", "true", "yes", "on"}

    def runtime_control_handler(request, credentials):
        try:
            return registry.handle_request(request, credentials)
        except Exception as exc:
            response = control_failure_response(
                request,
                credentials,
                exc,
                include_debug=diagnostic_debug,
            )
            error = response["error"]
            debug = error.get("debug")
            fields = {
                key: value
                for key, value in error.items()
                if key not in {"debug", "diagnostic_persisted"}
            }
            try:
                envelope = runtime.event(
                    logger_name="caretaker.operator",
                    severity=int(error["severity"]),
                    channel=LogChannel.CARETAKER_INTERNAL,
                    message=str(error["message"]),
                    fields=fields,
                    attachment_payload=(
                        json.dumps(debug, sort_keys=True, default=str).encode("utf-8")
                        if debug
                        else None
                    ),
                    attachment_content_type="application/json",
                    attachment_priority=EvidencePriority.DEBUG,
                    origin="caretaker",
                )
                error["diagnostic_persisted"] = envelope is not None
            except Exception as logging_exc:
                # Never recurse through logging while reporting a logging failure.
                error["diagnostic_persisted"] = False
                error["diagnostic_persistence_error"] = {
                    "exception_type": type(logging_exc).__name__,
                    "message": str(logging_exc)[:2048],
                }
                try:
                    print(
                        json.dumps(
                            {
                                "event": "caretaker.diagnostic.persistence.failed",
                                "diagnostic_id": error["diagnostic_id"],
                                "operation": error["operation"],
                                "exception_type": type(logging_exc).__name__,
                                "message": str(logging_exc)[:2048],
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                    )
                except Exception:
                    pass
            return response

    runtime_control = None
    runtime_control_thread = None
    runtime_control_path = os.environ.get("CARETAKER_RUNTIME_CONTROL_SOCKET")
    if runtime_control_path:
        runtime_control = ControlSocketServer(
            runtime_control_path,
            runtime_control_handler,
            allowed_uids={os.getuid()},
        )
        runtime_control.start()
        runtime_control_thread = threading.Thread(
            target=runtime_control.serve_forever,
            name="caretaker-runtime-control",
            daemon=True,
        )
        runtime_control_thread.start()

    old_argv = sys.argv
    sys.argv = [module, *module_args]
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return 0
    finally:
        sys.argv = old_argv
        if runtime_control is not None:
            runtime_control.stop()
        if runtime_control_thread is not None:
            runtime_control_thread.join(timeout=1.0)
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
