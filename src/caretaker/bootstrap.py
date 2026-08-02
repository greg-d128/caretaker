from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

from .logging import configure_remote
from .logging.policy import OperatorLoggingPolicy, load_operator_policy


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        raise SystemExit("Usage: python -m caretaker.bootstrap <module> [args...]")
    module, *module_args = argv
    policy_path = os.environ.get("CARETAKER_LOGGING_POLICY")
    if policy_path:
        policy, _ = load_operator_policy(policy_path)
    else:
        policy = OperatorLoggingPolicy.application_defaults(
            directory=os.environ.get("CARETAKER_DATA_DIR", "./caretaker-data"),
            application_id=os.environ.get("CARETAKER_APPLICATION_ID", module),
        )
    socket_path = os.environ["CARETAKER_EVENT_SOCKET"]
    runtime = configure_remote(policy, socket_path)
    old_argv = sys.argv
    sys.argv = [module, *module_args]
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return 0
    finally:
        sys.argv = old_argv
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
