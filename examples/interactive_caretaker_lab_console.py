"""Attach to the live Interactive Caretaker Behavior Lab.

This is an example-specific observation and operator console. It talks to the
lab process over a same-UID Unix-domain control socket using Caretaker's local
control protocol. It does not expose arbitrary Python or shell execution.

Start the lab in one terminal, then from another terminal run::

    PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console

Type ``help`` after connecting.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import sys
from typing import Any

from caretaker.logging.ipc import control_request


DEFAULT_LAB_ROOT = Path(
    os.environ.get("CARETAKER_LAB_ROOT", "./caretaker-interactive-lab")
).resolve()
DEFAULT_SOCKET = DEFAULT_LAB_ROOT / "caretaker-data" / "run" / "lab-console.sock"


HELP = """
Observation commands
--------------------
status                         Runtime/socket summary.
targets                        List targets and current implementation state.
state TARGET                   Show one target's FunctionSlot/variant state.
policy TARGET                  Show the effective Caretaker policy for a target.
summary TARGET                 Show recent Guard behavior summary.
events [TARGET] [LIMIT]        Show Guard behavior events; target is optional.
deviations TARGET [LIMIT]      Show Guard baseline deviations.
inspections TARGET [LIMIT]     Show Guard runtime/code inspections.
decisions [LIMIT]              Show Guard decisions.
repair [TARGET] [LIMIT]        Show Repair events; target is optional.
logs [LIMIT]                   Show recent persisted Caretaker log records.
collector [LIMIT]              Show synthetic loopback collector events.

Operator actions
----------------
baseline TARGET                Accept the target's current Guard baseline.
approvals                      Show repairs awaiting operator approval.
approve EPISODE_ID             Approve a pending Repair episode.
reject EPISODE_ID [REASON]     Reject a pending Repair episode.

Console commands
----------------
help                           Show this help.
quit | exit                    Disconnect from the lab console.

TARGET may be the menu number, short name, or target id, for example:
  1
  divide
  lab.divide

Examples
--------
  events lab.divide 20
  baseline lab.divide
  deviations lab.divide
  repair lab.divide
  approvals
  approve 5d2817c8-...
  inspections lab.divide
  logs 30
""".strip()


def _request(socket_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    response = control_request(socket_path, payload)
    if response.get("ok") is False:
        raise RuntimeError(str(response.get("error", "lab console request failed")))
    return response


def _positive_int(value: str | None, default: int = 30) -> int:
    if value is None:
        return default
    parsed = int(value)
    if parsed <= 0:
        raise ValueError("limit must be greater than zero")
    return min(parsed, 200)


def _parse_command(words: list[str]) -> dict[str, Any] | None:
    if not words:
        return None

    command = words[0].lower()
    args = words[1:]

    if command in {"quit", "exit"}:
        return {"_local": "quit"}
    if command in {"help", "?"}:
        return {"_local": "help"}
    if command in {"status", "targets", "approvals"}:
        if args:
            raise ValueError(f"{command} does not take arguments")
        return {"command": command}
    if command in {"state", "policy", "summary", "baseline"}:
        if len(args) != 1:
            raise ValueError(f"usage: {command} TARGET")
        server_command = "baseline-accept" if command == "baseline" else command
        return {"command": server_command, "target": args[0]}
    if command in {"events", "repair"}:
        target = None
        limit = 30
        if args:
            if args[0].isdigit():
                limit = _positive_int(args[0])
            else:
                target = args[0]
                if len(args) > 1:
                    limit = _positive_int(args[1])
        if len(args) > 2:
            raise ValueError(f"usage: {command} [TARGET] [LIMIT]")
        return {
            "command": "repair-events" if command == "repair" else "events",
            "target": target,
            "limit": limit,
        }
    if command in {"deviations", "inspections"}:
        if not args or len(args) > 2:
            raise ValueError(f"usage: {command} TARGET [LIMIT]")
        return {
            "command": command,
            "target": args[0],
            "limit": _positive_int(args[1] if len(args) > 1 else None),
        }
    if command in {"decisions", "logs", "collector"}:
        if len(args) > 1:
            raise ValueError(f"usage: {command} [LIMIT]")
        return {
            "command": command,
            "limit": _positive_int(args[0] if args else None),
        }
    if command == "approve":
        if len(args) != 1:
            raise ValueError("usage: approve EPISODE_ID")
        return {"command": "approve", "episode_id": args[0]}
    if command == "reject":
        if not args:
            raise ValueError("usage: reject EPISODE_ID [REASON]")
        return {
            "command": "reject",
            "episode_id": args[0],
            "reason": " ".join(args[1:]) or "interactive lab rejection",
        }

    raise ValueError(f"unknown command {command!r}; type 'help'")


def _print_response(response: dict[str, Any]) -> None:
    print(json.dumps(response, indent=2, sort_keys=True, default=str))


def _run_one(socket_path: Path, words: list[str]) -> int:
    try:
        payload = _parse_command(words)
        if payload is None:
            return 0
        local = payload.get("_local")
        if local == "help":
            print(HELP)
            return 0
        if local == "quit":
            return 0
        _print_response(_request(socket_path, payload))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def _interactive(socket_path: Path) -> int:
    try:
        status = _request(socket_path, {"command": "status"})
    except OSError as exc:
        print(f"Unable to attach to {socket_path}: {exc}", file=sys.stderr)
        print("Start examples.interactive_caretaker_lab first, or pass --socket.", file=sys.stderr)
        return 1

    print("Caretaker interactive lab console")
    print(f"Attached to: {socket_path}")
    print(f"Lab PID: {status.get('pid')}  supervised={status.get('supervised')}")
    print("Type 'help' for commands; 'quit' to disconnect.")

    while True:
        try:
            line = input("caretaker-lab> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        try:
            words = shlex.split(line)
            payload = _parse_command(words)
            if payload is None:
                continue
            local = payload.get("_local")
            if local == "quit":
                return 0
            if local == "help":
                print(HELP)
                continue
            _print_response(_request(socket_path, payload))
        except (OSError, RuntimeError, ValueError) as exc:
            print(f"ERROR: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Attach to the live Interactive Caretaker Behavior Lab"
    )
    parser.add_argument(
        "--socket",
        type=Path,
        default=Path(os.environ.get("CARETAKER_LAB_CONSOLE_SOCKET", DEFAULT_SOCKET)),
        help="lab console Unix socket path",
    )
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="optional one-shot console command; omit for interactive mode",
    )
    args = parser.parse_args(argv)
    socket_path = args.socket.expanduser().resolve()

    if args.command:
        return _run_one(socket_path, args.command)
    return _interactive(socket_path)


if __name__ == "__main__":
    raise SystemExit(main())
