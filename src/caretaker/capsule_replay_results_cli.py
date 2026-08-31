"""Inspect persisted Incident Capsule replay results without changing evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .console import discover_control_socket
from .logging.ipc import control_request
from .replay import ReplayResultStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-capsule-replay-results",
        description="List or load verified, persisted Incident Capsule replay results.",
    )
    parser.add_argument("--socket", type=Path, help="explicit caretaker-run control socket")
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory or parent containing one active run",
    )
    parser.add_argument(
        "--content-sha256",
        help="load one result by its 64-character content hash instead of listing summaries",
    )
    parser.add_argument("--limit", type=int, default=100, help="maximum summaries to return")
    args = parser.parse_args(argv)
    if args.limit <= 0:
        parser.error("--limit must be greater than zero")

    data_directory = args.data_directory.expanduser().resolve()
    socket_path = (
        args.socket.expanduser().resolve()
        if args.socket
        else discover_control_socket(data_directory)
    )
    if socket_path is not None:
        request = {
            "command": "incident-capsule-replay-results",
            "limit": args.limit,
        }
        if args.content_sha256:
            request["content_sha256"] = args.content_sha256
        result = control_request(socket_path, request, timeout=30.0)
    else:
        store = ReplayResultStore(data_directory, create_directory=False)
        if args.content_sha256:
            result = {
                "ok": True,
                "read_only": True,
                "integrity_verified": True,
                "result": store.load(args.content_sha256),
            }
        else:
            result = {
                "ok": True,
                "read_only": True,
                "results": store.list_summaries(limit=args.limit),
            }
    json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
