"""Read-only inspection of persistent regression-fixture evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .console import discover_control_socket
from .logging.ipc import control_request
from .regression import RegressionFixtureStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-regression-fixtures",
        description="Inspect bounded, data-only regression fixtures; never execute them.",
    )
    parser.add_argument("--socket", type=Path, help="explicit caretaker-run control socket")
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory",
    )
    parser.add_argument("--target-id", help="limit listing to one target")
    parser.add_argument("--fixture-id", help="load one fixture envelope")
    parser.add_argument("--limit", type=int, default=100, help="maximum fixtures to list")
    args = parser.parse_args(argv)
    if args.fixture_id and args.target_id:
        parser.error("--target-id cannot be used with --fixture-id")

    data_directory = args.data_directory.expanduser().resolve()
    socket_path = args.socket.expanduser().resolve() if args.socket else discover_control_socket(data_directory)
    if socket_path is not None:
        if args.fixture_id:
            result = control_request(
                socket_path,
                {"command": "regression-fixture-get", "fixture_id": args.fixture_id},
            )
        else:
            result = control_request(
                socket_path,
                {
                    "command": "regression-fixture-list",
                    "target_id": args.target_id,
                    "limit": args.limit,
                },
            )
    else:
        store = RegressionFixtureStore(data_directory)
        if args.fixture_id:
            result = {
                "ok": True,
                "envelope": store.load(args.fixture_id),
                "integrity_verified": True,
                "replay_status": "DATA_ONLY_NOT_EXECUTABLE",
            }
        else:
            result = {
                "ok": True,
                "enabled": True,
                "fixtures": store.list_summaries(
                    target_id=args.target_id,
                    limit=args.limit,
                ),
            }
    json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
