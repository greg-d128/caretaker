"""Non-interactive, policy-gated Incident Capsule fixture replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .console import discover_control_socket
from .logging.ipc import control_request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-capsule-replay",
        description=(
            "Replay one incident-linked historical fixture through the supervisor's "
            "configured isolated backend."
        ),
    )
    parser.add_argument("--socket", type=Path, help="explicit caretaker-run control socket")
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory or parent containing one active run",
    )
    parser.add_argument("--capsule-id", required=True, help="selected Incident Capsule UUID")
    parser.add_argument("--fixture-id", required=True, help="persistent regression fixture UUID")
    parser.add_argument("--entrypoint", required=True, help="fixture function entrypoint")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source", help="subject function source text")
    source.add_argument("--source-file", type=Path, help="file containing subject function source")
    args = parser.parse_args(argv)

    if args.source is not None:
        source_text = args.source
    else:
        try:
            source_text = args.source_file.read_text(encoding="utf-8")
        except OSError as exc:
            parser.error(f"could not read --source-file: {exc}")

    data_directory = args.data_directory.expanduser().resolve()
    socket_path = (
        args.socket.expanduser().resolve()
        if args.socket
        else discover_control_socket(data_directory)
    )
    if socket_path is None:
        parser.error(
            "Incident Capsule replay requires an active caretaker-run supervisor "
            "with an explicitly configured isolated backend"
        )
    result = control_request(
        socket_path,
        {
            "command": "incident-capsule-replay",
            "capsule_id": args.capsule_id,
            "fixture_id": args.fixture_id,
            "entrypoint": args.entrypoint,
            "source": source_text,
        },
        timeout=360.0,
    )
    json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
