"""Non-interactive local review of an Incident communication draft."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import UUID

from .capsule import IncidentCapsuleStore
from .communications import review_communication_draft
from .console import discover_control_socket
from .logging.ipc import control_request
from .logging.policy import OperatorLoggingPolicy, load_operator_policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-incident-review",
        description="Record an explicit local review decision for an Incident communication draft.",
    )
    parser.add_argument("--socket", type=Path, help="explicit caretaker-run control socket")
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory or parent containing one active run",
    )
    parser.add_argument("--policy", type=Path, help="logging policy for offline review")
    parser.add_argument("--draft-id", required=True, help="recorded communication draft UUID")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--capsule-id", help="verified capsule UUID")
    source.add_argument("--incident-id", help="incident UUID; use its latest capsule revision")
    parser.add_argument("--decision", choices=("approved", "rejected"), required=True)
    parser.add_argument("--reason", required=True, help="bounded operator reason for the decision")
    parser.add_argument("--output", type=Path, help="write JSON to a new mode-0600 file")
    args = parser.parse_args(argv)

    data_directory = args.data_directory.expanduser().resolve()
    socket_path = args.socket.expanduser().resolve() if args.socket else discover_control_socket(data_directory)
    if socket_path is not None:
        request = {
            "command": "incident-communication-review",
            "draft_id": args.draft_id,
            "decision": args.decision,
            "reason": args.reason,
        }
        if args.capsule_id:
            request["capsule_id"] = args.capsule_id
        else:
            request["incident_id"] = args.incident_id
        result = control_request(socket_path, request, timeout=30.0)
    else:
        if args.policy:
            policy, _snapshot = load_operator_policy(args.policy.expanduser().resolve())
        else:
            policy = OperatorLoggingPolicy.application_defaults(directory=str(data_directory))
        store = IncidentCapsuleStore(data_directory, policy=policy.capsules)
        envelope = (
            store.load(args.capsule_id)
            if args.capsule_id
            else store.latest_for_incident(UUID(args.incident_id))
        )
        if envelope is None:
            parser.error(f"No Incident Capsule found for incident {args.incident_id}")
        result = review_communication_draft(
            store,
            envelope,
            draft_id=args.draft_id,
            decision=args.decision,
            reason=args.reason,
            capsule_policy=policy.capsules,
            reviewer_identity=f"uid:{os.getuid()}",
        )
        result = {
            "ok": True,
            "reviewable": True,
            "delivery_authorized": False,
            **result,
        }

    serialized = json.dumps(result, indent=2, sort_keys=True, default=str) + "\n"
    if args.output:
        output = args.output.expanduser().resolve()
        if not output.parent.is_dir():
            parser.error(f"output directory does not exist: {output.parent}")
        try:
            with output.open("x", encoding="utf-8") as handle:
                handle.write(serialized)
            output.chmod(0o600)
        except FileExistsError:
            parser.error(f"refusing to overwrite existing output: {output}")
    else:
        sys.stdout.write(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
