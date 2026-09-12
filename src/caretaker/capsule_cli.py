"""Non-interactive Incident Capsule Explorer assistance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from .capsule import IncidentCapsuleStore
from .capsule_assistance import assist_capsules
from .console import discover_control_socket
from .logging.ipc import control_request, wait_for_job
from .provider_security import endpoint_policy_from_mapping


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-capsule-explorer",
        description="Ask a bounded, read-only LLM question of historical Incident Capsules.",
    )
    parser.add_argument("--socket", type=Path, help="explicit caretaker-run control socket")
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory or parent containing one active run",
    )
    parser.add_argument("--query", required=True, help="advisory question to ask")
    parser.add_argument("--model", required=True, help="local Ollama model name")
    parser.add_argument(
        "--scope",
        choices=("all", "incident", "selected"),
        default="all",
        help="historical capsule scope (default: all)",
    )
    parser.add_argument("--incident-id", help="incident UUID for incident scope")
    parser.add_argument("--capsule-id", help="capsule UUID for selected scope")
    parser.add_argument("--endpoint", help="Ollama generate endpoint (defaults to policy or loopback)")
    parser.add_argument("--ollama-endpoint-mode", choices=("local_only", "remote_unverified", "remote_server_verified", "remote_attested"))
    parser.add_argument("--ollama-ca-bundle")
    parser.add_argument("--ollama-spki-pin", action="append", default=[])
    parser.add_argument("--ollama-certificate-pin", action="append", default=[])
    parser.add_argument("--ollama-client-cert")
    parser.add_argument("--ollama-client-key")
    parser.add_argument("--ollama-attestation")
    parser.add_argument("--ollama-attestation-public-key")
    parser.add_argument("--accept-remote-risk", action="store_true")
    parser.add_argument("--insecure-tls", action="store_true")
    parser.add_argument("--limit", type=int, default=50, help="maximum capsules to assess")
    args = parser.parse_args(argv)
    if args.scope == "incident" and not args.incident_id:
        parser.error("--scope incident requires --incident-id")
    if args.scope == "selected" and not args.capsule_id:
        parser.error("--scope selected requires --capsule-id")

    data_directory = args.data_directory.expanduser().resolve()
    policy_values = {
        "mode": args.ollama_endpoint_mode,
        "ca_bundle": args.ollama_ca_bundle,
        "spki_pins": args.ollama_spki_pin,
        "certificate_pins": args.ollama_certificate_pin,
        "client_cert": args.ollama_client_cert,
        "client_key": args.ollama_client_key,
        "attestation": args.ollama_attestation,
        "attestation_public_key": args.ollama_attestation_public_key,
        "accept_remote_risk": args.accept_remote_risk,
        "insecure_tls": args.insecure_tls,
    }
    explicit_security = any(value not in (None, [], False) for value in policy_values.values())
    endpoint_security = {
        key: value for key, value in policy_values.items() if value not in (None, [], False)
    }
    endpoint_policy = endpoint_policy_from_mapping(endpoint_security) if explicit_security else None
    socket_path = args.socket.expanduser().resolve() if args.socket else discover_control_socket(data_directory)
    if socket_path is not None:
        request = {
            "command": "incident-capsule-assist",
            "query": args.query,
            "model": args.model,
            "scope": args.scope,
            "limit": args.limit,
        }
        if args.incident_id:
            request["incident_id"] = args.incident_id
        if args.capsule_id:
            request["capsule_id"] = args.capsule_id
        if explicit_security:
            request["endpoint_security"] = endpoint_security
        result = control_request(socket_path, request, timeout=360.0)
        if result.get("accepted") and isinstance(result.get("job"), dict):
            completed = wait_for_job(
                socket_path,
                str(result["job"]["job_id"]),
                timeout=3600.0,
            )
            job = completed.get("job")
            if isinstance(job, dict) and isinstance(job.get("result"), dict):
                result = {
                    **job["result"],
                    "job_id": job.get("job_id"),
                    "job_state": job.get("state"),
                }
            else:
                result = completed
    else:
        capsule_directory = data_directory / "incident-capsules"
        if not capsule_directory.is_dir():
            parser.error(f"No Incident Capsule directory found at {capsule_directory}")
        store = IncidentCapsuleStore(data_directory)
        if args.scope == "all":
            summaries = store.list_summaries(limit=args.limit)
        elif args.scope == "incident":
            summaries = store.list_summaries(
                incident_id=UUID(args.incident_id),
                limit=args.limit,
            )
        else:
            summaries = [
                item for item in store.list_summaries(limit=200)
                if str(item.get("capsule_id") or "") == args.capsule_id
            ]
        result = assist_capsules(
            store,
            summaries,
            query=args.query,
            model=args.model,
            endpoint=args.endpoint,
            endpoint_policy=endpoint_policy,
        )
        result.update({"ok": True, "scope": args.scope, "non_interactive": True})
    json.dump(result, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
