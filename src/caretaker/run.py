from __future__ import annotations

import argparse
import hashlib
import importlib
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from uuid import UUID, uuid4

from .authority import (
    PolicyAuthoritySupervisor,
    PolicySetting,
)
from .capsule import IncidentCapsuleStore
from .capsule_assistance import assist_capsules
from .communications import generate_communication_draft, review_communication_draft
from .behavior import (
    BehaviorSnapshotStore,
    BehaviorStatisticsRepository,
    OllamaBehaviorSnapshotAnalyst,
    compare_snapshots,
    snapshot_payload,
    wrap_snapshot,
)
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
from .logging.ipc import (
    ControlSocketServer,
    SocketLogServer,
    control_request,
    unix_socket_exists,
)
from .logging.policy import OperatorLoggingPolicy, load_operator_policy
from .logging.segments import read_segment
from .regression import RegressionFixtureStore
from .replay import (
    IsolatedReplayCoordinator,
    RootlessPodmanReplayBackend,
    execute_capsule_replay,
)
from .integrity import SignatureVerificationMode, verify_release_publication
from .builtin_profiles import builtin_profile_names, load_builtin_profile_supervisor
from .system import SystemCollectionPolicy, SystemDataCollector, SystemOutputPolicy, load_system_policy


def _load_external_signer(specification: str | None):
    if not specification:
        return None
    module_name, separator, attribute = specification.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("external signer must use module:attribute syntax")
    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    if isinstance(value, type):
        value = value()
    elif callable(value) and not hasattr(value, "sign_artifact") and not hasattr(value, "sign_manifest"):
        value = value()
    if not hasattr(value, "public_identity"):
        raise TypeError("external signer must provide public_identity()")
    if not hasattr(value, "sign_artifact") and not hasattr(value, "sign_manifest"):
        raise TypeError("external signer must provide sign_artifact() or sign_manifest()")
    return value


def _behavior_materialization_log(
    envelopes: tuple[dict[str, object], ...],
) -> tuple[str, dict[str, object]]:
    snapshots = [dict(item.get("snapshot") or {}) for item in envelopes]
    subjects = sorted({str(item.get("subject_key") or "unknown") for item in snapshots})
    subject_preview = ", ".join(subjects[:3])
    if len(subjects) > 3:
        subject_preview += f", +{len(subjects) - 3} more"
    count = len(snapshots)
    message = (
        f"Materialized {count} behavior snapshot{'s' if count != 1 else ''}"
        + (f" for {subject_preview}" if subject_preview else "")
    )
    return message, {
        "snapshot_count": count,
        "subject_keys": subjects,
        "snapshot_ids": [str(item.get("snapshot_id") or "") for item in snapshots],
        "seal_reasons": sorted({str(item.get("seal_reason") or "unknown") for item in snapshots}),
        "signature_states": sorted({
            str((envelope.get("integrity") or {}).get("signature_state") or "unknown")
            for envelope in envelopes
        }),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caretaker-run")
    parser.add_argument("--policy")
    parser.add_argument("--data-directory")
    parser.add_argument(
        "--external-signer",
        help="trusted supervisor signer provider in module:attribute form",
    )
    parser.add_argument("--system-data", action="store_true")
    parser.add_argument(
        "--authority-stack",
        help="TOML descriptor for signed/unsigned Caretaker policy authority layers",
    )
    parser.add_argument(
        "--profile",
        choices=builtin_profile_names(),
        help="select a built-in framework profile before importing the application",
    )
    parser.add_argument(
        "--profile-trusted-fingerprint",
        action="append",
        default=[],
        help="independently trusted profile-root fingerprint; repeat for all three identities",
    )
    parser.add_argument(
        "--integrity-publication-directory",
        help="verify signed root and release manifests before starting the application",
    )
    parser.add_argument(
        "--integrity-artifact-root",
        help="source/artifact tree covered by the manifests (defaults to publication directory)",
    )
    parser.add_argument(
        "--integrity-trusted-fingerprint",
        action="append",
        default=[],
        help="independently trusted primary fingerprint; repeat for each trusted root identity",
    )
    parser.add_argument(
        "--integrity-verification-mode",
        choices=[item.value for item in SignatureVerificationMode],
        default=SignatureVerificationMode.FULL_PUBLICATION.value,
    )
    parser.add_argument(
        "--replay-podman-image",
        help=(
            "pre-provisioned local rootless Podman image for isolated historical replay; "
            "replay remains disabled unless policy enables it"
        ),
    )
    parser.add_argument(
        "--replay-podman-executable",
        default="podman",
        help="Podman executable used by the optional isolated replay backend",
    )
    parser.add_argument(
        "--replay-cgroup-manager",
        choices=("cgroupfs", "systemd"),
        default="cgroupfs",
        help="cgroup manager for the optional rootless replay backend",
    )
    parser.add_argument("module")
    parser.add_argument("module_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.profile and args.authority_stack:
        parser.error("--profile and --authority-stack are mutually exclusive")
    release_integrity: dict[str, object] = {
        "status": "NOT_CONFIGURED",
        "configured": False,
        "root_anchored": False,
        "manifests": {},
    }
    if args.integrity_publication_directory:
        if not args.integrity_trusted_fingerprint:
            parser.error(
                "--integrity-publication-directory requires at least one "
                "--integrity-trusted-fingerprint obtained independently"
            )
        try:
            release_integrity = verify_release_publication(
                args.integrity_publication_directory,
                trusted_primary_fingerprints=args.integrity_trusted_fingerprint,
                artifact_root=args.integrity_artifact_root,
                verification_mode=SignatureVerificationMode(args.integrity_verification_mode),
            )
        except Exception as exc:
            parser.error(f"release-integrity verification could not complete: {type(exc).__name__}: {exc}")
        if release_integrity["status"] != "TRUSTED":
            parser.error("configured release-integrity verification failed")
    if args.policy:
        declared_policy, _ = load_operator_policy(args.policy)
    else:
        directory = args.data_directory or f"./caretaker-data/{args.module}"
        declared_policy = OperatorLoggingPolicy.application_defaults(
            directory=directory, application_id=args.module
        )

    if args.profile:
        try:
            authority = load_builtin_profile_supervisor(
                args.profile,
                trusted_primary_fingerprints=(
                    tuple(args.profile_trusted_fingerprint)
                    if args.profile_trusted_fingerprint
                    else None
                ),
            )
        except Exception as exc:
            parser.error(f"built-in profile could not be loaded: {type(exc).__name__}: {exc}")
    elif args.authority_stack:
        authority = PolicyAuthoritySupervisor.from_stack_file(args.authority_stack)
    else:
        authority = PolicyAuthoritySupervisor()
    policy_transform = lambda value: authority.effective.apply_dataclass(
        value, prefix="logging"
    )
    policy = policy_transform(declared_policy)
    authority.set_snapshot_path(
        Path(policy.directory) / "policy" / "authority-effective.json"
    )
    try:
        external_signer = _load_external_signer(args.external_signer)
    except (ImportError, AttributeError, TypeError, ValueError) as exc:
        parser.error(f"external signer configuration is invalid: {exc}")
    runtime = LoggingRuntime(
        declared_policy,
        source_path=args.policy,
        supervised=True,
        policy_transform=policy_transform,
        external_signer=external_signer,
    )
    policy = runtime.active_policy
    behavior_store = BehaviorSnapshotStore(
        policy.directory, artifact_signer=runtime.writer.signing_service
    )
    capsule_store = IncidentCapsuleStore(
        policy.directory,
        policy=policy.capsules,
        artifact_signer=runtime.writer.signing_service,
    )
    regression_fixture_store = (
        RegressionFixtureStore(policy.directory, policy=policy.regression)
        if policy.regression.enabled
        else None
    )
    replay_coordinator = None
    if regression_fixture_store is not None:
        replay_backend = (
            RootlessPodmanReplayBackend(
                args.replay_podman_image,
                podman_executable=args.replay_podman_executable,
                cgroup_manager=args.replay_cgroup_manager,
            )
            if args.replay_podman_image
            else None
        )
        replay_coordinator = IsolatedReplayCoordinator(
            regression_fixture_store,
            policy=policy.regression,
            backend=replay_backend,
        ) if replay_backend is not None else IsolatedReplayCoordinator(
            regression_fixture_store,
            policy=policy.regression,
        )
    behavior_statistics = BehaviorStatisticsRepository(policy.directory)
    behavior_revision = {"value": 0}
    behavior_collection_id = str(uuid4())
    runtime.event(
        logger_name="caretaker.authority",
        severity=30 if authority.effective.overall_assurance in {"GUARANTEE_VIOLATED", "INVALID_AUTHORITY_CHAIN"} else 20,
        channel=LogChannel.CARETAKER_INTERNAL,
        message="Policy authority stack loaded",
        fields={
            "generation": authority.effective.generation,
            "fingerprint": authority.effective.fingerprint,
            "assurance": authority.effective.overall_assurance,
            "layers": authority.effective.layer_status(),
        },
    )
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
    authority_generation_holder = {"generation": authority.effective.generation}
    authority_runtime_match_holder: dict[str, bool | None] = {"match": None}
    authority_lease_holder = {
        str(lease.lease_id): lease for lease in authority.effective.runtime_leases
    }

    def deployment_fingerprint() -> str | None:
        layer = next(
            (
                item
                for item in authority.effective.layers
                if getattr(getattr(item, "kind", None), "value", None) == "deployment"
            ),
            None,
        )
        return layer.fingerprint if layer else None

    def materialize_behavior_snapshots(*, maximum: int = 100) -> int:
        envelopes = behavior_statistics.materialize_pending(
            behavior_store,
            authority_fingerprint=authority.effective.fingerprint,
            deployment_fingerprint=deployment_fingerprint(),
            maximum=maximum,
        )
        if envelopes:
            message, fields = _behavior_materialization_log(envelopes)
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message=message,
                fields=fields,
            )
        behavior_revision["value"] += len(envelopes)
        return len(envelopes)

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

    def capsule_evidence_references(incident_id: UUID, *, limit: int = 100) -> list[dict[str, object]]:
        references = []
        for record in recent_log_records(max(1000, limit)):
            if record.incident_id != incident_id:
                continue
            references.append({
                "record_id": str(record.record_id),
                "occurred_at": record.occurred_at.isoformat(),
                "channel": record.channel.name,
                "content_sha256": hashlib.sha256(
                    json.dumps(
                        {
                            "record_id": str(record.record_id),
                            "sequence_number": record.sequence_number,
                            "message": record.formatted_message or record.message_template,
                            "fields": dict(record.fields),
                        },
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest(),
            })
        return references

    def capsule_timeline(incident_id: UUID, *, limit: int = 100) -> list[dict[str, object]]:
        timeline = []
        for record in recent_log_records(max(1000, limit)):
            if record.incident_id != incident_id:
                continue
            message = record.formatted_message or record.message_template
            timeline.append({
                "record_id": str(record.record_id),
                "sequence_number": record.sequence_number,
                "occurred_at": record.occurred_at.isoformat(),
                "severity": record.severity,
                "channel": record.channel.name,
                "logger": record.logger_name,
                "message": message,
                "target_id": str(record.target_id) if record.target_id else None,
                "call_id": str(record.call_id) if record.call_id else None,
                "incident_id": str(record.incident_id) if record.incident_id else None,
                "fields": dict(record.fields),
                "content_sha256": hashlib.sha256(
                    json.dumps(
                        {
                            "record_id": str(record.record_id),
                            "sequence_number": record.sequence_number,
                            "message": message,
                            "fields": dict(record.fields),
                        },
                        sort_keys=True,
                        default=str,
                    ).encode("utf-8")
                ).hexdigest(),
                "evidence_status": "PERSISTED_LOG_RECORD",
            })
        return timeline[-max(1, limit):]

    def runtime_authority_match() -> tuple[bool | None, dict[str, object] | None]:
        if not unix_socket_exists(runtime_control_socket):
            return None, None
        try:
            child_status = control_request(runtime_control_socket, {"command": "status"})
        except OSError:
            return None, None
        child_authority = child_status.get("authority_policy")
        if not isinstance(child_authority, dict):
            return False, child_status
        expected = authority.effective
        matches = (
            int(child_authority.get("generation", -1)) == expected.generation
            and str(child_authority.get("fingerprint", "")) == expected.fingerprint
        )
        return matches, child_status


    def control_handler(request, credentials):
        command = request.get("command")
        if command in {"status", "health"}:
            child = child_holder.get("child")
            supervisor = supervisor_holder.get("supervisor")
            runtime_policy_match, application_runtime = runtime_authority_match()
            effective_authority = authority.effective
            signing_identity = None
            if runtime.active_policy.signing.publish_public_key_to_control_clients:
                identity = runtime.writer.signing_service.identity
                if identity is not None:
                    signing_identity = asdict(identity) if hasattr(identity, "__dataclass_fields__") else dict(identity)
            return {"ok": True, "application_pid": child.pid if child else None,
                    "application_running": child.poll() is None if child else False,
                    "behavior_collection_id": behavior_collection_id,
                    "behavior_revision": behavior_revision["value"],
                    "policy_generation": runtime.effective.generation,
                    "active_leases": list(leases),
                    "runtime_signing_identity": signing_identity,
                    "release_integrity": release_integrity,
                    "authority_policy": {
                        "generation": effective_authority.generation,
                        "fingerprint": effective_authority.fingerprint,
                        "overall_assurance": effective_authority.overall_assurance,
                        "violations": len(effective_authority.violations),
                        "layers": effective_authority.layer_status(),
                        "runtime_matches_supervisor": runtime_policy_match,
                    },
                    "workers": [asdict(item) for item in supervisor.workers.all()] if supervisor else [],
                    "runtime": application_runtime}
        if command == "incident-capsule-list":
            raw_incident_id = str(request.get("incident_id") or "").strip() or None
            incident_id = UUID(raw_incident_id) if raw_incident_id else None
            limit = max(1, min(int(request.get("limit", 100)), 200))
            return {
                "ok": True,
                "capsules": capsule_store.list_summaries(
                    incident_id=incident_id,
                    limit=limit,
                ),
            }
        if command == "regression-fixture-list":
            target_id = str(request.get("target_id") or "").strip() or None
            limit = max(1, min(int(request.get("limit", 100)), 500))
            if regression_fixture_store is None:
                return {"ok": True, "enabled": False, "fixtures": []}
            return {
                "ok": True,
                "enabled": True,
                "fixtures": regression_fixture_store.list_summaries(
                    target_id=target_id,
                    limit=limit,
                ),
            }
        if command == "regression-fixture-get":
            fixture_id = str(request.get("fixture_id") or "").strip()
            if not fixture_id:
                raise ValueError("regression-fixture-get requires fixture_id")
            if regression_fixture_store is None:
                raise PermissionError("logging.regression.enabled=False")
            return {
                "ok": True,
                "envelope": regression_fixture_store.load(fixture_id),
                "integrity_verified": True,
                "replay_status": "DATA_ONLY_NOT_EXECUTABLE",
            }
        if command == "incident-capsule-get":
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            if not raw_capsule_id:
                raise ValueError("incident-capsule-get requires capsule_id")
            revision_value = request.get("revision")
            revision = int(revision_value) if revision_value is not None else None
            return {
                "ok": True,
                "envelope": capsule_store.load(raw_capsule_id, revision=revision),
                "integrity_verified": True,
            }
        if command == "incident-capsule-replay":
            if replay_coordinator is None:
                raise PermissionError(
                    "persistent regression fixtures are disabled; capsule replay is unavailable"
                )
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            fixture_id = str(request.get("fixture_id") or "").strip()
            entrypoint = str(request.get("entrypoint") or "").strip()
            source = request.get("source")
            if not raw_capsule_id:
                raise ValueError("incident-capsule-replay requires capsule_id")
            if not fixture_id:
                raise ValueError("incident-capsule-replay requires fixture_id")
            if not entrypoint:
                raise ValueError("incident-capsule-replay requires entrypoint")
            if not isinstance(source, str) or not source:
                raise ValueError("incident-capsule-replay requires source text")
            result = execute_capsule_replay(
                replay_coordinator,
                capsule_store,
                capsule_id=raw_capsule_id,
                fixture_id=fixture_id,
                entrypoint=entrypoint,
                source=source,
            )
            runtime.event(
                logger_name="caretaker.capsule",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Incident Capsule fixture replay completed",
                fields={
                    "capsule_id": result["capsule_id"],
                    "incident_id": result["incident_id"],
                    "fixture_id": result["fixture_id"],
                    "outcome": result["outcome"],
                    "backend_name": result["backend_name"],
                    "isolation_level": result["isolation_level"],
                    "capsule_modified": False,
                },
                origin="caretaker",
            )
            return {"ok": True, **result}
        if command == "incident-capsule-artifact":
            raw_artifact_id = str(request.get("artifact_id") or "").strip()
            if not raw_artifact_id:
                raise ValueError("incident-capsule-artifact requires artifact_id")
            return {
                "ok": True,
                "envelope": capsule_store.load_artifact(raw_artifact_id),
                "integrity_verified": True,
            }
        if command == "incident-capsule-timeline":
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if not raw_incident_id:
                raise ValueError("incident-capsule-timeline requires incident_id")
            limit = max(1, min(int(request.get("limit", 100)), 200))
            return {
                "ok": True,
                "incident_id": raw_incident_id,
                "records": capsule_timeline(UUID(raw_incident_id), limit=limit),
                "evidence_status": "PERSISTED_LOG_WINDOW",
            }
        if command == "incident-capsule-assist":
            query = str(request.get("query") or "").strip()
            model = str(request.get("model") or "").strip()
            if not query:
                raise ValueError("incident-capsule-assist requires query")
            if not model:
                raise ValueError("incident-capsule-assist requires model")
            scope = str(request.get("scope") or "all").strip().lower()
            limit = max(1, min(int(request.get("limit", 50)), 50))
            if scope == "selected":
                raw_capsule_id = str(request.get("capsule_id") or "").strip()
                if not raw_capsule_id:
                    raise ValueError("selected Incident Capsule assistance requires capsule_id")
                summaries = [
                    item
                    for item in capsule_store.list_summaries(limit=200)
                    if str(item.get("capsule_id") or "") == raw_capsule_id
                ]
            elif scope == "incident":
                raw_incident_id = str(request.get("incident_id") or "").strip()
                if not raw_incident_id:
                    raise ValueError("incident-scoped assistance requires incident_id")
                summaries = capsule_store.list_summaries(
                    incident_id=UUID(raw_incident_id),
                    limit=limit,
                )
            elif scope == "all":
                summaries = capsule_store.list_summaries(limit=limit)
            else:
                raise ValueError("incident-capsule-assist scope must be selected, incident, or all")
            result = assist_capsules(
                capsule_store,
                summaries,
                query=query,
                model=model,
                endpoint=str(
                    request.get("endpoint")
                    or "http://127.0.0.1:11434/api/generate"
                ),
                timeline_provider=lambda incident_id: capsule_timeline(
                    incident_id,
                    limit=200,
                ),
            )
            return {
                "ok": True,
                "scope": scope,
                "non_interactive": True,
                **result,
            }
        if command == "incident-communication-draft":
            profile_id = str(request.get("audience_profile_id") or "").strip()
            if not profile_id:
                raise ValueError("incident-communication-draft requires audience_profile_id")
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if bool(raw_capsule_id) == bool(raw_incident_id):
                raise ValueError(
                    "incident-communication-draft requires exactly one of capsule_id or incident_id"
                )
            envelope = (
                capsule_store.load(raw_capsule_id)
                if raw_capsule_id
                else capsule_store.latest_for_incident(UUID(raw_incident_id))
            )
            if envelope is None:
                raise KeyError(f"No Incident Capsule found for incident {raw_incident_id}")
            raw_record = request.get("record", True)
            if not isinstance(raw_record, bool):
                raise ValueError("incident-communication-draft record must be boolean")
            result = generate_communication_draft(
                capsule_store,
                envelope,
                audience_profile_id=profile_id,
                policy=runtime.active_policy.communications,
                capsule_policy=runtime.active_policy.capsules,
                effective_policy_fingerprint=runtime.snapshot.content_hash,
                record=raw_record,
                run_id=runtime.run_id,
            )
            draft = result.get("draft") or {}
            recording = result.get("recording") or {}
            runtime.event(
                logger_name="caretaker.communication",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Incident communication draft generated",
                fields={
                    "draft_id": draft.get("draft_id"),
                    "audience_profile_id": draft.get("audience_profile_id"),
                    "source_capsule_id": draft.get("source_capsule_id"),
                    "recording_status": recording.get("status"),
                    "delivery_authorized": False,
                },
            )
            return {
                "ok": True,
                "reviewable": True,
                "delivery_authorized": False,
                **result,
            }
        if command == "incident-communication-review":
            draft_id = str(request.get("draft_id") or "").strip()
            decision = str(request.get("decision") or "").strip()
            reason = str(request.get("reason") or "").strip()
            if not draft_id:
                raise ValueError("incident-communication-review requires draft_id")
            if not decision:
                raise ValueError("incident-communication-review requires decision")
            if not reason:
                raise ValueError("incident-communication-review requires reason")
            raw_capsule_id = str(request.get("capsule_id") or "").strip()
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if bool(raw_capsule_id) == bool(raw_incident_id):
                raise ValueError(
                    "incident-communication-review requires exactly one of capsule_id or incident_id"
                )
            envelope = (
                capsule_store.load(raw_capsule_id)
                if raw_capsule_id
                else capsule_store.latest_for_incident(UUID(raw_incident_id))
            )
            if envelope is None:
                raise KeyError(f"No Incident Capsule found for incident {raw_incident_id}")
            result = review_communication_draft(
                capsule_store,
                envelope,
                draft_id=draft_id,
                decision=decision,
                reason=reason,
                capsule_policy=runtime.active_policy.capsules,
                reviewer_identity=f"uid:{credentials[1]}",
                run_id=runtime.run_id,
            )
            review = result.get("review") or {}
            runtime.event(
                logger_name="caretaker.communication",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Incident communication draft reviewed",
                fields={
                    "draft_id": draft_id,
                    "review_decision": (review.get("metadata") or {}).get("review_decision"),
                    "recording_status": result.get("status"),
                    "delivery_authorized": False,
                },
            )
            return {
                "ok": True,
                "reviewable": True,
                "delivery_authorized": False,
                **result,
            }
        if command == "incident-capsule-attach-view":
            raw_incident_id = str(request.get("incident_id") or "").strip()
            if not raw_incident_id:
                raise ValueError("incident-capsule-attach-view requires incident_id")
            incident_id = UUID(raw_incident_id)
            operator_view = request.get("operator_view")
            if not isinstance(operator_view, str) or not operator_view.strip():
                raise ValueError("incident-capsule-attach-view requires a non-empty operator_view")
            tab_id = str(request.get("tab_id") or "unknown").strip() or "unknown"
            target_id = str(request.get("target_id") or "").strip() or None
            call_id = str(request.get("call_id") or "").strip() or None
            result = capsule_store.attach_artifact(
                incident_id,
                kind="operator-view",
                content={
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "tab_id": tab_id,
                    "target_id": target_id,
                    "incident_id": raw_incident_id,
                    "call_id": call_id,
                    "view": operator_view,
                },
                source="caretaker-console",
                operator_identity=f"uid:{credentials[1]}",
                metadata={"peer_pid": credentials[0], "peer_gid": credentials[2]},
                policy=runtime.active_policy.capsules,
                run_id=runtime.run_id,
                incident_state={
                    "incident_id": raw_incident_id,
                    "target_id": target_id,
                    "call_id": call_id,
                    "source_evidence": capsule_evidence_references(incident_id),
                    "capture_reason": "operator-view",
                },
            )
            capsule_payload = result["capsule"].get("capsule") or {}
            runtime.event(
                logger_name="caretaker.capsule",
                severity=20,
                channel=LogChannel.AUDIT,
                message="Operator view attached to Incident Capsule",
                fields={
                    "incident_id": raw_incident_id,
                    "capsule_id": capsule_payload.get("capsule_id"),
                    "capsule_revision": capsule_payload.get("revision"),
                    "artifact_id": (result["artifact"].get("artifact") or {}).get("artifact_id"),
                    "artifact_content_sha256": (result["artifact"].get("integrity") or {}).get("content_sha256"),
                    "tab_id": tab_id,
                },
                origin="caretaker",
            )
            return {
                "ok": True,
                "capsule": capsule_payload,
                "artifact": result["artifact"].get("artifact"),
                "artifact_path": result["artifact_path"],
            }
        if command == "behavior-list":
            # Generation summaries are compact. Use the full bounded allowance so
            # the console can retain three generations across many subjects.
            limit = max(1, min(int(request.get("limit", 500)), 500))
            collection_status: dict[str, object] = {}
            if unix_socket_exists(runtime_control_socket):
                try:
                    collection_status = control_request(
                        runtime_control_socket,
                        {"command": "behavior-collection-status"},
                    )
                except OSError:
                    collection_status = {"available": False}
            return {
                "ok": True,
                "collection_id": behavior_collection_id,
                "revision": behavior_revision["value"],
                "snapshots": list(behavior_store.list_summaries(limit=limit)),
                "collection_status": collection_status,
            }

        if command == "behavior-get":
            snapshot_id = str(request.get("snapshot_id") or "").strip()
            if not snapshot_id:
                raise ValueError("behavior-get requires snapshot_id")
            return {"ok": True, "envelope": behavior_store.load(snapshot_id)}

        if command == "behavior-capture":
            if not unix_socket_exists(runtime_control_socket):
                raise RuntimeError("Application runtime is unavailable for behavior capture")
            scope = str(request.get("scope") or "function").strip().lower()
            subject = str(request.get("subject") or "").strip()
            if not subject:
                raise ValueError("behavior-capture requires subject")
            reason = str(request.get("reason") or "operator-requested behavior capture").strip()
            if not reason:
                raise ValueError("behavior-capture requires a non-empty reason")
            if len(reason) > 500:
                raise ValueError("behavior-capture reason exceeds the 500 character limit")
            requested_calls = max(1, min(int(request.get("calls", 50)), 1000))
            requested_at = datetime.now(timezone.utc).isoformat()
            request_id = str(uuid4())
            authority_fingerprint = authority.effective.fingerprint
            deployment_fingerprint_value = deployment_fingerprint()
            response = control_request(
                runtime_control_socket,
                {
                    "command": "behavior-capture",
                    "scope": scope,
                    "subject": subject,
                    "calls": requested_calls,
                    "requested_by": f"uid:{credentials[1]}",
                    "reason": reason,
                    "priority": int(request.get("priority", 100)),
                    "deadline": request.get("deadline"),
                },
            )
            if response.get("ok") is False:
                return response
            capture = dict(response["capture"])
            profile = capture.get("profile")
            observed_calls = (
                int(profile.get("call_count") or 0)
                if isinstance(profile, dict)
                else 0
            )
            collection_request = dict(capture.get("collection_request") or {})
            collection_request.update(
                {
                    "request_id": collection_request.get("request_id") or request_id,
                    "requested_at": collection_request.get("requested_at") or requested_at,
                    "requested_by": collection_request.get("requested_by") or f"uid:{credentials[1]}",
                    "reason": collection_request.get("reason") or reason,
                    "scope": collection_request.get("scope") or scope,
                    "subject": collection_request.get("subject") or subject,
                    "requested_calls": collection_request.get("requested_calls") or requested_calls,
                    "requested_generation": collection_request.get("requested_generation")
                    or capture.get("generation_id"),
                    "authority_policy_generation": authority.effective.generation,
                    "authority_policy_fingerprint": authority_fingerprint,
                    "observed_calls": observed_calls,
                    "outcome": collection_request.get("outcome") or "CAPTURED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            capture["collection_request"] = collection_request
            # Generation identity is derived from observed subject/code/
            # monitoring metadata, not request metadata. Previewing it keeps
            # the identity stable before the store adds sequence commitments.
            collection_request["observed_generation"] = snapshot_payload(
                capture,
                authority_fingerprint=authority_fingerprint,
                deployment_fingerprint=deployment_fingerprint_value,
            )["generation_id"]
            envelope = behavior_store.create(
                capture,
                authority_fingerprint=authority_fingerprint,
                deployment_fingerprint=deployment_fingerprint_value,
            )
            behavior_revision["value"] += 1
            snapshot = envelope["snapshot"]
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior snapshot captured",
                fields={
                    "snapshot_id": snapshot["snapshot_id"],
                    "scope": snapshot["scope"],
                    "subject_key": snapshot["subject_key"],
                    "code_hash": snapshot.get("code_hash"),
                    "collection_request_id": collection_request.get("request_id"),
                    "requested_by": collection_request.get("requested_by"),
                    "reason": collection_request.get("reason"),
                    "requested_calls": collection_request.get("requested_calls"),
                    "observed_calls": collection_request.get("observed_calls"),
                    "observed_generation": collection_request.get("observed_generation"),
                    "outcome": collection_request.get("outcome"),
                    "content_sha256": envelope["integrity"]["content_sha256"],
                    "signature_state": envelope["integrity"]["signature_state"],
                },
            )
            return {"ok": True, "envelope": envelope}

        if command in {"behavior-collection-status", "behavior-collection-cancel"}:
            if not unix_socket_exists(runtime_control_socket):
                return {
                    "ok": True,
                    "collections": [],
                    "available": False,
                    "reason": "Application runtime is unavailable for collection status",
                }
            return control_request(runtime_control_socket, request)

        if command in {"behavior-compare", "behavior-previous-compare"}:
            snapshot_a_id = str(request.get("snapshot_a_id") or request.get("snapshot_id") or "").strip()
            if not snapshot_a_id:
                raise ValueError(f"{command} requires snapshot_a_id/snapshot_id")
            left = behavior_store.load(snapshot_a_id)
            if command == "behavior-previous-compare":
                current = left["snapshot"]
                candidates = [
                    item
                    for item in behavior_store.list()
                    if item.get("subject_key") == current.get("subject_key")
                    and str(item.get("created_at") or "") < str(current.get("created_at") or "")
                ]
                if not candidates:
                    raise KeyError("No earlier snapshot exists for this behavior subject")
                right_id = candidates[0]["snapshot_id"]
                right = left
                left = behavior_store.load(right_id)
            else:
                snapshot_b_id = str(request.get("snapshot_b_id") or "").strip()
                if not snapshot_b_id:
                    raise ValueError("behavior-compare requires snapshot_b_id")
                right = behavior_store.load(snapshot_b_id)
            return {"ok": True, "comparison": compare_snapshots(left, right)}

        if command == "behavior-live-compare":
            snapshot_id = str(request.get("snapshot_id") or "").strip()
            if not snapshot_id:
                raise ValueError("behavior-live-compare requires snapshot_id")
            if not unix_socket_exists(runtime_control_socket):
                raise RuntimeError("Application runtime is unavailable for live behavior comparison")
            left = behavior_store.load(snapshot_id)
            snapshot = left["snapshot"]
            scope = snapshot["scope"]
            subject_data = snapshot.get("subject") or {}
            subject = (
                subject_data.get("module_name")
                if scope == "module"
                else subject_data.get("target_id")
            )
            if not subject:
                raise ValueError("Stored snapshot does not identify a live comparison subject")
            response = control_request(
                runtime_control_socket,
                {
                    "command": "behavior-capture",
                    "scope": scope,
                    "subject": subject,
                    "calls": int(request.get("calls", 50)),
                },
            )
            if response.get("ok") is False:
                return response
            live_profile = response.get("capture", {}).get("profile", {})
            if int(live_profile.get("call_count") or 0) <= 0:
                return {
                    "ok": False,
                    "error": {
                        "message": (
                            "The active unsaved behavior window contains no completed calls. "
                            "This action does not execute the function. Run the function, refresh "
                            "Behavior, and compare the newly persisted snapshot instead."
                        ),
                        "failure_kind": "empty-active-behavior-window",
                    },
                }
            current = wrap_snapshot(
                snapshot_payload(
                    response["capture"],
                    authority_fingerprint=authority.effective.fingerprint,
                    deployment_fingerprint=snapshot.get("deployment_fingerprint"),
                )
            )
            return {
                "ok": True,
                "comparison": compare_snapshots(left, current),
                "live_snapshot": current["snapshot"],
            }

        if command == "behavior-archive":
            subject_key = str(request.get("subject_key") or "").strip()
            generation_id = str(request.get("generation_id") or "").strip()
            reason = str(request.get("reason") or "").strip()
            if not subject_key or not generation_id:
                raise ValueError("behavior-archive requires subject_key and generation_id")
            if not reason:
                raise ValueError("behavior-archive requires an operator reason")
            path, snapshot_ids = behavior_store.archive_generation(
                subject_key,
                generation_id,
                reason=reason,
            )
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior snapshots archived",
                fields={
                    "snapshot_ids": snapshot_ids,
                    "snapshot_count": len(snapshot_ids),
                    "subject_key": subject_key,
                    "generation_id": generation_id,
                    "reason": reason,
                    "archive_path": str(path),
                },
            )
            return {
                "ok": True,
                "archive": str(path),
                "snapshot_count": len(snapshot_ids),
                "subject_key": subject_key,
                "generation_id": generation_id,
                "reason": reason,
            }

        if command == "behavior-archive-list":
            return {"ok": True, "archives": list(behavior_store.list_archives())}

        if command == "behavior-archive-verify":
            name = str(request.get("archive") or "").strip()
            if not name:
                raise ValueError("behavior-archive-verify requires archive")
            path = behavior_store.resolve_archive(name)
            return {"ok": True, "verification": behavior_store.verify_archive(path)}

        if command == "behavior-archive-restore":
            name = str(request.get("archive") or "").strip()
            if not name:
                raise ValueError("behavior-archive-restore requires archive")
            path = behavior_store.resolve_archive(name)
            restored = behavior_store.restore_archive(path)
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior archive restored",
                fields={"archive": path.name, "snapshot_ids": list(restored)},
            )
            return {"ok": True, "archive": path.name, "restored": list(restored)}

        if command == "behavior-delete":
            snapshot_id = str(request.get("snapshot_id") or "").strip()
            if not snapshot_id:
                raise ValueError("behavior-delete requires snapshot_id")
            behavior_store.delete(snapshot_id)
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=30,
                channel=LogChannel.GUARD,
                message="Behavior snapshot deleted",
                fields={"snapshot_id": snapshot_id},
            )
            return {"ok": True, "deleted": snapshot_id}

        if command == "behavior-assess-history":
            model = str(request.get("model") or "").strip()
            if not model:
                raise ValueError("behavior-assess-history requires an Ollama model")
            analyst = OllamaBehaviorSnapshotAnalyst(model)
            return {
                "ok": True,
                "assessment": analyst.assess_history(
                    behavior_store.list(),
                    objective=str(
                        request.get("objective")
                        or "Assess overall behavior snapshot history and identify meaningful changes or trends"
                    ),
                ),
            }

        if command == "behavior-assess":
            comparison = request.get("comparison")
            if not isinstance(comparison, dict):
                raise ValueError("behavior-assess requires comparison object")
            model = str(request.get("model") or "").strip()
            if not model:
                raise ValueError("behavior-assess requires an Ollama model")
            analyst = OllamaBehaviorSnapshotAnalyst(model)
            return {
                "ok": True,
                "assessment": analyst.assess(
                    comparison,
                    objective=str(request.get("objective") or "Assess behavior changes"),
                ),
            }

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
                        "record_id": str(item.record_id),
                        "call_id": str(item.call_id) if item.call_id else None,
                        "incident_id": str(item.incident_id) if item.incident_id else None,
                        "fields": dict(item.fields),
                    }
                    for item in records[-limit:]
                ],
            }
        if command == "investigate":
            interrogation_policy = runtime.active_policy.interrogation
            if not interrogation_policy.enabled:
                raise PermissionError("logging.interrogation.enabled=False")
            target = str(request.get("target") or "").strip()
            call_id = str(request.get("call_id") or "").strip()
            incident_id = str(request.get("incident_id") or "").strip()
            minutes = max(1, min(int(request.get("minutes", 15)), 24 * 60))
            objective = str(request.get("objective") or "Investigate the current Caretaker incident")
            now = datetime.now(timezone.utc)
            interrogation = InterrogationRequest(
                period_start=now - timedelta(minutes=minutes),
                period_end=now,
                target_ids=(target,) if target else (),
                call_ids=(UUID(call_id),) if call_id else (),
                incident_ids=(UUID(incident_id),) if incident_id else (),
                objective=objective,
            )
            behavior = ()
            if target and unix_socket_exists(runtime_control_socket):
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
                tuple(recent_log_records(interrogation_policy.maximum_records)),
                behavior_deviations=behavior,
                maximum_representative_records=interrogation_policy.maximum_representative_records,
            )
            model = str(request.get("model") or "").strip()
            if model and not interrogation_policy.llm_enabled:
                raise PermissionError("logging.interrogation.llm_enabled=False")
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
        if command == "authority-status":
            runtime_policy_match, _ = runtime_authority_match()
            return {
                "ok": True,
                **authority.effective.snapshot_dict(),
                "runtime_matches_supervisor": runtime_policy_match,
            }

        if command == "authority-lease-acquire-signed":
            descriptor = str(request.get("descriptor") or "").strip()
            if not descriptor:
                return {
                    "ok": False,
                    "error": "authority-lease-acquire-signed requires a signed lease descriptor",
                }
            lease_directory = (
                Path(runtime.active_policy.directory) / "policy" / "runtime-leases"
            ).resolve()
            descriptor_path = (lease_directory / descriptor).resolve()
            try:
                descriptor_path.relative_to(lease_directory)
            except ValueError:
                return {
                    "ok": False,
                    "error": "Signed runtime-lease descriptors must be below "
                    f"{lease_directory}",
                }
            reason = str(request.get("reason") or "signed temporary incident policy escalation")
            lease = authority.load_signed_runtime_lease_from_stack_file(
                descriptor_path,
                requested_by=f"uid:{credentials[1]}",
                reason=reason,
            )
            try:
                runtime.refresh_authority_policy()
                if unix_socket_exists(runtime_control_socket):
                    response = control_request(
                        runtime_control_socket,
                        {
                            "command": "policy-authority-update",
                            "snapshot": authority.effective.snapshot_dict(),
                        },
                    )
                    if response.get("ok") is False:
                        raise RuntimeError(
                            str(response.get("error", "application rejected authority policy"))
                        )
            except Exception:
                authority.release_runtime_lease(lease.lease_id)
                runtime.refresh_authority_policy()
                raise
            runtime.event(
                logger_name="caretaker.authority",
                severity=30,
                channel=LogChannel.CARETAKER_INTERNAL,
                message="Signed temporary authority policy lease acquired",
                fields={
                    "lease_id": str(lease.lease_id),
                    "requested_by": lease.requested_by,
                    "reason": lease.reason,
                    "expires_at": lease.expires_at.isoformat(),
                    "signature_state": lease.signature_state.value,
                    "source_layer_fingerprint": lease.source_layer_fingerprint,
                    "authority_generation": authority.effective.generation,
                    "authority_fingerprint": authority.effective.fingerprint,
                    "assurance": authority.effective.overall_assurance,
                },
            )
            return {
                "ok": True,
                "lease_id": str(lease.lease_id),
                "expires_at": lease.expires_at.isoformat(),
                "authority_policy": authority.effective.snapshot_dict(),
            }

        if command == "authority-lease-acquire":
            path = str(request.get("path") or "").strip()
            if not path:
                return {"ok": False, "error": "authority-lease-acquire requires path"}
            reason = str(request.get("reason") or "temporary incident policy escalation")
            duration_seconds = max(1, int(request.get("duration_seconds", 3600)))
            target_scope = str(request.get("target")) if request.get("target") else None
            if path.startswith("repair.") and not target_scope:
                return {
                    "ok": False,
                    "error": "Temporary repair.* authority leases require an explicit target id or glob",
                }
            setting = PolicySetting(
                path=path,
                value=request.get("value"),
                target=target_scope,
                override_constraints=bool(request.get("override_constraints", False)),
                reason=reason,
            )
            lease = authority.acquire_runtime_lease(
                settings=(setting,),
                requested_by=f"uid:{credentials[1]}",
                reason=reason,
                duration_seconds=duration_seconds,
            )
            try:
                runtime.refresh_authority_policy()
                if unix_socket_exists(runtime_control_socket):
                    response = control_request(
                        runtime_control_socket,
                        {
                            "command": "policy-authority-update",
                            "snapshot": authority.effective.snapshot_dict(),
                        },
                    )
                    if response.get("ok") is False:
                        raise RuntimeError(str(response.get("error", "application rejected authority policy")))
            except Exception:
                authority.release_runtime_lease(lease.lease_id)
                runtime.refresh_authority_policy()
                raise
            runtime.event(
                logger_name="caretaker.authority",
                severity=30,
                channel=LogChannel.CARETAKER_INTERNAL,
                message="Temporary authority policy lease acquired",
                fields={
                    "lease_id": str(lease.lease_id),
                    "requested_by": lease.requested_by,
                    "reason": lease.reason,
                    "expires_at": lease.expires_at.isoformat(),
                    "path": setting.path,
                    "target": setting.target,
                    "value": setting.value,
                    "override_constraints": setting.override_constraints,
                    "authority_generation": authority.effective.generation,
                    "authority_fingerprint": authority.effective.fingerprint,
                    "assurance": authority.effective.overall_assurance,
                },
            )
            return {
                "ok": True,
                "lease_id": str(lease.lease_id),
                "expires_at": lease.expires_at.isoformat(),
                "authority_policy": authority.effective.snapshot_dict(),
            }

        if command == "authority-lease-release":
            lease_id = UUID(str(request["lease_id"]))
            authority.release_runtime_lease(lease_id)
            runtime.refresh_authority_policy()
            if unix_socket_exists(runtime_control_socket):
                response = control_request(
                    runtime_control_socket,
                    {
                        "command": "policy-authority-update",
                        "snapshot": authority.effective.snapshot_dict(),
                    },
                )
                if response.get("ok") is False:
                    return response
            runtime.event(
                logger_name="caretaker.authority",
                severity=20,
                channel=LogChannel.CARETAKER_INTERNAL,
                message="Temporary authority policy lease released",
                fields={
                    "lease_id": str(lease_id),
                    "authority_generation": authority.effective.generation,
                    "authority_fingerprint": authority.effective.fingerprint,
                },
            )
            return {"ok": True, "released": str(lease_id), "authority_policy": authority.effective.snapshot_dict()}

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
        "CARETAKER_AUTHORITY_POLICY": str(authority.snapshot_path),
    })
    if args.policy:
        env["CARETAKER_LOGGING_POLICY"] = str(Path(args.policy).resolve())
    child = subprocess.Popen(
        [sys.executable, "-m", "caretaker.bootstrap", args.module, *args.module_args],
        env=env,
        start_new_session=True,
    )
    child_holder["child"] = child
    supervisor = CaretakerApplicationSupervisor(
        runtime,
        application_pid=child.pid,
        application_process_group_id=os.getpgid(child.pid),
        application_process=child,
    )
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
    system_policy = authority.effective.apply_dataclass(system_policy, prefix="system")
    system_health = None
    if system_policy.enabled:
        collector = SystemDataCollector(system_policy, application_pid=child.pid)
        collector_thread = threading.Thread(target=collector.run, name="caretaker-system-collector", daemon=True)
        collector_thread.start()
        system_health = supervisor.workers.register(WorkerKind.SYSTEM_COLLECTOR, os.getpid())

    health_stop = threading.Event()
    system_restart_times: list[float] = []
    application_stop_requested = False

    def health_loop() -> None:
        nonlocal application_stop_requested, collector, collector_thread
        while not health_stop.wait(1.0):
            effective_authority = authority.effective
            materialize_behavior_snapshots(maximum=100)
            current_leases = {
                str(lease.lease_id): lease for lease in effective_authority.runtime_leases
            }
            now_utc = datetime.now(timezone.utc)
            for lease_id, previous_lease in tuple(authority_lease_holder.items()):
                if lease_id not in current_leases and previous_lease.expires_at <= now_utc:
                    runtime.event(
                        logger_name="caretaker.authority",
                        severity=20,
                        channel=LogChannel.CARETAKER_INTERNAL,
                        message="Temporary authority policy lease expired",
                        fields={
                            "lease_id": lease_id,
                            "authority_id": previous_lease.authority_id,
                            "requested_by": previous_lease.requested_by,
                            "reason": previous_lease.reason,
                            "expires_at": previous_lease.expires_at.isoformat(),
                        },
                    )
            authority_lease_holder.clear()
            authority_lease_holder.update(current_leases)
            if effective_authority.generation != authority_generation_holder["generation"]:
                runtime.refresh_authority_policy()
                authority_generation_holder["generation"] = effective_authority.generation
                if unix_socket_exists(runtime_control_socket):
                    try:
                        control_request(
                            runtime_control_socket,
                            {
                                "command": "policy-authority-update",
                                "snapshot": effective_authority.snapshot_dict(),
                            },
                        )
                    except OSError:
                        pass
                runtime.event(
                    logger_name="caretaker.authority",
                    severity=20,
                    channel=LogChannel.CARETAKER_INTERNAL,
                    message="Authority policy generation changed",
                    fields={
                        "generation": effective_authority.generation,
                        "fingerprint": effective_authority.fingerprint,
                        "assurance": effective_authority.overall_assurance,
                    },
                )
            runtime_match, _ = runtime_authority_match()
            previous_match = authority_runtime_match_holder["match"]
            if runtime_match is False and unix_socket_exists(runtime_control_socket):
                try:
                    control_request(
                        runtime_control_socket,
                        {
                            "command": "policy-authority-update",
                            "snapshot": effective_authority.snapshot_dict(),
                        },
                    )
                except OSError:
                    pass
            if runtime_match is not None and runtime_match != previous_match:
                authority_runtime_match_holder["match"] = runtime_match
                runtime.event(
                    logger_name="caretaker.authority",
                    severity=50 if not runtime_match else 20,
                    channel=LogChannel.CARETAKER_INTERNAL,
                    message=(
                        "Application authority policy fingerprint does not match supervisor"
                        if not runtime_match
                        else "Application authority policy fingerprint matches supervisor"
                    ),
                    fields={
                        "runtime_matches_supervisor": runtime_match,
                        "authority_generation": effective_authority.generation,
                        "authority_fingerprint": effective_authority.fingerprint,
                    },
                )
            elif runtime_match is None:
                authority_runtime_match_holder["match"] = None

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
                    elif (
                        restart_policy.exhaustion_action is WorkerFailureAction.STOP_APPLICATION
                        and not application_stop_requested
                    ):
                        application_stop_requested = True
                        shutdown = supervisor.stop_application()
                        runtime.event(
                            logger_name="caretaker.watchdog",
                            severity=50,
                            channel=LogChannel.EMERGENCY,
                            message="System collector restart policy exhausted; stopping application boundary",
                            fields={
                                "worker_id": str(system_health.worker_id),
                                "shutdown_reason": "system_collector_restart_exhausted",
                                "shutdown": shutdown,
                            },
                        )

    health_thread = threading.Thread(target=health_loop, name="caretaker-health-monitor", daemon=True)
    health_thread.start()
    try:
        return child.wait()
    finally:
        health_stop.set()
        health_thread.join(timeout=3)
        materialize_behavior_snapshots(maximum=10_000)
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
