from __future__ import annotations

import argparse
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m caretaker.run")
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
    parser.add_argument("module")
    parser.add_argument("module_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.policy:
        declared_policy, _ = load_operator_policy(args.policy)
    else:
        directory = args.data_directory or f"./caretaker-data/{args.module}"
        declared_policy = OperatorLoggingPolicy.application_defaults(
            directory=directory, application_id=args.module
        )

    authority = (
        PolicyAuthoritySupervisor.from_stack_file(args.authority_stack)
        if args.authority_stack
        else PolicyAuthoritySupervisor()
    )
    policy_transform = lambda value: authority.effective.apply_dataclass(
        value, prefix="logging"
    )
    policy = policy_transform(declared_policy)
    authority.set_snapshot_path(
        Path(policy.directory) / "policy" / "authority-effective.json"
    )
    external_signer = _load_external_signer(args.external_signer)
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
        for envelope in envelopes:
            snapshot = envelope["snapshot"]
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior snapshot automatically materialized",
                fields={
                    "snapshot_id": snapshot["snapshot_id"],
                    "subject_key": snapshot["subject_key"],
                    "generation_id": snapshot.get("generation_id"),
                    "seal_reason": snapshot.get("seal_reason"),
                    "content_sha256": envelope["integrity"]["content_sha256"],
                    "signature_state": envelope["integrity"]["signature_state"],
                },
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
        if command == "behavior-list":
            # Generation summaries are compact. Use the full bounded allowance so
            # the console can retain three generations across many subjects.
            limit = max(1, min(int(request.get("limit", 500)), 500))
            return {
                "ok": True,
                "collection_id": behavior_collection_id,
                "revision": behavior_revision["value"],
                "snapshots": list(behavior_store.list_summaries(limit=limit)),
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
            envelope = behavior_store.create(
                response["capture"],
                authority_fingerprint=authority.effective.fingerprint,
                deployment_fingerprint=deployment_fingerprint(),
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
                    "content_sha256": envelope["integrity"]["content_sha256"],
                    "signature_state": envelope["integrity"]["signature_state"],
                },
            )
            return {"ok": True, "envelope": envelope}

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
            snapshot_ids = request.get("snapshot_ids") or ()
            if isinstance(snapshot_ids, str):
                snapshot_ids = [snapshot_ids]
            path = behavior_store.archive(snapshot_ids, remove=True)
            behavior_revision["value"] += 1
            runtime.event(
                logger_name="caretaker.behavior",
                severity=20,
                channel=LogChannel.GUARD,
                message="Behavior snapshots archived",
                fields={"snapshot_ids": list(snapshot_ids), "archive_path": str(path)},
            )
            return {"ok": True, "archive": str(path)}

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
    system_policy = authority.effective.apply_dataclass(system_policy, prefix="system")
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
