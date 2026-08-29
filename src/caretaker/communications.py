"""Policy-governed, reviewable Incident communication drafts.

Drafts are projections of verified Incident Capsule state.  They contain only
bounded data, preserve source provenance, and are never delivery authority.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import NAMESPACE_URL, UUID, uuid5

from .capsule import (
    IncidentCapsulePolicy,
    IncidentCapsuleStore,
    bounded_safe_data,
    content_hash,
)


COMMUNICATION_SCHEMA_VERSION = 1
DEFAULT_COMMUNICATION_SECTIONS = (
    "identity",
    "confirmed_observations",
    "supported_inferences",
    "hypotheses",
    "unknowns",
    "impact",
    "scope",
    "mitigation",
    "next_update",
    "ownership",
    "contact",
    "interventions",
    "validation",
    "governance",
    "provenance",
)
COMMUNICATION_SECTIONS = frozenset({
    *DEFAULT_COMMUNICATION_SECTIONS,
})
_REQUIRED_STATUS_FIELDS = ("impact", "scope", "mitigation", "next_update", "ownership", "contact")
_OBSERVATION_FIELDS = (
    "occurred_at",
    "trigger",
    "target",
    "failure",
    "fingerprint",
    "capture_reason",
)


@dataclass(frozen=True, slots=True)
class CommunicationAudiencePolicy:
    """Disclosure and rendering limits for one named audience."""

    profile_id: str
    display_name: str
    allowed_sections: tuple[str, ...]
    maximum_text_characters: int = 4_000
    maximum_items: int = 32
    require_review: bool = True


@dataclass(frozen=True, slots=True)
class IncidentCommunicationPolicy:
    """Policy for local draft generation and reviewable export."""

    enabled: bool = True
    maximum_draft_bytes: int = 128 * 1024
    audiences: tuple[CommunicationAudiencePolicy, ...] = field(
        default_factory=lambda: (
            CommunicationAudiencePolicy(
                profile_id="operators-v1",
                display_name="On-call operators",
                allowed_sections=DEFAULT_COMMUNICATION_SECTIONS,
            ),
            CommunicationAudiencePolicy(
                profile_id="engineers-v1",
                display_name="Application engineers",
                allowed_sections=tuple(
                    section for section in DEFAULT_COMMUNICATION_SECTIONS if section != "contact"
                ),
            ),
            CommunicationAudiencePolicy(
                profile_id="leadership-v1",
                display_name="Leadership and support",
                allowed_sections=(
                    "identity",
                    "confirmed_observations",
                    "unknowns",
                    "impact",
                    "scope",
                    "mitigation",
                    "next_update",
                    "ownership",
                    "contact",
                    "provenance",
                ),
            ),
            CommunicationAudiencePolicy(
                profile_id="security-v1",
                display_name="Security and assurance",
                allowed_sections=DEFAULT_COMMUNICATION_SECTIONS,
            ),
        )
    )


class CommunicationPolicyError(ValueError):
    """Raised when a draft cannot be produced under communication policy."""


def validate_incident_communication_policy(policy: IncidentCommunicationPolicy) -> None:
    errors: list[str] = []
    if policy.maximum_draft_bytes <= 0:
        errors.append("maximum_draft_bytes must be greater than zero")
    if not policy.audiences:
        errors.append("at least one communication audience is required")
    profile_ids: set[str] = set()
    for index, audience in enumerate(policy.audiences):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", audience.profile_id):
            errors.append(f"audiences[{index}].profile_id is invalid")
        if audience.profile_id in profile_ids:
            errors.append(f"audiences[{index}].profile_id is duplicated")
        profile_ids.add(audience.profile_id)
        if not audience.display_name.strip():
            errors.append(f"audiences[{index}].display_name must not be empty")
        if audience.maximum_text_characters <= 0:
            errors.append(f"audiences[{index}].maximum_text_characters must be greater than zero")
        if audience.maximum_items <= 0:
            errors.append(f"audiences[{index}].maximum_items must be greater than zero")
        unknown = set(audience.allowed_sections) - COMMUNICATION_SECTIONS
        if unknown:
            errors.append(
                f"audiences[{index}].allowed_sections contains unsupported sections: "
                + ", ".join(sorted(unknown))
            )
    if errors:
        raise CommunicationPolicyError("Invalid Incident communication policy: " + "; ".join(errors))


def communication_policy_fingerprint(policy: IncidentCommunicationPolicy) -> str:
    return content_hash(dataclasses.asdict(policy))


def audience_policy(
    policy: IncidentCommunicationPolicy,
    profile_id: str,
) -> CommunicationAudiencePolicy:
    validate_incident_communication_policy(policy)
    for audience in policy.audiences:
        if audience.profile_id == profile_id:
            return audience
    raise CommunicationPolicyError(f"communication audience {profile_id!r} is not permitted by policy")


def build_communication_draft(
    envelope: Mapping[str, Any],
    *,
    audience_profile_id: str,
    policy: IncidentCommunicationPolicy,
    effective_policy_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic, bounded draft from a verified capsule envelope."""

    if not policy.enabled:
        raise CommunicationPolicyError("Incident communication drafting is disabled by policy")
    audience = audience_policy(policy, audience_profile_id)
    capsule = envelope.get("capsule")
    integrity = envelope.get("integrity")
    if not isinstance(capsule, Mapping) or not isinstance(integrity, Mapping):
        raise CommunicationPolicyError("verified Incident Capsule envelope is required")
    capsule_id = str(capsule.get("capsule_id") or "")
    incident_id = str(capsule.get("incident_id") or "")
    source_hash = str(integrity.get("content_sha256") or "")
    if not capsule_id or not incident_id or not source_hash:
        raise CommunicationPolicyError("Incident Capsule identity and content hash are required")
    if content_hash(capsule) != source_hash:
        raise CommunicationPolicyError("Incident Capsule content hash is invalid")
    state = capsule.get("incident_state")
    state = state if isinstance(state, Mapping) else {}
    capture_policy = IncidentCapsulePolicy(
        maximum_text_characters=audience.maximum_text_characters,
        maximum_collection_items=audience.maximum_items,
        maximum_depth=6,
    )

    identity = {
        key: capsule[key]
        for key in ("capsule_id", "incident_id", "run_id", "revision", "created_at")
        if key in capsule
    }
    sections: dict[str, Any] = {}
    provenance: list[dict[str, Any]] = []

    def add_section(name: str, value: Any, *, source_fields: tuple[str, ...] = ()) -> None:
        if name not in audience.allowed_sections:
            return
        sections[name] = bounded_safe_data(value, policy=capture_policy, name=name)
        provenance.append({
            "section": name,
            "source": "incident_capsule.incident_state" if source_fields else "incident_capsule",
            "source_fields": list(source_fields),
            "capsule_id": capsule_id,
            "capsule_revision": capsule.get("revision"),
            "capsule_content_sha256": source_hash,
        })

    add_section("identity", identity)

    observations = {
        field: state[field]
        for field in _OBSERVATION_FIELDS
        if field in state
    }
    add_section(
        "confirmed_observations",
        observations,
        source_fields=tuple(observations),
    )
    for field in _REQUIRED_STATUS_FIELDS:
        value = state.get(field)
        if value is None:
            value = {"status": "UNKNOWN", "reason": "not recorded in the Incident Capsule"}
            source_fields: tuple[str, ...] = ()
        else:
            value = {"status": "RECORDED", "value": value}
            source_fields = (field,)
        add_section(field, value, source_fields=source_fields)

    for output_name, state_names in (
        ("supported_inferences", ("supported_inferences", "inferences")),
        ("hypotheses", ("hypotheses", "primary_hypothesis", "alternative_hypotheses")),
        ("interventions", ("interventions", "repair_attempts", "repairs")),
        ("validation", ("validation", "validation_results")),
    ):
        present = next((name for name in state_names if name in state), None)
        add_section(
            output_name,
            state.get(present, []) if present else [],
            source_fields=(present,) if present else (),
        )

    explicit_unknowns = state.get("unknowns", [])
    unknowns = list(explicit_unknowns) if isinstance(explicit_unknowns, (list, tuple)) else [explicit_unknowns]
    unknowns.extend(
        f"{field} is not recorded in the Incident Capsule"
        for field in _REQUIRED_STATUS_FIELDS
        if field not in state
    )
    add_section("unknowns", unknowns, source_fields=("unknowns",) if "unknowns" in state else ())

    governance = {
        key: capsule[key]
        for key in (
            "policy_fingerprint",
            "authority_policy_generation",
            "authority_policy_fingerprint",
        )
        if key in capsule
    }
    add_section("governance", governance)
    if "provenance" in audience.allowed_sections:
        sections["provenance"] = provenance

    draft_basis = {
        "capsule_id": capsule_id,
        "incident_id": incident_id,
        "incident_state": state,
        "audience_profile_id": audience.profile_id,
        "communication_policy_fingerprint": communication_policy_fingerprint(policy),
    }
    draft_id = uuid5(NAMESPACE_URL, "caretaker-incident-communication:" + content_hash(draft_basis))
    evidence_cutoff = str(capsule.get("created_at") or "")
    body = _render_body(sections, audience=audience, incident_id=incident_id)
    draft = {
        "schema_version": COMMUNICATION_SCHEMA_VERSION,
        "draft_id": str(draft_id),
        "communication_id": str(draft_id),
        "created_at": evidence_cutoff,
        "audience_profile_id": audience.profile_id,
        "audience_display_name": audience.display_name,
        "status": "DRAFT",
        "review_required": audience.require_review,
        "delivery_authorized": False,
        "delivery_status": "NOT_AUTHORIZED",
        "evidence_cutoff": evidence_cutoff,
        "source_capsule_id": capsule_id,
        "source_incident_id": incident_id,
        "source_capsule_revision": capsule.get("revision"),
        "source_capsule_content_sha256": source_hash,
        "source_incident_policy_fingerprint": capsule.get("policy_fingerprint"),
        "effective_policy_fingerprint": effective_policy_fingerprint,
        "communication_policy_fingerprint": communication_policy_fingerprint(policy),
        "redaction_status": "BOUNDED_REDACTION_APPLIED",
        "truncation_status": "BOUNDED_BY_AUDIENCE_POLICY",
        "sections": sections,
        "body": body,
    }
    digest = content_hash(draft)
    result = {"draft": draft, "integrity": {"content_sha256": digest}}
    if len(json.dumps(result, sort_keys=True, ensure_ascii=False).encode("utf-8")) > policy.maximum_draft_bytes:
        raise CommunicationPolicyError("communication draft exceeds maximum_draft_bytes")
    return result


def _render_body(
    sections: Mapping[str, Any],
    *,
    audience: CommunicationAudiencePolicy,
    incident_id: str,
) -> str:
    lines = [f"Incident {incident_id}", f"Audience: {audience.display_name}", "Status: DRAFT — review required"]
    labels = {
        "confirmed_observations": "Confirmed observations",
        "supported_inferences": "Supported inferences",
        "hypotheses": "Hypotheses",
        "impact": "Impact",
        "scope": "Scope",
        "mitigation": "Mitigation",
        "next_update": "Next update",
        "ownership": "Ownership",
        "contact": "Contact",
        "interventions": "Interventions",
        "validation": "Validation",
        "unknowns": "Unknowns",
    }
    for section, label in labels.items():
        if section not in sections:
            continue
        value = json.dumps(sections[section], sort_keys=True, ensure_ascii=False, default=str)
        lines.extend((f"{label}:", f"- {value}"))
    lines.append("Delivery: not authorized; this is a reviewable draft only.")
    return "\n".join(lines)


def communication_record_metadata(draft_envelope: Mapping[str, Any]) -> dict[str, Any]:
    draft = draft_envelope.get("draft") or {}
    return {
        "draft_id": draft.get("draft_id"),
        "draft_schema_version": draft.get("schema_version"),
        "source_capsule_id": draft.get("source_capsule_id"),
        "source_capsule_revision": draft.get("source_capsule_revision"),
        "source_capsule_content_sha256": draft.get("source_capsule_content_sha256"),
        "draft_content_sha256": (draft_envelope.get("integrity") or {}).get("content_sha256"),
        "communication_policy_fingerprint": draft.get("communication_policy_fingerprint"),
        "delivery_authorized": False,
    }


def generate_communication_draft(
    store: IncidentCapsuleStore,
    envelope: Mapping[str, Any],
    *,
    audience_profile_id: str,
    policy: IncidentCommunicationPolicy,
    capsule_policy: IncidentCapsulePolicy,
    effective_policy_fingerprint: str | None = None,
    record: bool = True,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    """Create a draft and optionally append only its audit metadata to a capsule."""

    draft_envelope = build_communication_draft(
        envelope,
        audience_profile_id=audience_profile_id,
        policy=policy,
        effective_policy_fingerprint=effective_policy_fingerprint,
    )
    draft = draft_envelope["draft"]
    capsule = envelope["capsule"]
    recording: dict[str, Any] = {
        "requested": record,
        "status": "NOT_REQUESTED" if not record else "PENDING",
        "capsule_mutated": False,
    }
    if record:
        existing = next(
            (
                item
                for item in capsule.get("communications", ())
                if isinstance(item, Mapping)
                and str((item.get("metadata") or {}).get("draft_id") or "") == str(draft["draft_id"])
            ),
            None,
        )
        if existing is not None:
            recording.update({
                "status": "ALREADY_RECORDED",
                "communication_id": existing.get("communication_id"),
                "capsule_revision": capsule.get("revision"),
            })
        else:
            try:
                updated = store.record_communication(
                    str(capsule["incident_id"]),
                    direction="outbound",
                    channel="reviewable-draft",
                    audience_profile_id=audience_profile_id,
                    status="drafted",
                    content_sha256=(draft_envelope["integrity"] or {}).get("content_sha256"),
                    source="caretaker-communication-drafter",
                    metadata=communication_record_metadata(draft_envelope),
                    policy=capsule_policy,
                    run_id=run_id,
                )
                recording.update({
                    "status": "RECORDED",
                    "capsule_mutated": True,
                    "capsule_revision": (updated.get("capsule") or {}).get("revision"),
                    "communication_id": next(
                        (
                            item.get("communication_id")
                            for item in (updated.get("capsule") or {}).get("communications", ())
                            if isinstance(item, Mapping)
                            and str((item.get("metadata") or {}).get("draft_id") or "") == str(draft["draft_id"])
                        ),
                        None,
                    ),
                })
            except Exception as exc:
                recording.update({
                    "status": "UNRECORDED",
                    "error": f"{type(exc).__name__}: {exc}",
                })
    return {**draft_envelope, "recording": recording}
