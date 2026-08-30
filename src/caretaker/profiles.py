from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .authority import (
    AuthorityKind,
    AuthorityPolicyError,
    ConstraintOperator,
    PolicyAuthorityLayer,
    PolicyConstraint,
    PolicySetting,
    load_policy_authority_layer,
    write_policy_authority_layer,
)


PROFILE_METADATA_PREFIX = "caretaker.profile."
PROFILE_LINEAGE = PROFILE_METADATA_PREFIX + "lineage"
PROFILE_NAME = PROFILE_METADATA_PREFIX + "name"
PROFILE_VERSION = PROFILE_METADATA_PREFIX + "version"
PROFILE_DESCRIPTION = PROFILE_METADATA_PREFIX + "description"
PROFILE_SURFACE_VERSION = PROFILE_METADATA_PREFIX + "policy_surface_version"
PROFILE_MINIMUM_CARETAKER = PROFILE_METADATA_PREFIX + "caretaker_minimum"
PROFILE_TESTED_THROUGH = PROFILE_METADATA_PREFIX + "caretaker_tested_through"
PROFILE_SUPERSEDES_VERSION = PROFILE_METADATA_PREFIX + "supersedes_version"
PROFILE_SUPERSEDES_FINGERPRINT = PROFILE_METADATA_PREFIX + "supersedes_fingerprint"
PROFILE_BASED_ON_LINEAGE = PROFILE_METADATA_PREFIX + "based_on_lineage"
PROFILE_BASED_ON_VERSION = PROFILE_METADATA_PREFIX + "based_on_version"
PROFILE_BASED_ON_FINGERPRINT = PROFILE_METADATA_PREFIX + "based_on_fingerprint"
PROFILE_SIGNER_ROLE = PROFILE_METADATA_PREFIX + "signer_role"
PROFILE_REQUIRE_COMPLETE_SURFACE = PROFILE_METADATA_PREFIX + "require_complete_surface"
PROFILE_REQUIRE_CURRENT_VERSION = PROFILE_METADATA_PREFIX + "require_current_caretaker_version"
PROFILE_ORIGIN = PROFILE_METADATA_PREFIX + "origin"

OFFICIAL_PROFILE_SIGNING_ROLE = "profile-signing"


@dataclass(frozen=True, slots=True)
class PolicyCapability:
    capability_id: str
    surface_version: int
    introduced_in: str
    title: str
    description: str
    review_note: str
    paths: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "surface_version": self.surface_version,
            "introduced_in": self.introduced_in,
            "title": self.title,
            "description": self.description,
            "review_note": self.review_note,
            "paths": list(self.paths),
        }


# Policy-surface generations are deliberately independent from the authority
# manifest schema and from Caretaker package versions. When a new
# policy-controlled capability is introduced, add a PolicyCapability and bump
# CURRENT_POLICY_SURFACE_VERSION. Profiles created against an older surface can
# then be identified without pretending that an available update is itself a
# security failure.
POLICY_CAPABILITIES: tuple[PolicyCapability, ...] = (
    PolicyCapability(
        "authority.runtime-leases",
        1,
        "0.6.0",
        "Runtime policy authority",
        "Controls temporary authority leases and whether higher-assurance deployments require signed leases.",
        "Review who may change effective policy during an incident and whether unsigned runtime authority is acceptable.",
        ("authority.runtime.",),
    ),
    PolicyCapability(
        "repair.lifecycle",
        1,
        "0.2.0a1",
        "Repair lifecycle and authority",
        "Controls whether Repair runs, what authority it has, validation, retry, observation, rollback, and candidate restrictions.",
        "Review changes for repair autonomy, validation strength, replay safety, and activation boundaries.",
        ("repair.",),
    ),
    PolicyCapability(
        "guard.behavior",
        1,
        "0.4.0a1",
        "Guard behavior analysis",
        "Controls Guard collection, behavior comparison, target inspection, baselines, deviations, and actions.",
        "Review changes for new observation scope, enforcement behavior, and evidence requirements.",
        ("guard.", "repair.guard."),
    ),
    PolicyCapability(
        "logging.evidence",
        1,
        "0.5.0a1",
        "Logging and retained evidence",
        "Controls application evidence capture, buffering, retention, attachments, signing, redaction, indexing, and failure behavior.",
        "Review changes for evidence loss, privacy exposure, retention, and tamper-evidence guarantees.",
        ("logging.",),
    ),
    PolicyCapability(
        "system.evidence",
        1,
        "0.5.0a1",
        "System evidence collection",
        "Controls host/process collection used to correlate Caretaker activity with operating-system state.",
        "Review changes for collection scope, privacy, storage volume, and failure behavior.",
        ("system.",),
    ),
    PolicyCapability(
        "adaptive.instrumentation",
        2,
        "0.6.0",
        "Adaptive lightweight instrumentation",
        "Controls lightweight dependency/function observation, promotion, evidence-gated repair escalation, sampling, and demotion.",
        "Review changes for hot-path overhead, observation scope, repair eligibility, evidence sufficiency, and demotion behavior.",
        ("lightweight.",),
    ),
    PolicyCapability(
        "guard.behavior-snapshots",
        2,
        "0.6.0",
        "Persistent behavior statistics and snapshots",
        "Controls bounded behavior statistics, automatic materialization, restart reconstruction, and accepted-baseline snapshot handling.",
        "Review sampling/statistics cost, generation compatibility, automatic materialization, and baseline persistence semantics.",
        ("guard.snapshots.",),
    ),
    PolicyCapability(
        "guard.randomized-behavior-regimes",
        3,
        "0.6.1",
        "Randomized behavior snapshot boundaries",
        "Controls opt-in randomized, bounded behavior epochs that preserve disjoint sample ranges and provenance.",
        "Review reproducibility, minimum useful epoch size, snapshot rate, and the fact that randomized snapshots remain evidence rather than an automatic baseline.",
        ("guard.snapshots.randomized_epoch_",),
    ),
    PolicyCapability(
        "guard.return-behavior-categories",
        5,
        "0.6.1",
        "Bounded return behavior categories and shapes",
        "Controls bounded, type-only categories and non-value structural buckets observed from successful Behavior-stage returns.",
        "Review category/shape cardinality, type-name disclosure, generation provenance, safe container handling, and overflow handling.",
        ("guard.snapshots.maximum_return_categories", "guard.snapshots.maximum_return_shapes"),
    ),
    PolicyCapability(
        "guard.behavior-collection-scheduler",
        5,
        "0.6.1",
        "Policy-governed operator behavior collection scheduling",
        "Controls bounded durable operator-directed behavior capture requests and opt-in automatic backlog promotion.",
        "Review queue backpressure, priority/deadline handling, restart recovery, cancellation, automatic-promotion limits, and evidence-only provenance.",
        ("guard.snapshots.collection_",),
    ),
    PolicyCapability(
        "repair.validation-isolation",
        2,
        "0.6.0",
        "Validation isolation requirements",
        "Controls the minimum isolation capability required before a repair candidate may pass validation and the fail-closed action when that backend is unavailable.",
        "Review whether automatic repair can run with PROCESS, CONTAINER, VM, or EXTERNAL isolation and how unavailable stronger isolation is handled.",
        (
            "repair.validation.minimum_isolation",
            "repair.validation.backend_unavailable_action",
        ),
    ),
    PolicyCapability(
        "logging.signing-identity-journal",
        2,
        "0.6.0",
        "Runtime signing identity retention",
        "Controls the independent signing-identity journal used to retain public identities and ephemeral key transitions required to verify signed runtime artifacts.",
        "Review identity retention against the longest retained signed artifact and the configured runtime signing assurance mode.",
        ("logging.signing.identity_journal_",),
    ),
)

CURRENT_POLICY_SURFACE_VERSION = max(
    (item.surface_version for item in POLICY_CAPABILITIES), default=1
)


@dataclass(frozen=True, slots=True)
class ProfileIdentity:
    lineage: str
    name: str
    version: int
    policy_surface_version: int
    caretaker_minimum: str | None = None
    caretaker_tested_through: str | None = None
    description: str | None = None
    supersedes_version: int | None = None
    supersedes_fingerprint: str | None = None
    based_on_lineage: str | None = None
    based_on_version: int | None = None
    based_on_fingerprint: str | None = None
    signer_role: str | None = None
    require_complete_surface: bool = False
    require_current_caretaker_version: bool = False
    origin: str | None = None

    @property
    def display_name(self) -> str:
        return f"{self.name} v{self.version} ({self.lineage})"

    def as_dict(self) -> dict[str, Any]:
        return {
            "lineage": self.lineage,
            "name": self.name,
            "version": self.version,
            "policy_surface_version": self.policy_surface_version,
            "caretaker_minimum": self.caretaker_minimum,
            "caretaker_tested_through": self.caretaker_tested_through,
            "description": self.description,
            "supersedes_version": self.supersedes_version,
            "supersedes_fingerprint": self.supersedes_fingerprint,
            "based_on_lineage": self.based_on_lineage,
            "based_on_version": self.based_on_version,
            "based_on_fingerprint": self.based_on_fingerprint,
            "signer_role": self.signer_role,
            "require_complete_surface": self.require_complete_surface,
            "require_current_caretaker_version": self.require_current_caretaker_version,
            "origin": self.origin,
        }


@dataclass(frozen=True, slots=True)
class ProfileCoverageReport:
    profile_surface_version: int
    current_surface_version: int
    missing_capabilities: tuple[PolicyCapability, ...] = ()
    future_surface: bool = False

    @property
    def complete(self) -> bool:
        return not self.future_surface and not self.missing_capabilities

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_surface_version": self.profile_surface_version,
            "current_surface_version": self.current_surface_version,
            "complete": self.complete,
            "future_surface": self.future_surface,
            "missing_capabilities": [item.as_dict() for item in self.missing_capabilities],
        }


@dataclass(frozen=True, slots=True)
class ProfileDifference:
    change: str
    path: str
    target: str | None
    old: Any
    new: Any
    meaning: str
    consequence: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "change": self.change,
            "path": self.path,
            "target": self.target,
            "old": self.old,
            "new": self.new,
            "meaning": self.meaning,
            "consequence": self.consequence,
        }


@dataclass(frozen=True, slots=True)
class ProfileComparison:
    left_fingerprint: str
    right_fingerprint: str
    left_authority_id: str
    right_authority_id: str
    left_kind: str
    right_kind: str
    left_generation: int
    right_generation: int
    left_identity: ProfileIdentity | None
    right_identity: ProfileIdentity | None
    same_lineage: bool | None
    lineage_continuation: bool | None
    changes: tuple[ProfileDifference, ...] = ()
    right_coverage: ProfileCoverageReport | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "left_fingerprint": self.left_fingerprint,
            "right_fingerprint": self.right_fingerprint,
            "left_authority_id": self.left_authority_id,
            "right_authority_id": self.right_authority_id,
            "left_kind": self.left_kind,
            "right_kind": self.right_kind,
            "left_generation": self.left_generation,
            "right_generation": self.right_generation,
            "left_identity": self.left_identity.as_dict() if self.left_identity else None,
            "right_identity": self.right_identity.as_dict() if self.right_identity else None,
            "same_lineage": self.same_lineage,
            "lineage_continuation": self.lineage_continuation,
            "changes": [item.as_dict() for item in self.changes],
            "right_coverage": self.right_coverage.as_dict() if self.right_coverage else None,
        }


def _metadata_text(metadata: Mapping[str, str], key: str) -> str | None:
    value = str(metadata.get(key, "")).strip()
    return value or None


def _metadata_int(metadata: Mapping[str, str], key: str) -> int | None:
    value = _metadata_text(metadata, key)
    if value is None:
        return None
    try:
        result = int(value)
    except ValueError as exc:
        raise AuthorityPolicyError(f"Profile metadata {key!r} must be an integer") from exc
    return result


def _metadata_bool(metadata: Mapping[str, str], key: str, default: bool = False) -> bool:
    value = _metadata_text(metadata, key)
    if value is None:
        return default
    normalized = value.casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise AuthorityPolicyError(f"Profile metadata {key!r} must be true or false")


def profile_identity(
    layer: PolicyAuthorityLayer,
    *,
    required: bool = False,
) -> ProfileIdentity | None:
    metadata = layer.metadata
    lineage = _metadata_text(metadata, PROFILE_LINEAGE)
    if lineage is None:
        if required:
            raise AuthorityPolicyError(
                f"Authority layer {layer.authority_id!r} is not a named Caretaker profile"
            )
        return None
    if layer.kind is not AuthorityKind.FRAMEWORK:
        raise AuthorityPolicyError("Named profiles must be framework authority layers")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", lineage):
        raise AuthorityPolicyError(
            "Profile lineage must be a stable lowercase identifier containing only letters, "
            "numbers, '.', '_' or '-'"
        )
    name = _metadata_text(metadata, PROFILE_NAME) or lineage
    version = _metadata_int(metadata, PROFILE_VERSION)
    if version is None or version < 1:
        raise AuthorityPolicyError("Profile version must be a positive integer")
    surface = _metadata_int(metadata, PROFILE_SURFACE_VERSION)
    if surface is None or surface < 1:
        raise AuthorityPolicyError("Profile policy-surface version must be a positive integer")
    supersedes_version = _metadata_int(metadata, PROFILE_SUPERSEDES_VERSION)
    supersedes_fingerprint = _metadata_text(metadata, PROFILE_SUPERSEDES_FINGERPRINT)
    based_on_lineage = _metadata_text(metadata, PROFILE_BASED_ON_LINEAGE)
    based_on_version = _metadata_int(metadata, PROFILE_BASED_ON_VERSION)
    based_on_fingerprint = _metadata_text(metadata, PROFILE_BASED_ON_FINGERPRINT)
    if (supersedes_version is None) != (supersedes_fingerprint is None):
        raise AuthorityPolicyError(
            "Profile continuation metadata must include both supersedes version and fingerprint"
        )
    based_on_values = (based_on_lineage, based_on_version, based_on_fingerprint)
    if any(value is not None for value in based_on_values) and not all(
        value is not None for value in based_on_values
    ):
        raise AuthorityPolicyError(
            "Profile based-on metadata must include lineage, version, and fingerprint together"
        )
    if supersedes_version is not None and based_on_lineage is not None:
        raise AuthorityPolicyError(
            "A profile revision cannot both continue a lineage and declare itself based on another profile"
        )
    return ProfileIdentity(
        lineage=lineage,
        name=name,
        version=version,
        policy_surface_version=surface,
        caretaker_minimum=_metadata_text(metadata, PROFILE_MINIMUM_CARETAKER),
        caretaker_tested_through=_metadata_text(metadata, PROFILE_TESTED_THROUGH),
        description=_metadata_text(metadata, PROFILE_DESCRIPTION),
        supersedes_version=supersedes_version,
        supersedes_fingerprint=supersedes_fingerprint,
        based_on_lineage=based_on_lineage,
        based_on_version=based_on_version,
        based_on_fingerprint=based_on_fingerprint,
        signer_role=_metadata_text(metadata, PROFILE_SIGNER_ROLE),
        require_complete_surface=_metadata_bool(metadata, PROFILE_REQUIRE_COMPLETE_SURFACE),
        require_current_caretaker_version=_metadata_bool(metadata, PROFILE_REQUIRE_CURRENT_VERSION),
        origin=_metadata_text(metadata, PROFILE_ORIGIN),
    )


def profile_coverage(layer: PolicyAuthorityLayer) -> ProfileCoverageReport:
    identity = profile_identity(layer, required=True)
    assert identity is not None
    surface = identity.policy_surface_version
    missing = tuple(
        item for item in POLICY_CAPABILITIES if item.surface_version > surface
    )
    return ProfileCoverageReport(
        profile_surface_version=surface,
        current_surface_version=CURRENT_POLICY_SURFACE_VERSION,
        missing_capabilities=missing,
        future_surface=surface > CURRENT_POLICY_SURFACE_VERSION,
    )


def validate_runtime_profile(
    layer: PolicyAuthorityLayer,
    *,
    source_role: str | None = None,
) -> ProfileCoverageReport:
    """Validate profile metadata that has runtime security consequences.

    Signature validation remains owned by ``caretaker.authority``. This function
    checks the signed profile's declared lineage, signer-role expectation and
    policy-surface coverage. It never treats profile provenance as a selection
    pin; exact selection remains bound by lower-layer parent fingerprints.
    """

    identity = profile_identity(layer, required=True)
    assert identity is not None
    if identity.signer_role and source_role != identity.signer_role:
        raise AuthorityPolicyError(
            f"Profile {identity.display_name} requires signer role "
            f"{identity.signer_role!r}, but the authority stack selected {source_role!r}"
        )
    report = profile_coverage(layer)
    if report.future_surface:
        raise AuthorityPolicyError(
            f"Profile {identity.display_name} was created for policy surface "
            f"{identity.policy_surface_version}, newer than this Caretaker build's "
            f"surface {CURRENT_POLICY_SURFACE_VERSION}"
        )
    if identity.require_complete_surface and not report.complete:
        missing = ", ".join(item.capability_id for item in report.missing_capabilities)
        raise AuthorityPolicyError(
            f"Pinned profile {identity.display_name} requires complete policy-surface coverage, "
            f"but this Caretaker build adds policy-controlled capabilities not reviewed by the "
            f"profile: {missing}. Continue the profile lineage before starting Caretaker."
        )
    if identity.require_current_caretaker_version:
        try:
            from . import __version__ as current_caretaker_version
        except (ImportError, AttributeError):
            current_caretaker_version = None
        if not identity.caretaker_tested_through:
            raise AuthorityPolicyError(
                f"Profile {identity.display_name} requires explicit Caretaker-version review, "
                "but caretaker.profile.caretaker_tested_through is not set"
            )
        if current_caretaker_version and identity.caretaker_tested_through != current_caretaker_version:
            raise AuthorityPolicyError(
                f"Profile {identity.display_name} was explicitly reviewed through Caretaker "
                f"{identity.caretaker_tested_through}, but the running version is "
                f"{current_caretaker_version}. Continue/review the profile lineage for this "
                "Caretaker version before starting high-assurance operation."
            )
    return report


def load_profile(path: str | Path) -> PolicyAuthorityLayer:
    layer = load_policy_authority_layer(path, require_canonical=True)
    profile_identity(layer, required=True)
    return layer


def profile_summary(layer: PolicyAuthorityLayer) -> dict[str, Any]:
    identity = profile_identity(layer)
    coverage = profile_coverage(layer) if identity else None
    return {
        "authority_id": layer.authority_id,
        "kind": layer.kind.value,
        "generation": layer.generation,
        "fingerprint": layer.fingerprint,
        "created_at": layer.created_at,
        "expires_at": layer.expires_at,
        "profile": identity.as_dict() if identity else None,
        "coverage": coverage.as_dict() if coverage else None,
        "parents": dict(layer.parents),
        "settings": [
            {
                "path": item.path,
                "target": item.target,
                "value": item.value,
                "override_constraints": item.override_constraints,
                "reason": item.reason,
            }
            for item in layer.settings
        ],
        "constraints": [
            {
                "path": item.path,
                "target": item.target,
                "operator": item.operator.value,
                "value": item.value,
            }
            for item in layer.constraints
        ],
    }


def _setting_map(layer: PolicyAuthorityLayer) -> dict[tuple[str, str | None], PolicySetting]:
    return {(item.path, item.target): item for item in layer.settings}


def _constraint_map(
    layer: PolicyAuthorityLayer,
) -> dict[tuple[str, str | None, str], PolicyConstraint]:
    return {
        (item.path, item.target, item.operator.value): item for item in layer.constraints
    }


def _capability_for_path(path: str) -> PolicyCapability | None:
    matches = [
        item
        for item in POLICY_CAPABILITIES
        if any(path.startswith(prefix) for prefix in item.paths)
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: max(len(prefix) for prefix in item.paths))


def _repair_authority_consequence(old: Any, new: Any) -> str | None:
    order = {
        "ANALYZE_ONLY": 0,
        "PROPOSE_ONLY": 1,
        "REQUIRE_OPERATOR_APPROVAL": 2,
        "AUTOMATIC_ELIGIBLE_REPAIRS": 3,
    }
    if old not in order or new not in order:
        return None
    if order[new] > order[old]:
        return "Increases Repair authority/autonomy; fewer operator boundaries may remain before activation."
    if order[new] < order[old]:
        return "Reduces Repair authority/autonomy; more work remains advisory or operator-gated."
    return "Repair authority level is unchanged."


def explain_policy_change(path: str, old: Any, new: Any, *, change: str) -> tuple[str, str]:
    capability = _capability_for_path(path)
    meaning = capability.description if capability else "Changes a Caretaker authority-controlled policy value."
    if path == "repair.authority" and change == "changed":
        consequence = _repair_authority_consequence(old, new)
        if consequence:
            return meaning, consequence
    if path == "repair.enabled":
        if new is False:
            return meaning, "Disables Repair for the selected scope. Incidents may still be observed by other configured subsystems."
        if new is True:
            return meaning, "Enables Repair processing for the selected scope, still subject to authority and validation gates."
    if path == "authority.runtime.require_signed_leases":
        if new is True:
            return meaning, "Unsigned runtime authority leases are no longer accepted while this requirement is effective."
        if new is False:
            return meaning, "Allows runtime authority leases without cryptographic profile/deployment signing if no higher constraint forbids them."
    if change == "added":
        consequence = "Adds an explicit policy decision that was not present in the earlier profile."
    elif change == "removed":
        consequence = "Removes an explicit policy decision; effective behavior may fall back to a lower layer or product default."
    else:
        consequence = "Changes the effective choice or guarantee for this policy path. Review the old and new values before accepting the profile."
    if capability:
        consequence += " " + capability.review_note
    return meaning, consequence


def _setting_dict(item: PolicySetting | None) -> Any:
    if item is None:
        return None
    return {
        "value": item.value,
        "override_constraints": item.override_constraints,
        "reason": item.reason,
    }


def _constraint_dict(item: PolicyConstraint | None) -> Any:
    if item is None:
        return None
    return {"operator": item.operator.value, "value": item.value}


def compare_profiles(
    left: PolicyAuthorityLayer,
    right: PolicyAuthorityLayer,
) -> ProfileComparison:
    left_identity = profile_identity(left)
    right_identity = profile_identity(right)
    same_lineage: bool | None = None
    continuation: bool | None = None
    if left_identity and right_identity:
        same_lineage = left_identity.lineage == right_identity.lineage
        continuation = (
            same_lineage
            and right_identity.version > left_identity.version
            and right_identity.supersedes_version == left_identity.version
            and right_identity.supersedes_fingerprint == left.fingerprint
        )

    differences: list[ProfileDifference] = []
    left_settings = _setting_map(left)
    right_settings = _setting_map(right)
    for key in sorted(set(left_settings) | set(right_settings), key=lambda item: (item[0], item[1] or "")):
        old = left_settings.get(key)
        new = right_settings.get(key)
        if old == new:
            continue
        change = "added" if old is None else "removed" if new is None else "changed"
        old_value = _setting_dict(old)
        new_value = _setting_dict(new)
        meaning, consequence = explain_policy_change(
            key[0], old.value if old else None, new.value if new else None, change=change
        )
        differences.append(
            ProfileDifference(change, key[0], key[1], old_value, new_value, meaning, consequence)
        )

    left_constraints = _constraint_map(left)
    right_constraints = _constraint_map(right)
    for key in sorted(
        set(left_constraints) | set(right_constraints),
        key=lambda item: (item[0], item[1] or "", item[2]),
    ):
        old = left_constraints.get(key)
        new = right_constraints.get(key)
        if old == new:
            continue
        change = "constraint-added" if old is None else "constraint-removed" if new is None else "constraint-changed"
        meaning, consequence = explain_policy_change(
            key[0], _constraint_dict(old), _constraint_dict(new), change="changed"
        )
        if change == "constraint-added":
            consequence = "Adds a guarantee that lower authority must satisfy or explicitly override. " + consequence
        elif change == "constraint-removed":
            consequence = "Removes a higher-level guarantee previously constraining lower authority. " + consequence
        differences.append(
            ProfileDifference(
                change,
                key[0],
                key[1],
                _constraint_dict(old),
                _constraint_dict(new),
                meaning,
                consequence,
            )
        )

    right_coverage = profile_coverage(right) if right_identity else None
    return ProfileComparison(
        left_fingerprint=left.fingerprint,
        right_fingerprint=right.fingerprint,
        left_authority_id=left.authority_id,
        right_authority_id=right.authority_id,
        left_kind=left.kind.value,
        right_kind=right.kind.value,
        left_generation=left.generation,
        right_generation=right.generation,
        left_identity=left_identity,
        right_identity=right_identity,
        same_lineage=same_lineage,
        lineage_continuation=continuation,
        changes=tuple(differences),
        right_coverage=right_coverage,
    )


def format_comparison_text(comparison: ProfileComparison) -> str:
    lines: list[str] = []
    left_name = (
        comparison.left_identity.display_name
        if comparison.left_identity
        else f"{comparison.left_authority_id} ({comparison.left_kind}, generation {comparison.left_generation}, {comparison.left_fingerprint[:12]})"
    )
    right_name = (
        comparison.right_identity.display_name
        if comparison.right_identity
        else f"{comparison.right_authority_id} ({comparison.right_kind}, generation {comparison.right_generation}, {comparison.right_fingerprint[:12]})"
    )
    lines.append(f"Compare: {left_name}")
    lines.append(f"     -> {right_name}")
    if comparison.same_lineage is not None:
        lines.append(f"Same lineage: {'yes' if comparison.same_lineage else 'NO'}")
        if comparison.same_lineage:
            lines.append(
                "Exact continuation binding: "
                + ("yes" if comparison.lineage_continuation else "NO / not declared")
            )
    if comparison.right_coverage is not None:
        coverage = comparison.right_coverage
        lines.append(
            f"Policy surface: {coverage.profile_surface_version}/{coverage.current_surface_version} "
            f"({'complete' if coverage.complete else 'review required'})"
        )
        for capability in coverage.missing_capabilities:
            lines.append(
                f"  NEW CAPABILITY: {capability.capability_id} "
                f"(introduced {capability.introduced_in}) - {capability.title}"
            )
    lines.append("")
    if not comparison.changes:
        lines.append("No setting or constraint changes.")
        return "\n".join(lines)
    for item in comparison.changes:
        target = f" target={item.target}" if item.target else ""
        lines.append(f"[{item.change.upper()}] {item.path}{target}")
        lines.append(f"  old: {json.dumps(item.old, sort_keys=True, default=str)}")
        lines.append(f"  new: {json.dumps(item.new, sort_keys=True, default=str)}")
        lines.append(f"  meaning: {item.meaning}")
        lines.append(f"  consequence: {item.consequence}")
        lines.append("")
    return "\n".join(lines).rstrip()


def _profile_metadata(
    *,
    lineage: str,
    name: str,
    version: int,
    description: str | None,
    policy_surface_version: int,
    caretaker_minimum: str | None,
    caretaker_tested_through: str | None,
    signer_role: str | None,
    require_complete_surface: bool,
    require_current_caretaker_version: bool,
    origin: str | None,
    supersedes: PolicyAuthorityLayer | None = None,
    based_on: PolicyAuthorityLayer | None = None,
) -> dict[str, str]:
    metadata = {
        PROFILE_LINEAGE: lineage,
        PROFILE_NAME: name,
        PROFILE_VERSION: str(version),
        PROFILE_SURFACE_VERSION: str(policy_surface_version),
        PROFILE_REQUIRE_COMPLETE_SURFACE: "true" if require_complete_surface else "false",
        PROFILE_REQUIRE_CURRENT_VERSION: "true" if require_current_caretaker_version else "false",
    }
    optional = {
        PROFILE_DESCRIPTION: description,
        PROFILE_MINIMUM_CARETAKER: caretaker_minimum,
        PROFILE_TESTED_THROUGH: caretaker_tested_through,
        PROFILE_SIGNER_ROLE: signer_role,
        PROFILE_ORIGIN: origin,
    }
    metadata.update({key: str(value) for key, value in optional.items() if value})
    if supersedes is not None:
        previous = profile_identity(supersedes, required=True)
        assert previous is not None
        metadata[PROFILE_SUPERSEDES_VERSION] = str(previous.version)
        metadata[PROFILE_SUPERSEDES_FINGERPRINT] = supersedes.fingerprint
    if based_on is not None:
        base = profile_identity(based_on, required=True)
        assert base is not None
        metadata[PROFILE_BASED_ON_LINEAGE] = base.lineage
        metadata[PROFILE_BASED_ON_VERSION] = str(base.version)
        metadata[PROFILE_BASED_ON_FINGERPRINT] = based_on.fingerprint
    return metadata


def create_profile(
    *,
    authority_id: str,
    lineage: str,
    name: str,
    version: int = 1,
    description: str | None = None,
    caretaker_minimum: str | None = None,
    caretaker_tested_through: str | None = None,
    signer_role: str | None = None,
    require_complete_surface: bool = False,
    require_current_caretaker_version: bool = False,
    origin: str | None = None,
    settings: Sequence[PolicySetting] = (),
    constraints: Sequence[PolicyConstraint] = (),
    supersedes: PolicyAuthorityLayer | None = None,
    based_on: PolicyAuthorityLayer | None = None,
    created_at: str | None = None,
) -> PolicyAuthorityLayer:
    if version < 1:
        raise AuthorityPolicyError("Profile version must be positive")
    if supersedes is not None:
        previous = profile_identity(supersedes, required=True)
        assert previous is not None
        if previous.lineage != lineage:
            raise AuthorityPolicyError(
                f"Profile lineage {lineage!r} does not continue {previous.lineage!r}"
            )
        if version <= previous.version:
            raise AuthorityPolicyError("A continuing profile must increase the profile version")
    metadata = _profile_metadata(
        lineage=lineage,
        name=name,
        version=version,
        description=description,
        policy_surface_version=CURRENT_POLICY_SURFACE_VERSION,
        caretaker_minimum=caretaker_minimum,
        caretaker_tested_through=caretaker_tested_through,
        signer_role=signer_role,
        require_complete_surface=require_complete_surface,
        require_current_caretaker_version=require_current_caretaker_version,
        origin=origin,
        supersedes=supersedes,
        based_on=based_on,
    )
    layer = PolicyAuthorityLayer(
        schema_version=1,
        authority_id=authority_id,
        kind=AuthorityKind.FRAMEWORK,
        generation=version,
        created_at=created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        settings=tuple(settings),
        constraints=tuple(constraints),
        parents={},
        metadata=metadata,
    )
    profile_identity(layer, required=True)
    return layer


def continue_profile(
    previous: PolicyAuthorityLayer,
    *,
    authority_id: str | None = None,
    name: str | None = None,
    description: str | None = None,
    settings: Sequence[PolicySetting] | None = None,
    constraints: Sequence[PolicyConstraint] | None = None,
    require_complete_surface: bool | None = None,
    require_current_caretaker_version: bool | None = None,
    caretaker_minimum: str | None = None,
    caretaker_tested_through: str | None = None,
) -> PolicyAuthorityLayer:
    identity = profile_identity(previous, required=True)
    assert identity is not None
    return create_profile(
        authority_id=authority_id or previous.authority_id,
        lineage=identity.lineage,
        name=name or identity.name,
        version=identity.version + 1,
        description=description if description is not None else identity.description,
        caretaker_minimum=caretaker_minimum or identity.caretaker_minimum,
        caretaker_tested_through=caretaker_tested_through or identity.caretaker_tested_through,
        signer_role=identity.signer_role,
        require_complete_surface=(
            identity.require_complete_surface
            if require_complete_surface is None
            else require_complete_surface
        ),
        require_current_caretaker_version=(
            identity.require_current_caretaker_version
            if require_current_caretaker_version is None
            else require_current_caretaker_version
        ),
        origin=identity.origin,
        settings=previous.settings if settings is None else settings,
        constraints=previous.constraints if constraints is None else constraints,
        supersedes=previous,
    )


def create_deployment_pin(
    profile: PolicyAuthorityLayer,
    *,
    authority_id: str,
    application: PolicyAuthorityLayer | None = None,
    generation: int = 1,
    created_at: str | None = None,
) -> PolicyAuthorityLayer:
    identity = profile_identity(profile, required=True)
    assert identity is not None
    parents = {"framework": profile.fingerprint}
    if application is not None:
        if application.kind is not AuthorityKind.APPLICATION:
            raise AuthorityPolicyError("The optional pin parent must be an application authority layer")
        parents["application"] = application.fingerprint
    return PolicyAuthorityLayer(
        schema_version=1,
        authority_id=authority_id,
        kind=AuthorityKind.DEPLOYMENT,
        generation=generation,
        created_at=created_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        parents=parents,
        metadata={
            "caretaker.profile.pin_lineage": identity.lineage,
            "caretaker.profile.pin_version": str(identity.version),
            "caretaker.profile.pin_fingerprint": profile.fingerprint,
        },
    )


def write_profile(path: str | Path, layer: PolicyAuthorityLayer) -> None:
    profile_identity(layer, required=True)
    write_policy_authority_layer(path, layer)


def parse_json_value(text: str) -> Any:
    value = text.strip()
    if not value:
        raise ValueError("Enter a value")
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def policy_capabilities_since(surface_version: int) -> tuple[PolicyCapability, ...]:
    return tuple(item for item in POLICY_CAPABILITIES if item.surface_version > surface_version)


def capability_catalog() -> tuple[dict[str, Any], ...]:
    return tuple(item.as_dict() for item in POLICY_CAPABILITIES)
