from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

import caretaker
import caretaker.profiles as profiles_module
from caretaker.builtin_profiles import (
    builtin_profile,
    builtin_profile_names,
    load_builtin_profile_supervisor,
)
from caretaker.authority import (
    AuthorityKind,
    AuthorityPolicyError,
    PolicyAuthoritySupervisor,
    ConstraintOperator,
    PolicyAuthorityLayer,
    PolicyConstraint,
    PolicySetting,
    load_policy_authority_layer,
    write_policy_authority_layer,
)
from caretaker.profiles import (
    CURRENT_POLICY_SURFACE_VERSION,
    OFFICIAL_PROFILE_SIGNING_ROLE,
    PROFILE_SURFACE_VERSION,
    PolicyCapability,
    compare_profiles,
    continue_profile,
    create_deployment_pin,
    create_profile,
    profile_coverage,
    profile_identity,
    validate_runtime_profile,
)


def _profile(**changes) -> PolicyAuthorityLayer:
    values = {
        "authority_id": "caretaker-project-profile",
        "lineage": "caretaker.balanced",
        "name": "Caretaker Balanced",
        "version": 1,
        "description": "General-purpose profile",
        "caretaker_minimum": "0.6.0",
        "caretaker_tested_through": caretaker.__version__,
        "settings": (
            PolicySetting("repair.authority", "REQUIRE_OPERATOR_APPROVAL"),
        ),
        "constraints": (
            PolicyConstraint(
                "repair.validation.isolate_validation",
                ConstraintOperator.REQUIRED_TRUE,
            ),
        ),
        "created_at": "2026-08-10T00:00:00+00:00",
    }
    values.update(changes)
    return create_profile(**values)


def test_profile_identity_separates_lineage_name_and_version() -> None:
    layer = _profile()
    identity = profile_identity(layer, required=True)
    assert identity is not None
    assert identity.lineage == "caretaker.balanced"
    assert identity.name == "Caretaker Balanced"
    assert identity.version == 1
    assert identity.policy_surface_version == CURRENT_POLICY_SURFACE_VERSION


def test_repository_sandbox_profile_and_stack_are_explicitly_nonproduction() -> None:
    profile = load_policy_authority_layer(
        Path(__file__).parents[1] / "profiles/caretaker-sandbox-v1.json"
    )
    identity = profile_identity(profile, required=True)
    assert identity is not None
    assert identity.lineage == "caretaker.sandbox"
    assert identity.signer_role is None
    assert profile.constraints == ()
    assert not any(item.path == "repair.authority" for item in profile.settings)
    assert profile.metadata["purpose"].startswith("demonstration only")

    supervisor = PolicyAuthoritySupervisor.from_stack_file(
        Path(__file__).parents[1] / "profiles/sandbox-stack.toml"
    )
    assert supervisor.effective.overall_assurance == "PARTIAL_OR_UNSIGNED"


def test_builtin_profile_catalog_marks_only_sandbox_nonproduction() -> None:
    assert builtin_profile_names() == (
        "observe-only",
        "balanced",
        "high-assurance",
        "sandbox",
    )
    assert builtin_profile("balanced").production is True
    assert builtin_profile("sandbox").production is False
    sandbox = load_builtin_profile_supervisor("sandbox")
    assert sandbox.effective.overall_assurance == "PARTIAL_OR_UNSIGNED"


def test_continuation_binds_exact_predecessor_fingerprint() -> None:
    first = _profile()
    second = continue_profile(first, caretaker_tested_through=caretaker.__version__)
    identity = profile_identity(second, required=True)
    assert identity is not None
    assert identity.version == 2
    assert identity.supersedes_version == 1
    assert identity.supersedes_fingerprint == first.fingerprint
    comparison = compare_profiles(first, second)
    assert comparison.same_lineage is True
    assert comparison.lineage_continuation is True


def test_changed_lineage_records_based_on_relationship_instead_of_continuation() -> None:
    official = _profile()
    custom = create_profile(
        authority_id="acme-profile",
        lineage="acme.production",
        name="Acme Production",
        version=1,
        caretaker_tested_through=caretaker.__version__,
        settings=official.settings,
        constraints=official.constraints,
        based_on=official,
        created_at="2026-08-10T00:00:01+00:00",
    )
    identity = profile_identity(custom, required=True)
    assert identity is not None
    assert identity.supersedes_version is None
    assert identity.based_on_lineage == "caretaker.balanced"
    assert identity.based_on_version == 1
    assert identity.based_on_fingerprint == official.fingerprint


def test_semantic_compare_explains_increased_repair_authority() -> None:
    first = _profile()
    second = continue_profile(
        first,
        settings=(PolicySetting("repair.authority", "AUTOMATIC_ELIGIBLE_REPAIRS"),),
        caretaker_tested_through=caretaker.__version__,
    )
    comparison = compare_profiles(first, second)
    change = next(item for item in comparison.changes if item.path == "repair.authority")
    assert change.change == "changed"
    assert "Increases Repair authority/autonomy" in change.consequence



def test_policy_surface_two_requires_review_of_adaptive_instrumentation() -> None:
    layer = _profile()
    metadata = dict(layer.metadata)
    metadata[PROFILE_SURFACE_VERSION] = "1"
    old_surface = replace(layer, metadata=metadata)

    report = profile_coverage(old_surface)

    assert report.complete is False
    assert [item.capability_id for item in report.missing_capabilities] == [
        "adaptive.instrumentation",
        "guard.behavior-snapshots",
        "repair.validation-isolation",
        "logging.signing-identity-journal",
    ]

def test_policy_surface_reports_capabilities_added_after_profile(monkeypatch) -> None:
    layer = _profile()
    extra = PolicyCapability(
        "repair.future-capability",
        CURRENT_POLICY_SURFACE_VERSION + 1,
        "0.7.0a1",
        "Future Repair control",
        "Controls a newly introduced Repair behavior.",
        "Review the new control before continuing the profile lineage.",
        ("repair.future.",),
    )
    monkeypatch.setattr(
        profiles_module,
        "POLICY_CAPABILITIES",
        profiles_module.POLICY_CAPABILITIES + (extra,),
    )
    monkeypatch.setattr(
        profiles_module,
        "CURRENT_POLICY_SURFACE_VERSION",
        CURRENT_POLICY_SURFACE_VERSION + 1,
    )
    report = profile_coverage(layer)
    assert report.complete is False
    assert [item.capability_id for item in report.missing_capabilities] == [
        "repair.future-capability"
    ]


def test_strict_profile_rejects_unreviewed_new_policy_surface(monkeypatch) -> None:
    layer = _profile(require_complete_surface=True)
    extra = PolicyCapability(
        "guard.future-capability",
        CURRENT_POLICY_SURFACE_VERSION + 1,
        "0.7.0a1",
        "Future Guard control",
        "Controls newly introduced Guard behavior.",
        "Review before high-assurance startup.",
        ("guard.future.",),
    )
    monkeypatch.setattr(
        profiles_module,
        "POLICY_CAPABILITIES",
        profiles_module.POLICY_CAPABILITIES + (extra,),
    )
    monkeypatch.setattr(
        profiles_module,
        "CURRENT_POLICY_SURFACE_VERSION",
        CURRENT_POLICY_SURFACE_VERSION + 1,
    )
    with pytest.raises(AuthorityPolicyError, match="not reviewed"):
        validate_runtime_profile(layer)


def test_strict_version_review_requires_current_caretaker_version() -> None:
    layer = _profile(
        require_current_caretaker_version=True,
        caretaker_tested_through="0.5.0a1",
    )
    with pytest.raises(AuthorityPolicyError, match="running version"):
        validate_runtime_profile(layer)


def test_profile_declared_signer_role_must_match_stack_role() -> None:
    layer = _profile(signer_role=OFFICIAL_PROFILE_SIGNING_ROLE)
    with pytest.raises(AuthorityPolicyError, match="requires signer role"):
        validate_runtime_profile(layer, source_role="release")
    validate_runtime_profile(layer, source_role=OFFICIAL_PROFILE_SIGNING_ROLE)


def test_deployment_pin_binds_exact_framework_and_optional_application() -> None:
    profile = _profile()
    application = PolicyAuthorityLayer(
        schema_version=1,
        authority_id="application-owner",
        kind=AuthorityKind.APPLICATION,
        generation=1,
        created_at=datetime.now(timezone.utc).isoformat(),
        parents={"framework": profile.fingerprint},
    )
    pin = create_deployment_pin(
        profile,
        authority_id="production-selection",
        application=application,
        generation=4,
        created_at="2026-08-10T00:00:02+00:00",
    )
    assert pin.kind is AuthorityKind.DEPLOYMENT
    assert pin.parents == {
        "framework": profile.fingerprint,
        "application": application.fingerprint,
    }
    assert pin.metadata["caretaker.profile.pin_fingerprint"] == profile.fingerprint


def test_runtime_stack_loader_applies_profile_metadata_validation(tmp_path: Path) -> None:
    # A future surface is rejected by the profile validator even when the authority
    # layer itself is otherwise valid and unsigned.
    from caretaker.authority import PolicyAuthoritySupervisor

    profile = _profile()
    metadata = dict(profile.metadata)
    metadata[PROFILE_SURFACE_VERSION] = str(CURRENT_POLICY_SURFACE_VERSION + 1)
    profile = replace(profile, metadata=metadata)
    profile_path = tmp_path / "profile.json"
    write_policy_authority_layer(profile_path, profile)
    stack = tmp_path / "stack.toml"
    stack.write_text(
        "\n".join(
            [
                "schema_version = 1",
                "[[layers]]",
                'kind = "framework"',
                f'path = "{profile_path.name}"',
                "require_signature = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(AuthorityPolicyError, match="newer than this Caretaker build"):
        PolicyAuthoritySupervisor.from_stack_file(stack)
