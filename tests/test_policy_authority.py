from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from caretaker.authority import (
    AuthorityKind,
    AuthorityLayerVerification,
    AuthorityPolicyConflictError,
    AuthorityPolicyError,
    ConstraintOperator,
    PolicyAuthorityLayer,
    PolicyAuthoritySupervisor,
    PolicyConstraint,
    PolicySetting,
    SignatureState,
    get_authority_runtime_context,
    load_policy_authority_layer,
    write_policy_authority_layer,
)
from caretaker.logging.models import RepairAuthority
from caretaker.policy import RepairPolicy


def _layer(
    authority_id: str,
    kind: AuthorityKind,
    *,
    settings=(),
    constraints=(),
    parents=None,
) -> PolicyAuthorityLayer:
    return PolicyAuthorityLayer(
        schema_version=1,
        authority_id=authority_id,
        kind=kind,
        generation=1,
        created_at=datetime.now(timezone.utc).isoformat(),
        settings=tuple(settings),
        constraints=tuple(constraints),
        parents=parents or {},
    )


@pytest.fixture(autouse=True)
def _reset_runtime_authority():
    context = get_authority_runtime_context()
    previous = context.effective.snapshot_dict()
    context.update_from_snapshot(
        {
            "generation": 0,
            "fingerprint": "unconfigured",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "layers": [],
            "verifications": [],
            "runtime_leases": [],
            "violations": [],
        }
    )
    yield
    context.update_from_snapshot(previous)


def test_application_layer_can_be_skipped_and_deployment_values_still_apply() -> None:
    framework = _layer("caretaker-project", AuthorityKind.FRAMEWORK)
    deployment = _layer(
        "prod-deployer",
        AuthorityKind.DEPLOYMENT,
        settings=(PolicySetting("repair.enabled", False),),
        parents={"framework": framework.fingerprint},
    )
    supervisor = PolicyAuthoritySupervisor((framework, deployment))

    policy = supervisor.effective.apply_dataclass(
        RepairPolicy(), prefix="repair", target_id="demo.target"
    )

    assert policy.enabled is False
    statuses = {item["kind"]: item for item in supervisor.effective.layer_status()}
    assert statuses["application"]["guarantee"] == "skipped"
    assert statuses["framework"]["guarantee"] == "unsigned"
    assert statuses["deployment"]["guarantee"] == "unsigned"


def test_conflict_requires_explicit_lower_authority_override() -> None:
    application = _layer(
        "application-owner",
        AuthorityKind.APPLICATION,
        constraints=(
            PolicyConstraint(
                "repair.authority",
                ConstraintOperator.ALLOWED_VALUES,
                ("ANALYZE_ONLY", "PROPOSE_ONLY", "REQUIRE_OPERATOR_APPROVAL"),
                target="billing.*",
            ),
        ),
    )
    deployment = _layer(
        "deployment",
        AuthorityKind.DEPLOYMENT,
        settings=(
            PolicySetting(
                "repair.authority",
                "AUTOMATIC_ELIGIBLE_REPAIRS",
                target="billing.charge",
            ),
        ),
        parents={"application": application.fingerprint},
    )

    with pytest.raises(AuthorityPolicyConflictError):
        PolicyAuthoritySupervisor((application, deployment))


def test_explicit_override_changes_behavior_and_invalidates_guarantee() -> None:
    application = _layer(
        "application-owner",
        AuthorityKind.APPLICATION,
        constraints=(
            PolicyConstraint(
                "repair.authority",
                ConstraintOperator.ALLOWED_VALUES,
                ("ANALYZE_ONLY", "PROPOSE_ONLY", "REQUIRE_OPERATOR_APPROVAL"),
                target="billing.*",
            ),
        ),
    )
    deployment = _layer(
        "deployment",
        AuthorityKind.DEPLOYMENT,
        settings=(
            PolicySetting(
                "repair.authority",
                "AUTOMATIC_ELIGIBLE_REPAIRS",
                target="billing.charge",
                override_constraints=True,
                reason="Emergency unattended repair approved by deployment owner",
            ),
        ),
        parents={"application": application.fingerprint},
    )
    supervisor = PolicyAuthoritySupervisor((application, deployment))

    policy = supervisor.effective.apply_dataclass(
        RepairPolicy(), prefix="repair", target_id="billing.charge"
    )

    assert policy.authority is RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS
    assert supervisor.effective.overall_assurance == "GUARANTEE_VIOLATED"
    assert len(supervisor.effective.violations) == 1
    violation = supervisor.effective.violations[0]
    assert violation.authority_id == "application-owner"
    assert violation.overridden_by == "deployment"


def test_target_constraint_also_applies_to_application_declared_policy() -> None:
    application = _layer(
        "application-owner",
        AuthorityKind.APPLICATION,
        constraints=(
            PolicyConstraint(
                "repair.retry.max_attempts",
                ConstraintOperator.EXACT,
                0,
                target="payments.*",
            ),
        ),
    )
    supervisor = PolicyAuthoritySupervisor((application,))
    unsafe = replace(RepairPolicy(), retry=replace(RepairPolicy().retry, max_attempts=1, safety=RepairPolicy().retry.safety))

    with pytest.raises(AuthorityPolicyConflictError):
        supervisor.effective.apply_dataclass(
            unsafe, prefix="repair", target_id="payments.charge"
        )

    # The same application-owner constraint does not affect an unrelated target.
    unrelated = supervisor.effective.apply_dataclass(
        unsafe, prefix="repair", target_id="cache.lookup"
    )
    assert unrelated.retry.max_attempts == 1


def test_unsigned_runtime_lease_allowed_by_default_and_can_be_target_scoped() -> None:
    supervisor = PolicyAuthoritySupervisor()
    lease = supervisor.acquire_runtime_lease(
        settings=(
            PolicySetting(
                "repair.authority",
                "AUTOMATIC_ELIGIBLE_REPAIRS",
                target="demo.divide",
                reason="incident demo",
            ),
        ),
        requested_by="uid:1000",
        reason="incident demo",
        duration_seconds=60,
    )

    assert lease.signature_state is SignatureState.UNSIGNED
    changed = supervisor.effective.apply_dataclass(
        RepairPolicy(), prefix="repair", target_id="demo.divide"
    )
    unchanged = supervisor.effective.apply_dataclass(
        RepairPolicy(), prefix="repair", target_id="demo.other"
    )
    assert changed.authority is RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS
    assert unchanged.authority is RepairAuthority.REQUIRE_OPERATOR_APPROVAL


def test_higher_policy_can_require_signed_runtime_leases() -> None:
    framework = _layer(
        "caretaker-project",
        AuthorityKind.FRAMEWORK,
        settings=(PolicySetting("authority.runtime.require_signed_leases", True),),
    )
    supervisor = PolicyAuthoritySupervisor((framework,))

    with pytest.raises(AuthorityPolicyError, match="requires signed runtime leases"):
        supervisor.acquire_runtime_lease(
            settings=(PolicySetting("repair.enabled", False, target="demo.target"),),
            requested_by="uid:1000",
            reason="test",
            duration_seconds=60,
        )


def test_parent_hash_binds_lower_layer_to_exact_upstream_policy() -> None:
    framework = _layer("caretaker-project", AuthorityKind.FRAMEWORK)
    deployment = _layer(
        "deployment",
        AuthorityKind.DEPLOYMENT,
        parents={"framework": "0" * 64},
    )

    with pytest.raises(AuthorityPolicyError, match="created against framework"):
        PolicyAuthoritySupervisor((framework, deployment))


def test_policy_layer_round_trip_uses_canonical_json(tmp_path: Path) -> None:
    layer = _layer(
        "application-owner",
        AuthorityKind.APPLICATION,
        settings=(PolicySetting("repair.enabled", False, target="critical.*"),),
        constraints=(
            PolicyConstraint("repair.enabled", ConstraintOperator.REQUIRED_FALSE, target="critical.*"),
        ),
    )
    path = tmp_path / "application-policy.json"
    write_policy_authority_layer(path, layer)

    loaded = load_policy_authority_layer(path)

    assert loaded == layer
    assert path.read_bytes().endswith(b"\n")


def test_lower_authority_must_reference_all_upstream_fingerprints() -> None:
    framework = _layer("caretaker-project", AuthorityKind.FRAMEWORK)
    application = _layer("application-owner", AuthorityKind.APPLICATION)

    with pytest.raises(AuthorityPolicyError, match="must reference the exact upstream"):
        PolicyAuthoritySupervisor((framework, application))


def test_runtime_repair_lease_must_be_target_scoped() -> None:
    supervisor = PolicyAuthoritySupervisor()
    with pytest.raises(AuthorityPolicyError, match="explicit target"):
        supervisor.acquire_runtime_lease(
            settings=(PolicySetting("repair.enabled", False),),
            requested_by="uid:1000",
            reason="incident",
            duration_seconds=60,
        )


def test_runtime_restart_bound_setting_is_rejected() -> None:
    supervisor = PolicyAuthoritySupervisor()
    with pytest.raises(AuthorityPolicyError, match="restart-bound"):
        supervisor.acquire_runtime_lease(
            settings=(PolicySetting("logging.directory", "/tmp/new-location"),),
            requested_by="uid:1000",
            reason="incident",
            duration_seconds=60,
        )


def test_signed_layer_uses_external_gpg_and_root_authority(tmp_path: Path) -> None:
    from caretaker.authority import AuthorityLayerSource, verify_authority_layer
    from caretaker.integrity import RolePolicy, RootMetadata, write_root
    from .integrity_helpers import export_public_key, generate_test_key, make_gpg_home, sign_file

    home = make_gpg_home(tmp_path / "signer")
    fingerprint = generate_test_key(home, "Application Owner <owner@example.invalid>")
    second = generate_test_key(home, "Authority Two <two@example.invalid>")
    third = generate_test_key(home, "Authority Three <three@example.invalid>")
    public_key = tmp_path / "owner.asc"
    export_public_key(home, fingerprint, public_key)

    root_path = tmp_path / "authority-root.json"
    write_root(
        root_path,
        RootMetadata(
            schema_version=1,
            project="demo-application",
            root_version=1,
            roles={
                "release": RolePolicy("release", (fingerprint, second, third), 1),
                "protected": RolePolicy("protected", (fingerprint, second, third), 2),
                "root": RolePolicy("root", (fingerprint, second, third), 2),
                "policy-application": RolePolicy(
                    "policy-application", (fingerprint,), 1
                ),
            },
            created_at=datetime.now(timezone.utc).isoformat(),
        ),
    )

    layer = _layer(
        "application-owner",
        AuthorityKind.APPLICATION,
        constraints=(
            PolicyConstraint(
                "repair.authority",
                ConstraintOperator.ALLOWED_VALUES,
                ("ANALYZE_ONLY", "PROPOSE_ONLY", "REQUIRE_OPERATOR_APPROVAL"),
            ),
        ),
    )
    layer_path = tmp_path / "application-policy.json"
    write_policy_authority_layer(layer_path, layer)
    signature = tmp_path / "application-policy.asc"
    sign_file(home, fingerprint, layer_path, signature)

    result = verify_authority_layer(
        layer,
        AuthorityLayerSource(
            kind=AuthorityKind.APPLICATION,
            path=layer_path,
            role="policy-application",
            signatures=(signature,),
            root=root_path,
            public_keys=(public_key,),
            require_signature=True,
        ),
        default_root=None,
        default_public_keys=(),
    )

    assert result.signature_state is SignatureState.VERIFIED
    assert result.valid_primary_fingerprints == (fingerprint,)


def test_unsigned_runtime_lease_reduces_verified_chain_assurance() -> None:
    framework = _layer("caretaker-project", AuthorityKind.FRAMEWORK)
    verification = AuthorityLayerVerification(
        authority_id=framework.authority_id,
        kind=framework.kind,
        fingerprint=framework.fingerprint,
        signature_state=SignatureState.VERIFIED,
    )
    supervisor = PolicyAuthoritySupervisor((framework,), (verification,))
    assert supervisor.effective.overall_assurance == "VERIFIED_AUTHORITY_CHAIN"

    supervisor.acquire_runtime_lease(
        settings=(PolicySetting("repair.enabled", False, target="demo.target"),),
        requested_by="uid:1000",
        reason="incident",
        duration_seconds=60,
    )
    assert supervisor.effective.overall_assurance == "UNSIGNED_RUNTIME_OVERRIDE"


def test_layer_expiration_creates_new_invalid_generation(monkeypatch) -> None:
    import caretaker.authority as authority_module

    start = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(authority_module, "utcnow", lambda: start)
    layer = PolicyAuthorityLayer(
        schema_version=1,
        authority_id="application-owner",
        kind=AuthorityKind.APPLICATION,
        generation=1,
        created_at=start.isoformat(),
        expires_at=start.replace(hour=13).isoformat(),
    )
    supervisor = PolicyAuthoritySupervisor((layer,))
    generation = supervisor.effective.generation

    monkeypatch.setattr(authority_module, "utcnow", lambda: start.replace(hour=14))
    effective = supervisor.effective

    assert effective.generation > generation
    assert effective.overall_assurance == "INVALID_AUTHORITY_CHAIN"


def test_repository_unsigned_authority_example_is_self_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    supervisor = PolicyAuthoritySupervisor.from_stack_file(
        root / "examples" / "policy_authority" / "stack-unsigned.toml"
    )
    assert supervisor.effective.overall_assurance == "PARTIAL_OR_UNSIGNED"
    policy = supervisor.effective.apply_dataclass(
        RepairPolicy(), prefix="repair", target_id="example.critical.payment"
    )
    assert policy.authority is RepairAuthority.REQUIRE_OPERATOR_APPROVAL


def test_signed_runtime_lease_stack_descriptor(tmp_path: Path) -> None:
    from caretaker.integrity import RolePolicy, RootMetadata, write_root
    from .integrity_helpers import export_public_key, generate_test_key, make_gpg_home, sign_file

    home = make_gpg_home(tmp_path / "signer")
    primary = generate_test_key(home, "Runtime Operator <runtime@example.invalid>")
    second = generate_test_key(home, "Authority Two <two@example.invalid>")
    third = generate_test_key(home, "Authority Three <three@example.invalid>")
    public_key = tmp_path / "runtime.asc"
    export_public_key(home, primary, public_key)

    root_path = tmp_path / "authority-root.json"
    write_root(
        root_path,
        RootMetadata(
            schema_version=1,
            project="demo",
            root_version=1,
            roles={
                "release": RolePolicy("release", (primary, second, third), 1),
                "protected": RolePolicy("protected", (primary, second, third), 2),
                "root": RolePolicy("root", (primary, second, third), 2),
                "policy-runtime": RolePolicy("policy-runtime", (primary,), 1),
            },
            created_at=datetime.now(timezone.utc).isoformat(),
        ),
    )

    now = datetime.now(timezone.utc).replace(microsecond=0)
    layer = PolicyAuthorityLayer(
        schema_version=1,
        authority_id="incident-operator",
        kind=AuthorityKind.RUNTIME,
        generation=1,
        created_at=now.isoformat(),
        expires_at=now.replace(year=now.year + 1).isoformat(),
        settings=(PolicySetting("repair.enabled", False, target="demo.target"),),
    )
    layer_path = tmp_path / "runtime-policy.json"
    write_policy_authority_layer(layer_path, layer)
    signature = tmp_path / "runtime-policy.asc"
    sign_file(home, primary, layer_path, signature)

    descriptor = tmp_path / "runtime-lease.toml"
    descriptor.write_text(
        "\n".join(
            [
                "schema_version = 1",
                "[trust]",
                f'root = "{root_path.name}"',
                f'public_keys = ["{public_key.name}"]',
                "[[layers]]",
                'kind = "runtime"',
                f'path = "{layer_path.name}"',
                'role = "policy-runtime"',
                f'signatures = ["{signature.name}"]',
                "require_signature = true",
                "",
            ]
        ),
        encoding="utf-8",
    )

    supervisor = PolicyAuthoritySupervisor()
    lease = supervisor.load_signed_runtime_lease_from_stack_file(
        descriptor, requested_by="uid:1000", reason="incident"
    )
    assert lease.signature_state is SignatureState.VERIFIED
    assert supervisor.effective.apply_dataclass(
        RepairPolicy(), prefix="repair", target_id="demo.target"
    ).enabled is False
