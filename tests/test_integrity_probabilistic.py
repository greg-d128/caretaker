from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from caretaker.integrity import (
    GPGVerifier,
    KeyRotationPolicy,
    RolePolicy,
    RootMetadata,
    SignatureVerificationMode,
    load_root,
    write_root,
)
from tests.integrity_helpers import (
    export_public_key,
    generate_test_key,
    make_gpg_home,
    sign_file,
)


class FixedRandom:
    def __init__(self, selected: tuple[str, ...]) -> None:
        self.selected = selected

    def sample(self, population: list[str], count: int) -> list[str]:
        assert all(item in population for item in self.selected[:count])
        return list(self.selected[:count])

    def shuffle(self, values: list[object]) -> None:
        return None


def _signed_data(tmp_path: Path):
    home = make_gpg_home(tmp_path / "signer")
    fingerprints = tuple(
        generate_test_key(home, f"Caretaker Random {name} <{name.lower()}@example.invalid>")
        for name in ("A", "B", "C")
    )
    public_keys: list[Path] = []
    for index, fingerprint in enumerate(fingerprints):
        path = tmp_path / f"key-{index}.asc"
        export_public_key(home, fingerprint, path)
        public_keys.append(path)
    data = tmp_path / "manifest.json"
    data.write_text('{"test":true}\n', encoding="utf-8")
    signatures: list[Path] = []
    for index, fingerprint in enumerate(fingerprints):
        signature = tmp_path / f"manifest.{index}.asc"
        sign_file(home, fingerprint, data, signature)
        signatures.append(signature)
    return home, fingerprints, public_keys, data, signatures


def test_full_publication_requires_all_three_distinct_signers(tmp_path: Path) -> None:
    _home, fingerprints, public_keys, data, signatures = _signed_data(tmp_path)
    role = RolePolicy(
        "release",
        fingerprints,
        threshold=1,
        publication_threshold=3,
        runtime_sample_size=1,
    )
    verifier = GPGVerifier()
    complete = verifier.verify_threshold(
        signed_path=data,
        signature_paths=signatures,
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.FULL_PUBLICATION,
    )
    assert complete.satisfied
    assert len(complete.valid_primary_fingerprints) == 3

    incomplete = verifier.verify_threshold(
        signed_path=data,
        signature_paths=signatures[:2],
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.FULL_PUBLICATION,
    )
    assert not incomplete.satisfied


def test_randomized_release_verification_detects_partial_key_compromise_probabilistically(
    tmp_path: Path,
) -> None:
    _home, fingerprints, public_keys, data, signatures = _signed_data(tmp_path)
    role = RolePolicy(
        "release",
        fingerprints,
        threshold=1,
        publication_threshold=3,
        runtime_sample_size=1,
    )

    selected_b = GPGVerifier(random_source=FixedRandom((fingerprints[1],)))
    honest_map = dict(zip(fingerprints, signatures, strict=True))
    honest = selected_b.verify_threshold(
        signed_path=data,
        signature_paths=honest_map,
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.RANDOMIZED_RUNTIME,
    )
    assert honest.satisfied
    assert honest.selected_primary_fingerprints == (fingerprints[1],)
    assert len(honest.signature_results) == 1

    forged_with_a_only = {fingerprint: signatures[0] for fingerprint in fingerprints}
    detected = selected_b.verify_threshold(
        signed_path=data,
        signature_paths=forged_with_a_only,
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.RANDOMIZED_RUNTIME,
    )
    assert not detected.satisfied

    selected_a = GPGVerifier(random_source=FixedRandom((fingerprints[0],)))
    probabilistic_pass = selected_a.verify_threshold(
        signed_path=data,
        signature_paths=forged_with_a_only,
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.RANDOMIZED_RUNTIME,
    )
    assert probabilistic_pass.satisfied


def test_protected_runtime_sampling_preserves_two_of_three(tmp_path: Path) -> None:
    _home, fingerprints, public_keys, data, signatures = _signed_data(tmp_path)
    role = RolePolicy(
        "protected",
        fingerprints,
        threshold=2,
        publication_threshold=3,
        runtime_sample_size=2,
    )
    selected_ab = GPGVerifier(random_source=FixedRandom((fingerprints[0], fingerprints[1])))
    result = selected_ab.verify_threshold(
        signed_path=data,
        signature_paths={
            fingerprints[0]: signatures[0],
            fingerprints[1]: signatures[1],
            fingerprints[2]: signatures[0],
        },
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.RANDOMIZED_RUNTIME,
    )
    assert result.satisfied
    assert len(result.signature_results) == 2

    selected_ac = GPGVerifier(random_source=FixedRandom((fingerprints[0], fingerprints[2])))
    result = selected_ac.verify_threshold(
        signed_path=data,
        signature_paths={
            fingerprints[0]: signatures[0],
            fingerprints[1]: signatures[1],
            fingerprints[2]: signatures[0],
        },
        public_key_paths=public_keys,
        role=role,
        mode=SignatureVerificationMode.RANDOMIZED_RUNTIME,
    )
    assert not result.satisfied


def test_root_v2_records_rolling_two_year_rotation_schedule(tmp_path: Path) -> None:
    fingerprints = ("A" * 40, "B" * 40, "C" * 40)
    root = RootMetadata(
        schema_version=2,
        project="caretaker",
        root_version=1,
        roles={
            "release": RolePolicy("release", fingerprints, 1, 3, 1),
            "protected": RolePolicy("protected", fingerprints, 2, 3, 2),
            "root": RolePolicy("root", fingerprints, 2, 3, 2),
        },
        key_slots={"A": fingerprints[0], "B": fingerprints[1], "C": fingerprints[2]},
        rotation_policy=KeyRotationPolicy(
            epoch="2026-01-01T00:00:00+00:00",
            interval_days=730,
            sequence=("A", "B", "C"),
            generation=0,
            warning_days=90,
        ),
    )
    path = tmp_path / "root.json"
    write_root(path, root)
    loaded = load_root(path)
    status = loaded.rotation_status(datetime(2027, 12, 15, tzinfo=timezone.utc))
    assert status is not None
    assert status.next_slot == "A"
    assert status.warning
    assert not status.overdue
    assert status.full_cycle_days == 2190


def test_bootstrap_integrity_default_is_authorization_threshold() -> None:
    import inspect
    from caretaker.integrity.runtime import bootstrap_integrity

    parameter = inspect.signature(bootstrap_integrity).parameters["verification_mode"]
    assert parameter.default is SignatureVerificationMode.AUTHORIZATION_THRESHOLD
