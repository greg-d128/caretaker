from __future__ import annotations

"""Discovery and verification of framework profiles shipped with Caretaker."""

from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .authority import (
    AuthorityKind,
    AuthorityLayerSource,
    AuthorityPolicyError,
    PolicyAuthoritySupervisor,
    load_policy_authority_layer,
    verify_authority_layer,
)
from .integrity.models import SignatureVerificationMode
from .integrity.gpg import GPGVerifier
from .integrity.manifest import load_root
from .integrity.verifier import IntegrityVerifier


@dataclass(frozen=True, slots=True)
class BuiltinProfile:
    name: str
    path: Path
    production: bool


_PROFILE_FILES = {
    "observe-only": ("caretaker-observe-only-v1.json", True),
    "balanced": ("caretaker-balanced-v1.json", True),
    "high-assurance": ("caretaker-high-assurance-v1.json", True),
    "sandbox": ("caretaker-sandbox-v1.json", False),
}


def builtin_profile_names() -> tuple[str, ...]:
    return tuple(_PROFILE_FILES)


def builtin_profiles() -> tuple[BuiltinProfile, ...]:
    directory = _profile_directory()
    return tuple(
        BuiltinProfile(name, directory / filename, production)
        for name, (filename, production) in _PROFILE_FILES.items()
    )


def builtin_profile(name: str) -> BuiltinProfile:
    normalized = str(name).strip().lower()
    try:
        filename, production = _PROFILE_FILES[normalized]
    except KeyError as exc:
        raise AuthorityPolicyError(
            f"Unknown built-in profile {name!r}; choose from {', '.join(builtin_profile_names())}"
        ) from exc
    path = _profile_directory() / filename
    if not path.is_file():
        raise AuthorityPolicyError(f"Built-in profile is unavailable: {path}")
    return BuiltinProfile(normalized, path, production)


def load_builtin_profile_supervisor(
    name: str,
    *,
    trusted_primary_fingerprints: tuple[str, ...] | None = None,
) -> PolicyAuthoritySupervisor:
    selected = builtin_profile(name)
    layer = load_policy_authority_layer(selected.path, require_canonical=True)
    if selected.production:
        publication = _publication_directory()
        slots = ("a", "b", "c")
        root_path = publication / "root.json"
        root = load_root(root_path)
        trusted = trusted_primary_fingerprints or tuple(root.key_slots.values())
        root_result = IntegrityVerifier(gpg=GPGVerifier()).verify_initial_root(
            root_path=root_path,
            signature_paths=tuple(
                publication / f"root.json.key-{slot}.asc" for slot in slots
            ),
            public_key_paths=tuple(
                publication / "release-keys" / f"caretaker-key-{slot}.asc"
                for slot in slots
            ),
            trusted_primary_fingerprints=trusted,
            threshold=root.roles["root"].threshold,
        )
        if not root_result.satisfied:
            raise AuthorityPolicyError(
                f"Built-in profile {selected.name!r} has an untrusted packaged root: "
                + ("; ".join(root_result.errors) or "signature threshold was not satisfied")
            )
        source = AuthorityLayerSource(
            kind=AuthorityKind.FRAMEWORK,
            path=selected.path,
            role="protected",
            signatures=tuple(
                selected.path.with_name(f"{selected.path.name}.key-{slot}.asc")
                for slot in slots
            ),
            root=root_path,
            public_keys=tuple(
                publication / "release-keys" / f"caretaker-key-{slot}.asc"
                for slot in slots
            ),
            verification_mode=SignatureVerificationMode.FULL_PUBLICATION,
            require_signature=True,
        )
        verification = verify_authority_layer(
            layer,
            source,
            default_root=None,
            default_public_keys=(),
        )
        if not verification.verified:
            detail = "; ".join(verification.errors) or "signature threshold was not satisfied"
            raise AuthorityPolicyError(
                f"Built-in profile {selected.name!r} failed verification: {detail}"
            )
        return PolicyAuthoritySupervisor((layer,), (verification,))
    return PolicyAuthoritySupervisor((layer,))


def _profile_directory() -> Path:
    installed = Path(str(files("caretaker").joinpath("profiles")))
    if installed.is_dir():
        return installed
    repository = Path(__file__).resolve().parents[2] / "profiles"
    return repository


def _publication_directory() -> Path:
    installed = Path(str(files("caretaker").joinpath("_publication")))
    if installed.is_dir():
        return installed
    return Path(__file__).resolve().parents[2]
