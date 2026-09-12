"""Shared transport and endpoint policy for all Caretaker Ollama clients."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import math
import os
import ssl
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, MutableMapping
from urllib.parse import urlparse

MAX_PROVIDER_RESPONSE_BYTES = 256 * 1024
_LOG = logging.getLogger("caretaker.ollama")


class ProviderResponseError(ValueError):
    """Raised when an advisory provider response violates its transport contract."""


class OllamaEndpointMode(str, Enum):
    LOCAL_ONLY = "local_only"
    REMOTE_UNVERIFIED = "remote_unverified"
    REMOTE_SERVER_VERIFIED = "remote_server_verified"
    REMOTE_ATTESTED = "remote_attested"


OllamaEndpointSecurityMode = OllamaEndpointMode


def _as_mode(value: OllamaEndpointMode | str) -> OllamaEndpointMode:
    if isinstance(value, OllamaEndpointMode):
        return value
    try:
        return OllamaEndpointMode(str(value).strip().lower())
    except ValueError as exc:
        raise ValueError(
            "ollama endpoint mode must be one of: "
            + ", ".join(item.value for item in OllamaEndpointMode)
        ) from exc


def _as_tuple(value: tuple[str, ...] | list[str] | None, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (tuple, list)) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    result = tuple(item.strip() for item in value)
    if any(not item for item in result):
        raise ValueError(f"{name} must not contain empty values")
    return result


@dataclass(frozen=True, slots=True)
class OllamaEndpointPolicy:
    """Explicit security policy shared by every Ollama integration.

    Attestations use canonical JSON over every field except ``signature``,
    signed with Ed25519, and verified by ``attestation_public_key``. The
    complete format is documented in ``docs/OLLAMA_ENDPOINT_SECURITY.md``.
    """

    mode: OllamaEndpointMode | str = OllamaEndpointMode.LOCAL_ONLY
    endpoint: str | None = None
    insecure_tls: bool = False
    accept_remote_risk: bool = False
    ca_bundle: str | Path | None = None
    spki_pins: tuple[str, ...] | list[str] = field(default_factory=tuple)
    certificate_pins: tuple[str, ...] | list[str] = field(default_factory=tuple)
    client_cert: str | Path | None = None
    client_key: str | Path | None = None
    attestation: str | Path | Mapping[str, Any] | None = None
    attestation_public_key: str | Path | bytes | None = None
    expected_deployment_id: str | None = None
    clock_skew_seconds: float = 60.0

    @classmethod
    def from_environment(cls) -> "OllamaEndpointPolicy":
        """Build the explicit policy from CARETAKER_OLLAMA_* variables.

        An unset environment produces the safe local-only default.  This is
        intentionally a small adapter; configuration files and Python callers
        should prefer constructing this policy directly.
        """
        values: dict[str, Any] = {}
        names = {
            "mode": "CARETAKER_OLLAMA_ENDPOINT_MODE",
            "endpoint": "CARETAKER_OLLAMA_ENDPOINT",
            "ca_bundle": "CARETAKER_OLLAMA_CA_BUNDLE",
            "client_cert": "CARETAKER_OLLAMA_CLIENT_CERT",
            "client_key": "CARETAKER_OLLAMA_CLIENT_KEY",
            "attestation": "CARETAKER_OLLAMA_ATTESTATION",
            "attestation_public_key": "CARETAKER_OLLAMA_ATTESTATION_PUBLIC_KEY",
            "expected_deployment_id": "CARETAKER_OLLAMA_DEPLOYMENT_ID",
        }
        for field_name, env_name in names.items():
            if os.environ.get(env_name):
                values[field_name] = os.environ[env_name]
        for field_name, env_name in (
            ("insecure_tls", "CARETAKER_OLLAMA_INSECURE_TLS"),
            ("accept_remote_risk", "CARETAKER_OLLAMA_ACCEPT_REMOTE_RISK"),
        ):
            if env_name in os.environ:
                raw = os.environ[env_name].strip().lower()
                if raw not in {"true", "false"}:
                    raise ValueError(f"{env_name} must be true or false")
                values[field_name] = raw == "true"
        for field_name, env_name in (
            ("spki_pins", "CARETAKER_OLLAMA_SPKI_PINS"),
            ("certificate_pins", "CARETAKER_OLLAMA_CERTIFICATE_PINS"),
        ):
            if env_name in os.environ:
                values[field_name] = tuple(item.strip() for item in os.environ[env_name].split(","))
        return cls(**values)

    def __post_init__(self) -> None:
        mode = _as_mode(self.mode)
        object.__setattr__(self, "mode", mode)
        if self.endpoint is not None:
            normalized_endpoint = _canonical_endpoint(str(self.endpoint))
            parsed_endpoint = urlparse(normalized_endpoint)
            if mode is OllamaEndpointMode.LOCAL_ONLY and not _is_loopback(parsed_endpoint.hostname or ""):
                raise ValueError("local_only Ollama policy endpoint must be loopback")
            if mode in {
                OllamaEndpointMode.REMOTE_SERVER_VERIFIED,
                OllamaEndpointMode.REMOTE_ATTESTED,
            } and parsed_endpoint.scheme != "https":
                raise ValueError(f"{mode.value} requires an HTTPS endpoint")
            object.__setattr__(self, "endpoint", normalized_endpoint)
        for name in ("insecure_tls", "accept_remote_risk"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"ollama {name} must be a boolean")
        if mode is OllamaEndpointMode.REMOTE_UNVERIFIED and not self.accept_remote_risk:
            raise ValueError(
                "remote_unverified requires accept_remote_risk=True; the remote service may be impersonated, modified, monitored, or unavailable"
            )
        if mode is not OllamaEndpointMode.REMOTE_UNVERIFIED and self.insecure_tls:
            raise ValueError("insecure_tls is permitted only with remote_unverified")
        if (self.client_cert is None) != (self.client_key is None):
            raise ValueError("ollama client_cert and client_key must be supplied together")
        for name in ("ca_bundle", "client_cert", "client_key"):
            value = getattr(self, name)
            if value is not None and not str(value).strip():
                raise ValueError(f"ollama {name} must not be empty")
        object.__setattr__(self, "spki_pins", _as_tuple(self.spki_pins, "ollama spki_pins"))
        object.__setattr__(self, "certificate_pins", _as_tuple(self.certificate_pins, "ollama certificate_pins"))
        if mode is OllamaEndpointMode.REMOTE_ATTESTED and (
            self.attestation is None or self.attestation_public_key is None
        ):
            raise ValueError("remote_attested requires ollama attestation and attestation_public_key")
        if self.expected_deployment_id is not None and not str(self.expected_deployment_id).strip():
            raise ValueError("ollama expected_deployment_id must not be empty")
        if (
            isinstance(self.clock_skew_seconds, bool)
            or not isinstance(self.clock_skew_seconds, (int, float))
            or self.clock_skew_seconds < 0
            or not __import__("math").isfinite(float(self.clock_skew_seconds))
        ):
            raise ValueError("ollama clock_skew_seconds must be a finite non-negative number")

    def status(self, endpoint: str, *, certificate: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Return a secret-free machine-readable endpoint status."""
        scheme = urlparse(endpoint).scheme
        tls = "NOT_APPLICABLE"
        if scheme == "https":
            tls = "DISABLED" if self.insecure_tls else (
                "SYSTEM_OR_CUSTOM_CA" if self.mode is not OllamaEndpointMode.LOCAL_ONLY else "SYSTEM_DEFAULT"
            )
        result: dict[str, Any] = {
            "mode": self.mode.value,
            "status": {
                OllamaEndpointMode.LOCAL_ONLY: "LOCAL_ONLY",
                OllamaEndpointMode.REMOTE_UNVERIFIED: "REMOTE_UNVERIFIED",
                OllamaEndpointMode.REMOTE_SERVER_VERIFIED: "REMOTE_SERVER_VERIFIED",
                OllamaEndpointMode.REMOTE_ATTESTED: "REMOTE_ATTESTED",
            }[self.mode],
            "canonical_endpoint": endpoint,
            "tls_verification": tls,
            "custom_ca_bundle": self.ca_bundle is not None,
            "pinning_configured": bool(self.spki_pins or self.certificate_pins),
            "client_certificate_configured": self.client_cert is not None,
            "attestation_configured": self.attestation is not None,
            "advisory_only": True,
        }
        if self.mode is OllamaEndpointMode.REMOTE_UNVERIFIED:
            result["warnings"] = [
                "REMOTE_UNVERIFIED: the remote service may be impersonated, modified, monitored, or unavailable",
                "remote model output remains untrusted advisory input",
            ]
            if self.insecure_tls:
                result["warnings"].append("TLS certificate verification is disabled")
        elif self.mode is not OllamaEndpointMode.LOCAL_ONLY:
            result["warnings"] = [
                "TLS endpoint identity does not independently prove the intended Ollama process or model"
            ]
        else:
            result["warnings"] = []
        if certificate:
            if scheme == "https" and self.mode in {
                OllamaEndpointMode.REMOTE_SERVER_VERIFIED,
                OllamaEndpointMode.REMOTE_ATTESTED,
            }:
                result["tls_verification"] = "VERIFIED"
            elif scheme == "https" and self.mode is OllamaEndpointMode.REMOTE_UNVERIFIED and not self.insecure_tls:
                result["tls_verification"] = "ENABLED_NOT_TRUSTED"
            for key in ("subject", "san", "issuer", "certificate_sha256", "spki_sha256"):
                if certificate.get(key) is not None:
                    result[key] = certificate[key]
        return result

    def ssl_context(self) -> ssl.SSLContext | None:
        if self.mode is OllamaEndpointMode.LOCAL_ONLY and self.ca_bundle is None and self.client_cert is None:
            return None
        context = ssl.create_default_context(cafile=str(self.ca_bundle) if self.ca_bundle else None)
        if self.insecure_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if self.client_cert is not None:
            context.load_cert_chain(str(self.client_cert), keyfile=str(self.client_key))
        return context

    def verify_attestation(
        self,
        endpoint: str,
        *,
        model: str,
        purpose: str,
        certificate: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> None:
        if self.mode is not OllamaEndpointMode.REMOTE_ATTESTED:
            return
        assertion = _load_attestation(self.attestation)
        _verify_attestation_signature(assertion, self.attestation_public_key)
        required = {
            "format_version", "endpoint", "deployment_id", "model", "provider_purpose",
            "attesting_operator", "issued_at", "expires_at", "signature",
        }
        if not required <= set(assertion):
            raise ProviderResponseError("Ollama attestation is missing required fields")
        if not assertion.get("certificate_sha256") and not assertion.get("spki_sha256"):
            raise ProviderResponseError(
                "Ollama attestation must bind a certificate_sha256 or spki_sha256"
            )
        if assertion.get("format_version") != 1:
            raise ProviderResponseError("Ollama attestation format_version is unsupported")
        now = datetime.now(timezone.utc).timestamp()
        issued = _timestamp(assertion["issued_at"], "issued_at")
        expires = _timestamp(assertion["expires_at"], "expires_at")
        skew = float(self.clock_skew_seconds)
        if issued > now + skew or expires <= now - skew or expires <= issued:
            raise ProviderResponseError("Ollama attestation is expired, stale, or not yet valid")
        if _canonical_endpoint(str(assertion["endpoint"])) != endpoint:
            raise ProviderResponseError("Ollama attestation endpoint does not match")
        if self.expected_deployment_id and assertion["deployment_id"] != self.expected_deployment_id:
            raise ProviderResponseError("Ollama attestation deployment does not match")
        if assertion["model"] != model:
            raise ProviderResponseError("Ollama attestation model does not match")
        if assertion["provider_purpose"] != purpose:
            raise ProviderResponseError("Ollama attestation provider purpose does not match")
        for assertion_key, certificate_key in (("certificate_sha256", "certificate_sha256"), ("spki_sha256", "spki_sha256")):
            expected = assertion.get(assertion_key)
            if expected is not None and str(expected).lower() != str(certificate.get(certificate_key, "")).lower():
                raise ProviderResponseError(f"Ollama attestation {assertion_key} does not match endpoint certificate")
        digest = assertion.get("model_digest")
        returned = response.get("model_digest") or response.get("digest")
        model_identity = assertion.get("model_identity")
        if digest is None and model_identity is None:
            raise ProviderResponseError("Ollama attestation requires model_digest or model_identity")
        if digest is not None and (returned is None or str(returned) != str(digest)):
            raise ProviderResponseError("Ollama attestation model digest does not match")


def _canonical_endpoint(url: str) -> str:
    normalized = url.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("provider endpoint must be an http(s) URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("provider endpoints must not contain credentials")
    return normalized


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_endpoint_policy(
    endpoint_policy: OllamaEndpointPolicy | None = None,
    *,
    allow_remote_endpoint: bool | None = None,
) -> OllamaEndpointPolicy:
    """Resolve the shared policy, retaining a temporary deprecated shim."""
    if endpoint_policy is not None and not isinstance(endpoint_policy, OllamaEndpointPolicy):
        raise TypeError("endpoint_policy must be an OllamaEndpointPolicy")
    if allow_remote_endpoint is not None:
        if not isinstance(allow_remote_endpoint, bool):
            raise ValueError("allow_remote_endpoint must be a boolean")
        warnings.warn(
            "allow_remote_endpoint is deprecated; pass OllamaEndpointPolicy explicitly",
            DeprecationWarning,
            stacklevel=3,
        )
        compatibility = (
            OllamaEndpointPolicy(mode=OllamaEndpointMode.REMOTE_UNVERIFIED, accept_remote_risk=True)
            if allow_remote_endpoint else OllamaEndpointPolicy()
        )
        if endpoint_policy is not None and endpoint_policy != compatibility:
            raise ValueError("endpoint_policy and deprecated allow_remote_endpoint conflict")
        return compatibility
    return endpoint_policy or OllamaEndpointPolicy.from_environment()


def endpoint_policy_from_mapping(values: Mapping[str, Any] | None) -> OllamaEndpointPolicy:
    """Parse policy-file/control-request fields without accepting aliases silently."""
    data = dict(values or {})
    for source, target in (
        ("endpoint_mode", "mode"), ("ollama_endpoint_mode", "mode"),
        ("ollama_endpoint", "endpoint"), ("ollama_ca_bundle", "ca_bundle"),
        ("ollama_spki_pins", "spki_pins"),
        ("ollama_certificate_pins", "certificate_pins"),
        ("ollama_client_cert", "client_cert"), ("ollama_client_key", "client_key"),
        ("ollama_attestation", "attestation"),
        ("ollama_attestation_public_key", "attestation_public_key"),
    ):
        if source in data and target not in data:
            data[target] = data.pop(source)
    allowed = {
        "mode", "endpoint", "insecure_tls", "accept_remote_risk", "ca_bundle", "spki_pins",
        "certificate_pins", "client_cert", "client_key", "attestation",
        "attestation_public_key", "expected_deployment_id", "clock_skew_seconds",
    }
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError("unknown Ollama endpoint policy fields: " + ", ".join(unknown))
    return OllamaEndpointPolicy(**data)


def validate_provider_endpoint(
    url: str,
    *,
    endpoint_policy: OllamaEndpointPolicy | None = None,
    allow_remote_endpoint: bool | None = None,
) -> str:
    """Validate an Ollama endpoint under one explicit endpoint policy."""
    policy = resolve_endpoint_policy(endpoint_policy, allow_remote_endpoint=allow_remote_endpoint)
    normalized = _canonical_endpoint(url)
    parsed = urlparse(normalized)
    if policy.mode is OllamaEndpointMode.LOCAL_ONLY and not _is_loopback(parsed.hostname or ""):
        raise ValueError(
            "remote provider endpoints are rejected in local_only; allow_remote_endpoint is deprecated, select remote_unverified explicitly"
        )
    if policy.mode in {OllamaEndpointMode.REMOTE_SERVER_VERIFIED, OllamaEndpointMode.REMOTE_ATTESTED} and parsed.scheme != "https":
        raise ValueError(f"{policy.mode.value} requires an HTTPS endpoint")
    if policy.mode is OllamaEndpointMode.REMOTE_UNVERIFIED:
        warning = "REMOTE_UNVERIFIED Ollama endpoint selected; the remote service may be impersonated, modified, monitored, or unavailable"
        warnings.warn(warning, RuntimeWarning, stacklevel=3)
        _LOG.warning("%s endpoint=%s", warning, normalized)
    return normalized


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, *, endpoint_policy: OllamaEndpointPolicy, origin: tuple[str, str, int | None]) -> None:
        super().__init__()
        self.endpoint_policy = endpoint_policy
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        normalized = validate_provider_endpoint(newurl, endpoint_policy=self.endpoint_policy)
        parsed = urlparse(normalized)
        if (parsed.scheme, (parsed.hostname or "").lower(), parsed.port) != self.origin:
            raise ProviderResponseError("provider redirect changes origin and was rejected")
        return super().redirect_request(req, fp, code, msg, headers, normalized)


def _certificate_details(response: Any) -> dict[str, Any]:
    details: dict[str, Any] = {}
    try:
        der = response.fp.raw._sock.getpeercert(binary_form=True)
    except (AttributeError, OSError, TypeError):
        return details
    if not der:
        return details
    details["certificate_sha256"] = hashlib.sha256(der).hexdigest()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        certificate = x509.load_der_x509_certificate(der)
        details["subject"] = certificate.subject.rfc4514_string()
        details["issuer"] = certificate.issuer.rfc4514_string()
        details["san"] = [name.value for name in certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        public_key = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        details["spki_sha256"] = hashlib.sha256(public_key).hexdigest()
    except Exception:
        pass
    return details


def _pin_matches(value: str, pins: tuple[str, ...]) -> bool:
    normalized = value.lower().removeprefix("sha256:")
    return any(pin.lower().removeprefix("sha256:") == normalized for pin in pins)


def _load_attestation(value: str | Path | Mapping[str, Any] | None) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if value is None:
        raise ProviderResponseError("Ollama attestation is not configured")
    try:
        loaded = json.loads(
            Path(value).read_text(encoding="utf-8"),
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ProviderResponseError("Ollama attestation could not be read") from exc
    if not isinstance(loaded, dict):
        raise ProviderResponseError("Ollama attestation must be a JSON object")
    return loaded


def _load_public_key(value: str | Path | bytes | None) -> Any:
    if value is None:
        raise ProviderResponseError("Ollama attestation public key is not configured")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ProviderResponseError("Ed25519 attestation verification requires cryptography") from exc
    raw: str | bytes = value
    if isinstance(value, (str, Path)):
        path = Path(value)
        raw = path.read_bytes() if path.is_file() else str(value).encode("utf-8")
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    try:
        return serialization.load_pem_public_key(raw)
    except ValueError:
        try:
            return serialization.load_der_public_key(raw)
        except ValueError:
            try:
                if len(raw) == 32:
                    return Ed25519PublicKey.from_public_bytes(raw)
                return Ed25519PublicKey.from_public_bytes(base64.b64decode(raw, validate=True))
            except Exception as exc:
                raise ProviderResponseError("Ollama attestation public key is invalid") from exc


def _verify_attestation_signature(assertion: Mapping[str, Any], public_key: str | Path | bytes | None) -> None:
    signature_value = assertion.get("signature")
    if not isinstance(signature_value, str):
        raise ProviderResponseError("Ollama attestation signature is missing")
    try:
        signature = base64.b64decode(signature_value, validate=True)
        payload = {key: value for key, value in assertion.items() if key != "signature"}
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        _load_public_key(public_key).verify(signature, encoded)
    except Exception as exc:
        raise ProviderResponseError("Ollama attestation signature is invalid") from exc


def _timestamp(value: Any, name: str) -> float:
    if not isinstance(value, str):
        raise ProviderResponseError(f"Ollama attestation {name} is invalid")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except ValueError as exc:
        raise ProviderResponseError(f"Ollama attestation {name} is invalid") from exc


def provider_json_response(
    request: urllib.request.Request,
    *,
    endpoint_policy: OllamaEndpointPolicy | None = None,
    allow_remote_endpoint: bool | None = None,
    timeout_seconds: float,
    maximum_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
    expected_model: str | None = None,
    expected_provider_purpose: str | None = None,
    security_status: MutableMapping[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Fetch bounded strict JSON with TLS, pin, and attestation checks."""
    policy = resolve_endpoint_policy(endpoint_policy, allow_remote_endpoint=allow_remote_endpoint)
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be a positive integer")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a finite positive number")
    endpoint = validate_provider_endpoint(request.full_url, endpoint_policy=policy)
    parsed = urlparse(endpoint)
    origin = (parsed.scheme, (parsed.hostname or "").lower(), parsed.port)
    handlers: list[Any] = [_ValidatedRedirectHandler(endpoint_policy=policy, origin=origin)]
    context = policy.ssl_context()
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            certificate = _certificate_details(response)
            if policy.mode in {OllamaEndpointMode.REMOTE_SERVER_VERIFIED, OllamaEndpointMode.REMOTE_ATTESTED}:
                if policy.spki_pins and not _pin_matches(str(certificate.get("spki_sha256", "")), policy.spki_pins):
                    raise ProviderResponseError("Ollama SPKI pin does not match endpoint certificate")
                if policy.certificate_pins and not _pin_matches(str(certificate.get("certificate_sha256", "")), policy.certificate_pins):
                    raise ProviderResponseError("Ollama certificate pin does not match endpoint certificate")
            raw = response.read(maximum_bytes + 1)
    except ProviderResponseError:
        raise
    except urllib.error.HTTPError as exc:
        raise ProviderResponseError(f"provider request failed: HTTP {exc.code}") from exc
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as exc:
        raise ProviderResponseError(f"provider request failed: {type(exc).__name__}") from exc
    if len(raw) > maximum_bytes:
        raise ProviderResponseError("provider response exceeds the configured byte limit")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderResponseError("provider response was not strict JSON") from exc
    if not isinstance(value, dict):
        raise ProviderResponseError("provider response must be a JSON object")
    actual_model = value.get("model")
    if expected_model is not None and actual_model is not None and actual_model != expected_model:
        raise ProviderResponseError("provider response model does not match the requested model")
    if expected_model is not None and policy.mode is OllamaEndpointMode.REMOTE_ATTESTED:
        policy.verify_attestation(
            endpoint,
            model=expected_model,
            purpose=expected_provider_purpose or "unknown",
            certificate=certificate,
            response=value,
        )
    if security_status is not None:
        security_status.clear()
        security_status.update(policy.status(endpoint, certificate=certificate))
        if policy.mode is OllamaEndpointMode.REMOTE_ATTESTED:
            security_status["attestation_valid"] = True
    return value, text
