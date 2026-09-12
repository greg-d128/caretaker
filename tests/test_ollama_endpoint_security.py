from __future__ import annotations

import base64
import hashlib
import json
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from caretaker import OllamaEndpointMode, OllamaEndpointPolicy, ProviderResponseError
from caretaker.behavior import OllamaBehaviorSnapshotAnalyst
from caretaker.capsule_assistance import IncidentCapsuleAssistant
from caretaker.communications import CommunicationDraftAssistant
from caretaker.guard.provider import OllamaBehaviorAssessmentProvider
from caretaker.logging.policy import load_operator_policy
from caretaker.logging.interrogation import OllamaRootCauseProvider
from caretaker.provider import OllamaRepairProvider
from caretaker.provider_security import (
    _ValidatedRedirectHandler,
    provider_json_response,
    validate_provider_endpoint,
)
from urllib.request import Request


class _OllamaHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(size)
        body = json.dumps({"model": "security-model", "model_digest": "sha256:model-1", "response": "{}"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


def _server(*, tls: bool = False, certificate: Path | None = None, key: Path | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OllamaHandler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, keyfile=key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    scheme = "https" if tls else "http"
    endpoint = f"{scheme}://localhost:{server.server_port}/api/generate"
    return server, thread, endpoint


def _certificate(
    tmp_path: Path, *, name: str = "localhost", expired: bool = False
) -> tuple[Path, Path, bytes]:
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=2 if expired else 0, minutes=1)
        )
        .not_valid_after(
            datetime.now(timezone.utc) - timedelta(days=1)
            if expired
            else datetime.now(timezone.utc) + timedelta(days=2)
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.DER)
    cert_path = tmp_path / f"{name}.crt"
    key_path = tmp_path / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path, cert_bytes


def test_modes_and_explicit_remote_risk() -> None:
    assert validate_provider_endpoint("http://127.0.0.1:11434", endpoint_policy=OllamaEndpointPolicy())
    with pytest.raises(ValueError, match="local_only"):
        validate_provider_endpoint("http://remote.example/api", endpoint_policy=OllamaEndpointPolicy())
    with pytest.raises(ValueError, match="accept_remote_risk"):
        OllamaEndpointPolicy(mode=OllamaEndpointMode.REMOTE_UNVERIFIED)
    with pytest.warns(RuntimeWarning, match="REMOTE_UNVERIFIED"):
        policy = OllamaEndpointPolicy(
            mode=OllamaEndpointMode.REMOTE_UNVERIFIED,
            accept_remote_risk=True,
        )
        validate_provider_endpoint("http://remote.example/api", endpoint_policy=policy)
    insecure = OllamaEndpointPolicy(
        mode=OllamaEndpointMode.REMOTE_UNVERIFIED,
        accept_remote_risk=True,
        insecure_tls=True,
    )
    assert any("disabled" in item for item in insecure.status("https://remote.example")["warnings"])
    with pytest.raises(ValueError, match="remote_unverified"):
        OllamaEndpointPolicy(mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED, insecure_tls=True)


def test_supervisor_policy_file_loads_shared_endpoint_policy(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.toml"
    policy_file.write_text(
        """
[logging.ollama]
endpoint_mode = "remote_server_verified"
endpoint = "https://ollama.example.internal/api/generate"
ca_bundle = "ca.pem"
spki_pins = ["old", "new"]
""",
        encoding="utf-8",
    )
    policy, _snapshot = load_operator_policy(policy_file)
    assert policy.ollama.mode is OllamaEndpointMode.REMOTE_SERVER_VERIFIED
    assert policy.ollama.endpoint == "https://ollama.example.internal/api/generate"
    assert policy.ollama.ca_bundle == str(tmp_path / "ca.pem")
    assert policy.ollama.spki_pins == ("old", "new")


def test_every_ollama_consumer_uses_local_only_by_default() -> None:
    constructors = (
        lambda: OllamaRepairProvider("model", base_url="http://remote.example"),
        lambda: OllamaBehaviorAssessmentProvider("model", base_url="http://remote.example"),
        lambda: OllamaBehaviorSnapshotAnalyst("model", endpoint="http://remote.example/api/generate"),
        lambda: OllamaRootCauseProvider(model="model", endpoint="http://remote.example/api/generate"),
        lambda: IncidentCapsuleAssistant(model="model", endpoint="http://remote.example/api/generate"),
        lambda: CommunicationDraftAssistant(
            model="model", endpoint="http://remote.example/api/generate", maximum_text_characters=1000
        ),
    )
    for constructor in constructors:
        with pytest.raises(ValueError, match="local_only"):
            constructor()


def test_remote_http_fake_endpoint_is_allowed_only_when_selected() -> None:
    server, thread, endpoint = _server()
    try:
        request = Request(endpoint, data=b"{}", method="POST")
        policy = OllamaEndpointPolicy(
            mode=OllamaEndpointMode.REMOTE_UNVERIFIED,
            accept_remote_risk=True,
        )
        with pytest.warns(RuntimeWarning):
            value, _ = provider_json_response(
                request, endpoint_policy=policy, timeout_seconds=3, expected_model="security-model"
            )
        assert value["model"] == "security-model"
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_remote_server_verified_accepts_private_ca_and_rejects_untrusted(tmp_path: Path) -> None:
    cert_path, key_path, der = _certificate(tmp_path)
    server, thread, endpoint = _server(tls=True, certificate=cert_path, key=key_path)
    try:
        request = Request(endpoint, data=b"{}", method="POST")
        verified = OllamaEndpointPolicy(
            mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED, ca_bundle=cert_path
        )
        value, _ = provider_json_response(
            request, endpoint_policy=verified, timeout_seconds=3, expected_model="security-model"
        )
        assert value["model"] == "security-model"
        overlap = OllamaEndpointPolicy(
            mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED,
            ca_bundle=cert_path,
            certificate_pins=(hashlib.sha256(der).hexdigest(), "00" * 32),
        )
        provider_json_response(
            request, endpoint_policy=overlap, timeout_seconds=3, expected_model="security-model"
        )
        with pytest.raises(ProviderResponseError, match="pin"):
            provider_json_response(
                request,
                endpoint_policy=OllamaEndpointPolicy(
                    mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED,
                    ca_bundle=cert_path,
                    certificate_pins=("00" * 32,),
                ),
                timeout_seconds=3,
                expected_model="security-model",
            )
        with pytest.raises(ProviderResponseError):
            provider_json_response(
                request,
                endpoint_policy=OllamaEndpointPolicy(mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED),
                timeout_seconds=3,
                expected_model="security-model",
            )
    finally:
        server.shutdown()
        thread.join(timeout=3)


@pytest.mark.parametrize("certificate_name,expired", [("otherhost", False), ("localhost", True)])
def test_remote_server_verified_rejects_hostname_mismatch_and_expiry(
    tmp_path: Path, certificate_name: str, expired: bool
) -> None:
    cert_path, key_path, _der = _certificate(
        tmp_path, name=certificate_name, expired=expired
    )
    server, thread, endpoint = _server(tls=True, certificate=cert_path, key=key_path)
    try:
        with pytest.raises(ProviderResponseError):
            provider_json_response(
                Request(endpoint, data=b"{}", method="POST"),
                endpoint_policy=OllamaEndpointPolicy(
                    mode=OllamaEndpointMode.REMOTE_SERVER_VERIFIED, ca_bundle=cert_path
                ),
                timeout_seconds=3,
                expected_model="security-model",
            )
    finally:
        server.shutdown()
        thread.join(timeout=3)


def test_cross_origin_redirect_is_rejected() -> None:
    handler = _ValidatedRedirectHandler(
        endpoint_policy=OllamaEndpointPolicy(
            mode=OllamaEndpointMode.REMOTE_UNVERIFIED,
            accept_remote_risk=True,
        ),
        origin=("http", "example.test", 80),
    )
    with pytest.raises(ProviderResponseError, match="origin"):
        handler.redirect_request(
            Request("http://example.test/api"), None, 302, "Found", {},
            "http://attacker.test/api",
        )


def test_remote_attested_requires_and_verifies_operator_assertion(tmp_path: Path) -> None:
    cert_path, key_path, der = _certificate(tmp_path)
    server, thread, endpoint = _server(tls=True, certificate=cert_path, key=key_path)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signing_key = Ed25519PrivateKey.generate()
        public_path = tmp_path / "attestation.pub"
        public_path.write_bytes(
            signing_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
        assertion = {
            "format_version": 1,
            "endpoint": endpoint,
            "deployment_id": "deployment-1",
            "model": "security-model",
            "model_digest": "sha256:model-1",
            "provider_purpose": "repair",
            "attesting_operator": "operator@example",
            "issued_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "certificate_sha256": hashlib.sha256(der).hexdigest(),
        }
        encoded = json.dumps(assertion, sort_keys=True, separators=(",", ":")).encode()
        assertion["signature"] = base64.b64encode(signing_key.sign(encoded)).decode()
        attestation_path = tmp_path / "attestation.json"
        attestation_path.write_text(json.dumps(assertion), encoding="utf-8")
        policy = OllamaEndpointPolicy(
            mode=OllamaEndpointMode.REMOTE_ATTESTED,
            ca_bundle=cert_path,
            attestation=attestation_path,
            attestation_public_key=public_path,
        )
        status = {}
        value, _ = provider_json_response(
            Request(endpoint, data=b"{}", method="POST"),
            endpoint_policy=policy,
            timeout_seconds=3,
            expected_model="security-model",
            expected_provider_purpose="repair",
            security_status=status,
        )
        assert value["model"] == "security-model"
        assert status["status"] == "REMOTE_ATTESTED"
        assert status["attestation_valid"] is True
    finally:
        server.shutdown()
        thread.join(timeout=3)
