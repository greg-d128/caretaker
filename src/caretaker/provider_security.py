from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from urllib.parse import urlparse
from typing import Any


MAX_PROVIDER_RESPONSE_BYTES = 256 * 1024


class ProviderResponseError(ValueError):
    """Raised when an advisory provider response violates its transport contract."""


def validate_provider_endpoint(url: str, *, allow_remote_endpoint: bool) -> str:
    """Validate an LLM-provider endpoint and return a normalized URL.

    Caretaker treats provider responses as untrusted. By default the built-in
    Ollama clients also restrict the transport endpoint to loopback so another
    network host cannot silently become part of the repair trust path.
    """
    normalized = url.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("provider endpoint must be an http(s) URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("provider endpoints must not contain credentials")
    if allow_remote_endpoint:
        return normalized
    host = parsed.hostname
    if host == "localhost":
        return normalized
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "remote provider endpoints require allow_remote_endpoint=True"
        ) from exc
    if not address.is_loopback:
        raise ValueError("remote provider endpoints require allow_remote_endpoint=True")
    return normalized


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, *, allow_remote_endpoint: bool) -> None:
        super().__init__()
        self.allow_remote_endpoint = allow_remote_endpoint

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_provider_endpoint(
            newurl, allow_remote_endpoint=self.allow_remote_endpoint
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def provider_json_response(
    request: urllib.request.Request,
    *,
    allow_remote_endpoint: bool,
    timeout_seconds: float,
    maximum_bytes: int = MAX_PROVIDER_RESPONSE_BYTES,
) -> tuple[dict[str, Any], str]:
    """Fetch one bounded strict-JSON provider response with validated redirects."""
    if isinstance(maximum_bytes, bool) or not isinstance(maximum_bytes, int) or maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be a positive integer")
    opener = urllib.request.build_opener(
        _ValidatedRedirectHandler(allow_remote_endpoint=allow_remote_endpoint)
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            raw = response.read(maximum_bytes + 1)
    except urllib.error.HTTPError as exc:
        raise ProviderResponseError(f"provider request failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ProviderResponseError(f"provider request failed: {exc}") from exc
    if len(raw) > maximum_bytes:
        raise ProviderResponseError("provider response exceeds the configured byte limit")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {token} is not permitted")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderResponseError("provider response was not strict JSON") from exc
    if not isinstance(value, dict):
        raise ProviderResponseError("provider response must be a JSON object")
    return value, text
