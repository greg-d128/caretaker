from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


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
