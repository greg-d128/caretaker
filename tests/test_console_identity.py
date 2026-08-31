from __future__ import annotations

import base64
import hashlib

import pytest

from caretaker.console import ConsoleInvocationIdentity
from caretaker.console_identity import ConsoleIdentityStore, normalize_console_public_identity


def _identity() -> dict[str, str]:
    public_key = b"p" * 32
    encoded = base64.b64encode(public_key).decode("ascii")
    return {
        "identity_id": "00000000-0000-0000-0000-000000000001",
        "algorithm": "ed25519",
        "encoding": "base64",
        "public_key": encoded,
        "public_key_fingerprint": hashlib.sha256(public_key).hexdigest(),
    }


def test_console_identity_store_retains_public_key_and_session_lifecycle(tmp_path):
    store = ConsoleIdentityStore(tmp_path)
    identity = _identity()
    started = store.record_start(
        "00000000-0000-0000-0000-000000000002",
        identity=identity,
        process_id=123,
        uid=1000,
        gid=1000,
    )
    assert started["public_key"] == identity["public_key"]
    assert store.get(started["invocation_id"])["ended_at"] is None
    ended = store.record_end(started["invocation_id"], process_id=123)
    assert ended["ended_at"] is not None
    assert ended["public_key_fingerprint"] == identity["public_key_fingerprint"]


def test_console_identity_rejects_private_material_and_wrong_fingerprint():
    identity = _identity()
    with pytest.raises(ValueError, match="private key"):
        normalize_console_public_identity({**identity, "private_key": "must-not-leave-memory"})
    with pytest.raises(ValueError, match="fingerprint"):
        normalize_console_public_identity({**identity, "public_key_fingerprint": "bad"})


def test_console_identity_private_key_is_memory_only():
    identity = ConsoleInvocationIdentity.create()
    if identity is None:
        pytest.skip("cryptography signing extra is unavailable")
    public = identity.public_record()
    assert "private_key" not in public
    assert "_private_key" not in public
    identity.close()
    assert identity._private_key is None
