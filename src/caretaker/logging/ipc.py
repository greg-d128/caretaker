from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import queue
import stat
import tempfile
import socket
import struct
import threading
import time
import select
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable
from uuid import UUID

from .models import AttachmentReference, EvidencePriority, LogEnvelope
from .records import TLVLogCodec
from .segments import SegmentWriter


_PEERCRED = struct.Struct("3i")


_UNIX_SOCKET_PATH_LIMIT = 100
_CONTROL_REQUEST_LIMIT = 64 * 1024
_CONTROL_RESPONSE_LIMIT = 16 * 1024 * 1024


def _canonical_control_authorization_payload(request: dict[str, Any]) -> bytes:
    authorization = request.get("authorization")
    if not isinstance(authorization, dict):
        raise ValueError("control request authorization envelope is required")
    unsigned_authorization = {
        key: value for key, value in authorization.items() if key != "signature"
    }
    unsigned_request = {
        key: value for key, value in request.items() if key != "authorization"
    }
    return json.dumps(
        {"authorization": unsigned_authorization, "request": unsigned_request},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sign_control_request(
    request: dict[str, Any],
    secret: bytes,
    *,
    key_id: str,
    scope: str,
    policy_generation: int,
    nonce: str | None = None,
    issued_at: int | None = None,
) -> dict[str, Any]:
    """Add an independent operator authorization envelope to a request."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("control authorization secret must contain at least 32 bytes")
    if not key_id.strip() or not scope.strip():
        raise ValueError("control authorization key_id and scope cannot be empty")
    signed = dict(request)
    signed["authorization"] = {
        "key_id": key_id,
        "scope": scope,
        "policy_generation": policy_generation,
        "issued_at": int(time.time()) if issued_at is None else issued_at,
        "nonce": nonce or secrets.token_urlsafe(18),
    }
    signed["authorization"]["signature"] = hmac.new(
        secret,
        _canonical_control_authorization_payload(signed),
        hashlib.sha256,
    ).hexdigest()
    return signed


class HMACControlAuthorizer:
    """Verify independent, replay-protected operator command envelopes."""

    def __init__(
        self,
        secret: bytes,
        *,
        key_id: str,
        allowed_scopes: set[str] | frozenset[str] = frozenset({"*"}),
        policy_generation: int | None = None,
        maximum_clock_skew_seconds: int = 30,
        nonce_retention_seconds: int = 300,
    ) -> None:
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("control authorization secret must contain at least 32 bytes")
        if not key_id.strip():
            raise ValueError("control authorization key_id cannot be empty")
        if maximum_clock_skew_seconds <= 0 or nonce_retention_seconds <= 0:
            raise ValueError("authorization time windows must be positive")
        self.secret = secret
        self.key_id = key_id
        self.allowed_scopes = frozenset(allowed_scopes)
        self.policy_generation = policy_generation
        self.maximum_clock_skew_seconds = maximum_clock_skew_seconds
        self.nonce_retention_seconds = nonce_retention_seconds
        self._seen_nonces: dict[str, int] = {}
        self._lock = threading.Lock()

    def __call__(self, request: dict[str, Any], _credentials: tuple[int, int, int]) -> bool:
        if not isinstance(request, dict):
            return False
        authorization = request.get("authorization")
        if not isinstance(authorization, dict):
            return False
        required = {"key_id", "scope", "policy_generation", "issued_at", "nonce", "signature"}
        if set(authorization) != required:
            return False
        if authorization["key_id"] != self.key_id:
            return False
        scope = authorization["scope"]
        command = request.get("command")
        if not isinstance(scope, str) or not isinstance(command, str):
            return False
        if scope not in self.allowed_scopes and "*" not in self.allowed_scopes:
            return False
        if scope != "*" and scope != command:
            return False
        if self.policy_generation is not None and authorization["policy_generation"] != self.policy_generation:
            return False
        policy_generation = authorization["policy_generation"]
        if isinstance(policy_generation, bool) or not isinstance(policy_generation, int):
            return False
        issued_at = authorization["issued_at"]
        nonce = authorization["nonce"]
        signature = authorization["signature"]
        if isinstance(issued_at, bool) or not isinstance(issued_at, int):
            return False
        if not isinstance(nonce, str) or not nonce or len(nonce) > 256:
            return False
        if not isinstance(signature, str) or len(signature) != 64:
            return False
        try:
            provided = bytes.fromhex(signature)
        except ValueError:
            return False
        now = int(time.time())
        if abs(now - issued_at) > self.maximum_clock_skew_seconds:
            return False
        try:
            expected = hmac.new(
                self.secret,
                _canonical_control_authorization_payload(request),
                hashlib.sha256,
            ).digest()
        except (TypeError, ValueError, OverflowError):
            return False
        if not hmac.compare_digest(provided, expected):
            return False
        with self._lock:
            cutoff = now - self.nonce_retention_seconds
            self._seen_nonces = {
                value: timestamp
                for value, timestamp in self._seen_nonces.items()
                if timestamp >= cutoff
            }
            if nonce in self._seen_nonces:
                return False
            self._seen_nonces[nonce] = now
        return True


def unix_socket_path(path: str | Path) -> Path:
    """Return a bindable pathname for a Unix-domain socket.

    Unix-domain socket pathnames have a small platform limit (108 bytes on
    Linux, including the terminating NUL).  Caretaker data directories can
    legitimately live much deeper than that.  Keep short requested paths
    unchanged; for long paths, place only the ephemeral socket under a
    private per-user runtime directory using a deterministic hash of the
    requested parent directory.

    The persistent Caretaker data/evidence directory is never relocated.
    """
    requested = Path(path).expanduser()
    absolute = Path(os.path.abspath(os.fspath(requested)))
    if len(os.fsencode(os.fspath(absolute))) <= _UNIX_SOCKET_PATH_LIMIT:
        return absolute

    runtime_root = _private_ipc_root()
    parent_key = hashlib.sha256(
        os.fsencode(os.fspath(absolute.parent))
    ).hexdigest()[:16]
    socket_dir = runtime_root / parent_key
    socket_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    os.chmod(socket_dir, 0o700)
    return socket_dir / absolute.name


def unix_socket_exists(path: str | Path) -> bool:
    """Return whether the physical socket corresponding to *path* exists."""
    return unix_socket_path(path).exists()


def _private_ipc_root() -> Path:
    uid = os.getuid() if hasattr(os, "getuid") else 0
    candidates: list[Path] = []
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        candidates.append(Path(xdg_runtime) / "caretaker")
    candidates.append(Path(tempfile.gettempdir()) / f"caretaker-{uid}")

    last_error: OSError | None = None
    for root in candidates:
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            metadata = root.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError(f"Caretaker IPC runtime path is not a directory: {root}")
            if hasattr(os, "getuid") and metadata.st_uid != uid:
                raise PermissionError(
                    f"Caretaker IPC runtime directory is not owned by uid {uid}: {root}"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                os.chmod(root, 0o700)
            probe = root / ("x" * 16) / "control.sock"
            if len(os.fsencode(os.fspath(probe))) <= _UNIX_SOCKET_PATH_LIMIT:
                return root
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError("Unable to create a short private Caretaker IPC runtime directory")


def peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    """Return (pid, uid, gid) for a local Unix-domain peer on Linux."""
    if not hasattr(socket, "SO_PEERCRED"):
        return (-1, -1, -1)
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size)
    return _PEERCRED.unpack(raw)


class SocketLogClient:
    def __init__(self, path: str | Path, *, codec: TLVLogCodec | None = None, timeout: float = 1.0) -> None:
        self.path = str(unix_socket_path(path))
        self.codec = codec or TLVLogCodec()
        socket_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_STREAM)
        self.socket = socket.socket(socket.AF_UNIX, socket_type)
        self.socket.settimeout(timeout)
        self.socket.connect(self.path)
        self._stream = socket_type == socket.SOCK_STREAM
        self._lock = threading.RLock()

    def _send_packet(self, packet: bytes) -> None:
        if self._stream:
            self.socket.sendall(len(packet).to_bytes(4, "big") + packet)
        else:
            self.socket.sendall(packet)

    def _recv_packet(self, maximum: int = 1024 * 1024) -> bytes:
        if self._stream:
            length_data = _recv_exact(self.socket, 4)
            return _recv_exact(self.socket, int.from_bytes(length_data, "big"))
        return self.socket.recv(maximum)

    def write(self, envelope: LogEnvelope) -> None:
        record = b"E" + self.codec.encode(envelope)
        with self._lock:
            self._send_packet(record)

    def store_attachment(
        self,
        *,
        event_id,
        event_sequence: int,
        content_type: str,
        payload: bytes,
        priority: EvidencePriority = EvidencePriority.ORDINARY,
        schema_version: int = 1,
    ) -> dict[str, Any]:
        header = json.dumps({
            "event_id": str(event_id),
            "event_sequence": event_sequence,
            "content_type": content_type,
            "priority": priority.name,
            "schema_version": schema_version,
        }, separators=(",", ":")).encode()
        packet = b"A" + len(header).to_bytes(4, "big") + header + payload
        with self._lock:
            self._send_packet(packet)
            response = self._recv_packet()
        if not response.startswith(b"R"):
            raise RuntimeError("Invalid attachment response from Caretaker writer")
        result = json.loads(response[1:])
        if not result.get("ok"):
            raise RuntimeError(result.get("error", "attachment storage failed"))
        return result["reference"]

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.socket.close()


class SocketLogServer:
    def __init__(
        self,
        path: str | Path,
        writer: SegmentWriter,
        *,
        allowed_uids: set[int] | None = None,
        codec: TLVLogCodec | None = None,
        attachment_store: Any | None = None,
        maximum_packet_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.path = unix_socket_path(path)
        self.writer = writer
        self.allowed_uids = allowed_uids
        self.codec = codec or writer.codec
        self.attachment_store = attachment_store
        self.maximum_packet_bytes = maximum_packet_bytes
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._connections: set[socket.socket] = set()
        self._connection_lock = threading.RLock()
        self._accept_lock = threading.Lock()
        self._socket: socket.socket | None = None
        self._serving = threading.Event()
        self._serve_done = threading.Event()

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.unlink(missing_ok=True)
        socket_type = getattr(socket, "SOCK_SEQPACKET", socket.SOCK_STREAM)
        server = socket.socket(socket.AF_UNIX, socket_type)
        server.bind(str(self.path))
        os.chmod(self.path, 0o600)
        server.listen(128)
        server.settimeout(0.25)
        self._socket = server
        self._stream = socket_type == socket.SOCK_STREAM

    def serve_forever(self) -> None:
        if self._socket is None:
            self.start()
        assert self._socket is not None
        self._serve_done.clear()
        self._serving.set()
        try:
            while not self._stop.is_set():
                try:
                    # Registration and shutdown are serialized so stop() cannot
                    # miss a connection between accept() and _connections.add().
                    with self._accept_lock:
                        if self._stop.is_set():
                            break
                        connection, _ = self._socket.accept()
                        with self._connection_lock:
                            self._connections.add(connection)
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                pid, uid, _gid = peer_credentials(connection)
                if self.allowed_uids is not None and uid not in self.allowed_uids:
                    with self._connection_lock:
                        self._connections.discard(connection)
                    connection.close()
                    continue
                thread = threading.Thread(target=self._handle, args=(connection, pid, uid), daemon=True)
                thread.start()
                self._threads.append(thread)
        finally:
            self._serving.clear()
            self._serve_done.set()

    def _handle(self, connection: socket.socket, pid: int, uid: int) -> None:
        try:
            # A graceful server stop ends acceptance but lets already accepted
            # clients drain through EOF. The stop path force-closes clients that
            # outlive its bounded grace period.
            while True:
                if self._stream:
                    length_data = _recv_exact(connection, 4)
                    if not length_data:
                        return
                    packet = _recv_exact(connection, int.from_bytes(length_data, "big"))
                else:
                    packet = connection.recv(self.maximum_packet_bytes)
                if not packet:
                    return
                if packet.startswith(b"A"):
                    self._handle_attachment(connection, packet)
                    continue
                record = packet[1:] if packet.startswith(b"E") else packet
                envelope = self.codec.decode(record)
                # A same-user emitter may claim a different PID in its payload;
                # preserve both and annotate the observed IPC peer.
                if envelope.process_id != pid and pid >= 0:
                    fields = dict(envelope.fields)
                    fields["ipc_peer_pid"] = pid
                    fields["ipc_peer_uid"] = uid
                    envelope = LogEnvelope(**{**asdict(envelope), "fields": fields})
                self.writer.write(envelope)
        finally:
            with self._connection_lock:
                self._connections.discard(connection)
            connection.close()

    def _handle_attachment(self, connection: socket.socket, packet: bytes) -> None:
        if self.attachment_store is None:
            response = {"ok": False, "error": "attachment store is not configured"}
        else:
            try:
                header_length = int.from_bytes(packet[1:5], "big")
                header = json.loads(packet[5:5 + header_length])
                payload = packet[5 + header_length:]
                from uuid import UUID
                event_id = UUID(header["event_id"])
                event_sequence = (
                    self.writer.reserve_sequence(event_id)
                    if hasattr(self.writer, "reserve_sequence")
                    else int(header["event_sequence"])
                )
                reference = self.attachment_store.store(
                    event_id=event_id,
                    event_sequence=event_sequence,
                    content_type=str(header["content_type"]),
                    payload=payload,
                    priority=EvidencePriority[header["priority"]],
                    schema_version=int(header.get("schema_version", 1)),
                )
                response = {"ok": True, "reference": _jsonable_reference(reference)}
            except Exception as exc:
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        encoded = b"R" + json.dumps(response, default=str).encode()
        if self._stream:
            connection.sendall(len(encoded).to_bytes(4, "big") + encoded)
        else:
            connection.sendall(encoded)

    def stop(self, *, grace_seconds: float = 1.0) -> None:
        # Drain queued and registered clients before stopping acceptance. The
        # accept lock makes the pending/active snapshot atomic with registration.
        grace = max(0.0, grace_seconds)
        deadline = time.monotonic() + grace
        while self._socket is not None and time.monotonic() < deadline:
            with self._accept_lock:
                try:
                    pending = bool(select.select([self._socket], [], [], 0)[0])
                except (OSError, ValueError):
                    pending = False
                with self._connection_lock:
                    active = bool(self._connections)
                if not pending and not active:
                    self._stop.set()
                    try:
                        self._socket.close()
                    except OSError:
                        pass
                    break
            time.sleep(0.01)
        else:
            with self._accept_lock:
                self._stop.set()
                if self._socket is not None:
                    try:
                        self._socket.close()
                    except OSError:
                        pass
        if self._serving.is_set():
            self._serve_done.wait(timeout=max(0.0, deadline - time.monotonic()))

        # Clients that have closed their side now drain naturally through EOF.
        for thread in tuple(self._threads):
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

        # Force-close only handlers that did not finish inside the grace period.
        with self._connection_lock:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        for thread in tuple(self._threads):
            thread.join(timeout=1.0)
        self._threads = [thread for thread in self._threads if thread.is_alive()]
        self.path.unlink(missing_ok=True)



class ControlSocketServer:
    """Declarative local administrative protocol.

    Authentication defaults to Unix socket permissions and peer credentials, or
    can be extended with an independent authorization verifier. The protocol
    never accepts shell commands, Python source, or arbitrary paths.
    """

    def __init__(
        self,
        path: str | Path,
        handler: Callable[[dict[str, Any], tuple[int, int, int]], dict[str, Any]],
        *,
        allowed_uids: set[int] | None = None,
        allowed_gids: set[int] | None = None,
        authorization_verifier: Callable[[dict[str, Any], tuple[int, int, int]], bool] | None = None,
    ) -> None:
        self.path = unix_socket_path(path)
        self.handler = handler
        self.allowed_uids = allowed_uids
        self.allowed_gids = allowed_gids
        self.authorization_verifier = authorization_verifier
        self._stop = threading.Event()
        self._socket: socket.socket | None = None
        self._threads: list[threading.Thread] = []
        self._thread_lock = threading.Lock()
        self._client_slots = threading.BoundedSemaphore(32)

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.unlink(missing_ok=True)
        # Control responses can contain evidence bundles and behavior snapshots
        # larger than the platform's SOCK_SEQPACKET message limit.  A framed
        # stream keeps those responses reliable without relying on recv timing.
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.path))
        os.chmod(self.path, 0o660)
        server.listen(16)
        server.settimeout(0.25)
        self._socket = server

    def serve_forever(self) -> None:
        if self._socket is None:
            self.start()
        assert self._socket is not None
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            credentials = peer_credentials(connection)
            _pid, uid, gid = credentials
            if self.allowed_uids is not None and uid not in self.allowed_uids:
                connection.close()
                continue
            if self.allowed_gids is not None and gid not in self.allowed_gids:
                connection.close()
                continue
            if not self._client_slots.acquire(blocking=False):
                try:
                    _send_control_payload(
                        connection,
                        json.dumps({
                            "ok": False,
                            "error": "Caretaker control server is busy",
                        }).encode(),
                    )
                finally:
                    connection.close()
                continue
            thread = threading.Thread(
                target=self._handle_connection,
                args=(connection, credentials),
                name="caretaker-control-client",
                daemon=True,
            )
            with self._thread_lock:
                self._threads = [item for item in self._threads if item.is_alive()]
                self._threads.append(thread)
            thread.start()

    def _handle_connection(
        self,
        connection: socket.socket,
        credentials: tuple[int, int, int],
    ) -> None:
        try:
            try:
                request = json.loads(
                    _recv_control_payload(connection, maximum=_CONTROL_REQUEST_LIMIT)
                )
                if self.authorization_verifier is not None and not self.authorization_verifier(
                    request, credentials
                ):
                    raise PermissionError("control request authorization failed")
                response = self.handler(request, credentials)
            except Exception as exc:
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            _send_control_payload(connection, json.dumps(response, default=str).encode())
        except OSError:
            # A timed-out or disconnected control client must not affect the
            # listener or other in-flight requests.
            pass
        finally:
            connection.close()
            self._client_slots.release()

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            self._socket.close()
        with self._thread_lock:
            threads = tuple(self._threads)
        for thread in threads:
            thread.join(timeout=1.0)
        with self._thread_lock:
            self._threads = [thread for thread in self._threads if thread.is_alive()]
        self.path.unlink(missing_ok=True)


def control_request(path: str | Path, request: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any]:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(str(unix_socket_path(path)))
    try:
        _send_control_payload(connection, json.dumps(request).encode())
        response = _recv_control_payload(connection, maximum=_CONTROL_RESPONSE_LIMIT)
        return json.loads(response)
    finally:
        connection.close()


def submit_worker_acceptance_observation(
    path: str | Path,
    *,
    worker_id: str | UUID,
    process_start_id: str | UUID,
    authority_packet_id: str | UUID,
    observation_id: str | UUID,
    success: bool,
    observed_at: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Submit one bounded acceptance observation to the local supervisor.

    The supervisor derives the worker's target and policy context from its
    registration. The worker therefore cannot use this helper to submit a
    different target, generation, code hash, or policy fingerprint.
    """
    if not isinstance(success, bool):
        raise ValueError("worker acceptance observation success must be a boolean")
    request: dict[str, Any] = {
        "command": "worker-acceptance-observation",
        "worker_id": str(worker_id),
        "process_start_id": str(process_start_id),
        "authority_packet_id": str(authority_packet_id),
        "observation_id": str(observation_id),
        "success": success,
    }
    if observed_at is not None:
        request["observed_at"] = str(observed_at)
    return control_request(path, request, timeout=timeout)


def list_adaptive_transition_requests(
    path: str | Path,
    *,
    worker_id: str | UUID | None = None,
    target_id: str | None = None,
    limit: int = 100,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Fetch supervisor-issued adaptive transition requests for a worker."""
    request: dict[str, Any] = {
        "command": "adaptive-transition-list",
        "limit": int(limit),
    }
    if worker_id is not None:
        request["worker_id"] = str(worker_id)
    if target_id is not None:
        request["target_id"] = str(target_id)
    return control_request(path, request, timeout=timeout)


def acknowledge_adaptive_transition(
    path: str | Path,
    *,
    request_id: str | UUID,
    worker_id: str | UUID,
    target_id: str,
    generation_id: str,
    code_hash: str,
    monitoring_fingerprint: str,
    policy_fingerprint: str,
    authority_policy_generation: str,
    authority_policy_fingerprint: str,
    applied: bool,
    observed_level: str | None = None,
    error: str | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Acknowledge one context-checked adaptive transition application."""
    if not isinstance(applied, bool):
        raise ValueError("adaptive transition applied must be a boolean")
    request: dict[str, Any] = {
        "command": "adaptive-transition-ack",
        "request_id": str(request_id),
        "worker_id": str(worker_id),
        "target_id": str(target_id),
        "generation_id": str(generation_id),
        "code_hash": str(code_hash),
        "monitoring_fingerprint": str(monitoring_fingerprint),
        "policy_fingerprint": str(policy_fingerprint),
        "authority_policy_generation": str(authority_policy_generation),
        "authority_policy_fingerprint": str(authority_policy_fingerprint),
        "applied": applied,
    }
    if observed_level is not None:
        request["observed_level"] = str(observed_level)
    if error is not None:
        request["error"] = str(error)
    return control_request(path, request, timeout=timeout)


def _send_control_payload(connection: socket.socket, payload: bytes) -> None:
    connection.sendall(len(payload).to_bytes(4, "big") + payload)


def _recv_control_payload(connection: socket.socket, *, maximum: int) -> bytes:
    size = int.from_bytes(_recv_exact(connection, 4), "big")
    if size > maximum:
        raise ValueError(f"Caretaker control payload exceeds {maximum} bytes")
    return _recv_exact(connection, size)


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            return b""
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _jsonable_reference(reference: AttachmentReference) -> dict[str, Any]:
    value = asdict(reference)
    for key, item in tuple(value.items()):
        if hasattr(item, "name"):
            value[key] = item.name
        elif hasattr(item, "hex"):
            value[key] = str(item)
    return value
