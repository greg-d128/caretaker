from __future__ import annotations

import importlib.metadata
import inspect
import os
import random
import sys
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from types import FrameType
from typing import Any, Callable
from uuid import UUID

from ..evidence.identity import identify_module, inventory_distribution
from ..evidence.models import (
    BehaviorEvent,
    BehaviorEventKind,
    CodeIdentity,
    EventOutcome,
    FrameIdentity,
    ResourceIdentity,
)
from ..runtime import snapshot_context
from ..state import value_snapshot
from .policy import AttributionPolicy, CollectorPolicy, SamplingPolicy


_in_audit_hook: ContextVar[bool] = ContextVar("caretaker_guard_in_audit_hook", default=False)


def _safe_text(value: object, maximum: int = 500) -> str:
    try:
        text = os.fspath(value) if isinstance(value, os.PathLike) else str(value)
    except Exception:
        text = f"<{type(value).__module__}.{type(value).__qualname__}>"
    if len(text) > maximum:
        return text[:maximum] + "..."
    return text


class AuditEventCollector:
    """Normalize selected CPython audit events into Guard behavior events.

    The callback intentionally does no database or LLM work. The supplied sink
    should enqueue or append the already-normalized immutable event.
    """

    _installed_collectors: list["AuditEventCollector"] = []
    _global_installed = False
    _global_lock = threading.RLock()

    def __init__(
        self,
        *,
        run_id: UUID,
        sink: Callable[[BehaviorEvent], None],
        collectors: CollectorPolicy | None = None,
        attribution: AttributionPolicy | None = None,
        sampling: SamplingPolicy | None = None,
    ) -> None:
        self.run_id = run_id
        self.sink = sink
        self.collectors = collectors or CollectorPolicy()
        self.attribution = attribution or AttributionPolicy()
        self.sampling = sampling or SamplingPolicy()
        self._random = random.SystemRandom()
        self._identity_cache: dict[str, CodeIdentity] = {}
        self._seen_resources: set[tuple[str, str, str | None]] = set()
        self._rate_second: int | None = None
        self._events_this_second = 0
        self._enabled = True

    def install(self) -> None:
        with self._global_lock:
            if self not in self._installed_collectors:
                self._installed_collectors.append(self)
            if not self._global_installed:
                sys.addaudithook(self._dispatch)
                type(self)._global_installed = True

    def disable(self) -> None:
        self._enabled = False
        with self._global_lock:
            if self in self._installed_collectors:
                self._installed_collectors.remove(self)

    @classmethod
    def _dispatch(cls, event: str, args: tuple[Any, ...]) -> None:
        if _in_audit_hook.get():
            return
        token = _in_audit_hook.set(True)
        try:
            for collector in tuple(cls._installed_collectors):
                if collector._enabled:
                    collector._handle(event, args)
        finally:
            _in_audit_hook.reset(token)

    def _handle(self, event: str, args: tuple[Any, ...]) -> None:
        # Map the event before sampling because mapping is cheap and tells us whether
        # the event category is enabled. Expensive attribution, stack construction,
        # value snapshots, and BehaviorEvent creation happen only after the sample
        # and rate-limit decisions.
        mapping = self._event_mapping(event, args)
        if mapping is None:
            return
        event_kind, resource, attributes = mapping
        context = snapshot_context()
        if not self.collectors.unattributed_events and context.get("target_id") is None:
            return
        resource_key = self._resource_key(resource)
        novel = resource_key is not None and resource_key not in self._seen_resources

        if not self._within_rate_limit():
            return

        always_novel = self.sampling.always_capture_novel_resources and novel
        rate = min(1.0, max(0.0, self.sampling.event_sample_rate))
        if not always_novel and (rate <= 0.0 or self._random.random() > rate):
            return

        stack_rate = min(1.0, max(0.0, self.sampling.stack_sample_rate))
        capture_stack = bool(
            self.attribution.capture_stack
            and (
                always_novel
                or stack_rate >= 1.0
                or (stack_rate > 0.0 and self._random.random() <= stack_rate)
            )
        )
        normalized = self._normalize_mapping(
            event,
            event_kind,
            resource,
            attributes,
            capture_stack=capture_stack,
            context=context,
        )
        try:
            self.sink(normalized)
        except Exception:
            # Audit callbacks must never recursively break the application.
            return
        if resource_key is not None:
            self._seen_resources.add(resource_key)

    def _normalize(self, event: str, args: tuple[Any, ...]) -> BehaviorEvent | None:
        """Normalize one event directly, bypassing sampling (test/introspection API)."""
        mapping = self._event_mapping(event, args)
        if mapping is None:
            return None
        event_kind, resource, attributes = mapping
        return self._normalize_mapping(
            event,
            event_kind,
            resource,
            attributes,
            capture_stack=self.attribution.capture_stack,
        )

    def _normalize_mapping(
        self,
        event: str,
        event_kind: BehaviorEventKind,
        resource: ResourceIdentity | None,
        attributes: dict[str, Any],
        *,
        capture_stack: bool,
        context: dict[str, object] | None = None,
    ) -> BehaviorEvent:
        if context is None:
            context = snapshot_context()
        executing, initiating, stack = self._attribute(capture_stack=capture_stack)
        identity = initiating or executing or self._identity_for_module("<unknown>")
        return BehaviorEvent.create(
            event_kind=event_kind,
            operation=event,
            code_identity=identity,
            initiating_identity=initiating,
            executing_identity=executing,
            run_id=self.run_id,
            call_id=context.get("call_id"),
            target_id=context.get("target_id"),
            process_id=os.getpid(),
            thread_id=threading.get_ident(),
            task_id=None,
            resource=resource,
            attributes={key: value_snapshot(value) for key, value in attributes.items()},
            outcome=EventOutcome.OBSERVED,
            stack_summary=stack,
        )

    @staticmethod
    def _resource_key(resource: ResourceIdentity | None) -> tuple[str, str, str | None] | None:
        if resource is None:
            return None
        return (resource.kind, resource.value, resource.category)

    def _within_rate_limit(self) -> bool:
        maximum = self.sampling.maximum_events_per_second
        if maximum <= 0:
            return False
        second = int(time.monotonic())
        if second != self._rate_second:
            self._rate_second = second
            self._events_this_second = 0
        if self._events_this_second >= maximum:
            return False
        self._events_this_second += 1
        return True

    def _event_mapping(
        self,
        event: str,
        args: tuple[Any, ...],
    ) -> tuple[BehaviorEventKind, ResourceIdentity | None, dict[str, Any]] | None:
        if event == "import" and self.collectors.imports:
            name = _safe_text(args[0]) if args else "<unknown>"
            return BehaviorEventKind.IMPORT, ResourceIdentity("import", name), {}
        if event in {"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"} and self.collectors.network:
            host = _safe_text(args[0]) if args else "<unknown>"
            port = _safe_text(args[1]) if len(args) > 1 else ""
            value = f"{host}:{port}" if port else host
            return BehaviorEventKind.NETWORK_DNS, ResourceIdentity("network", value, "dns"), {}
        if event in {"socket.connect", "socket.connect_ex", "http.client.connect"} and self.collectors.network:
            address = args[-1] if args else "<unknown>"
            return BehaviorEventKind.NETWORK_CONNECT, ResourceIdentity("network", _safe_text(address), "connect"), {}
        if event in {"socket.sendto", "socket.sendmsg"} and self.collectors.network:
            address = args[-1] if args else "<unknown>"
            return BehaviorEventKind.NETWORK_SEND, ResourceIdentity("network", _safe_text(address), "send"), {}
        if event == "open" and self.collectors.filesystem:
            path = _safe_text(args[0]) if args else "<unknown>"
            mode = _safe_text(args[1]) if len(args) > 1 else ""
            kind = BehaviorEventKind.FILE_WRITE if any(flag in mode for flag in "wax+") else BehaviorEventKind.FILE_OPEN
            return kind, ResourceIdentity("file", path, "open", _sensitive_path(path)), {"mode": mode}
        if event in {"os.listdir", "os.scandir"} and self.collectors.filesystem:
            path = _safe_text(args[0]) if args else "."
            return BehaviorEventKind.DIRECTORY_LIST, ResourceIdentity("directory", path, "enumeration", _sensitive_path(path)), {}
        if event in {"os.walk", "glob.glob", "pathlib.Path.glob", "pathlib.Path.rglob"} and self.collectors.filesystem:
            path = _safe_text(args[0]) if args else "."
            return BehaviorEventKind.DIRECTORY_WALK, ResourceIdentity("directory", path, "recursive", _sensitive_path(path)), {}
        if event == "subprocess.Popen" and self.collectors.subprocesses:
            executable = _safe_text(args[0]) if args else "<unknown>"
            return BehaviorEventKind.SUBPROCESS, ResourceIdentity("subprocess", executable), {}
        if event in {"exec", "compile"} and self.collectors.dynamic_code:
            return BehaviorEventKind.DYNAMIC_CODE, ResourceIdentity("dynamic-code", event), {}
        return None

    def _attribute(
        self,
        *,
        capture_stack: bool = True,
    ) -> tuple[CodeIdentity | None, CodeIdentity | None, tuple[FrameIdentity, ...]]:
        frame = sys._getframe(3)
        stack: list[FrameIdentity] = []
        executing: CodeIdentity | None = None
        initiating: CodeIdentity | None = None
        scanned = 0
        maximum = max(2, self.attribution.maximum_stack_frames)
        while frame is not None and scanned < maximum:
            scanned += 1
            module_name = frame.f_globals.get("__name__")
            if isinstance(module_name, str):
                identity = self._identity_for_module(module_name)
                if executing is None:
                    executing = identity
                if initiating is None and not self._skip_module(module_name):
                    initiating = identity
                if capture_stack:
                    stack.append(
                        FrameIdentity(
                            module_name=module_name,
                            qualified_name=frame.f_code.co_qualname,
                            filename=frame.f_code.co_filename,
                            line_number=frame.f_lineno,
                            distribution_name=identity.distribution_name,
                        )
                    )
            frame = frame.f_back
        return executing, initiating, tuple(stack)

    def _identity_for_module(self, module_name: str) -> CodeIdentity:
        cached = self._identity_cache.get(module_name)
        if cached is not None:
            return cached
        try:
            identity = identify_module(module_name)
        except Exception:
            identity = CodeIdentity(None, None, module_name)
        self._identity_cache[module_name] = identity
        return identity

    def _skip_module(self, module_name: str) -> bool:
        if module_name.startswith("caretaker"):
            return True
        return any(
            module_name == skipped or module_name.startswith(skipped + ".")
            for skipped in self.attribution.skip_infrastructure_modules
        )


class DependencyCollector:
    def snapshot_all(self) -> tuple[Any, ...]:
        records = []
        for distribution in sorted(importlib.metadata.distributions(), key=lambda item: item.metadata.get("Name", "")):
            name = distribution.metadata.get("Name")
            if not name:
                continue
            try:
                records.append(inventory_distribution(name))
            except Exception:
                continue
        return tuple(records)

    def snapshot(self, names: tuple[str, ...]) -> tuple[Any, ...]:
        records = []
        for name in names:
            try:
                records.append(inventory_distribution(name))
            except importlib.metadata.PackageNotFoundError:
                continue
        return tuple(records)


def _sensitive_path(path: str) -> bool:
    lowered = path.lower()
    markers = (
        "/.ssh",
        "\\.ssh",
        "/.aws",
        "\\.aws",
        "/.gnupg",
        "\\.gnupg",
        "credentials",
        "private-key",
        "id_rsa",
        "id_ed25519",
    )
    return any(marker in lowered for marker in markers)
