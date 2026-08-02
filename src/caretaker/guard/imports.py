from __future__ import annotations

import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
import threading
from pathlib import Path
from types import ModuleType
from typing import Callable
from uuid import UUID, uuid4

from ..control_plane import (
    RuntimeActionKind,
    RuntimeControlPlane,
    RuntimeSignal,
    SignalDomain,
    SignalSeverity,
)
from ..evidence.identity import identify_module
from ..evidence.models import InspectionKind
from ..runtime import set_runtime_context
from .introspection import RuntimeInspector
from .models import ImportRouteDecision, ModuleRoutePolicy, ModuleVariant


class GuardImportError(ImportError):
    pass


class RestartRequested(RuntimeError):
    def __init__(self, import_name: str, variant_id: str, reason: str) -> None:
        super().__init__(reason)
        self.import_name = import_name
        self.variant_id = variant_id
        self.reason = reason


class ModuleRouter:
    def __init__(self) -> None:
        self._variants: dict[str, dict[str, ModuleVariant]] = {}
        self._policies: dict[str, ModuleRoutePolicy] = {}
        self._quarantined: set[str] = set()
        self._active_routes: dict[str, str] = {}
        self.decisions: list[ImportRouteDecision] = []
        self._lock = threading.RLock()

    def register_variant(self, variant: ModuleVariant) -> None:
        with self._lock:
            self._variants.setdefault(variant.import_name, {})[variant.variant_id] = variant

    def register_policy(self, policy: ModuleRoutePolicy) -> None:
        with self._lock:
            self._policies[policy.import_name] = policy

    def policy_for(self, import_name: str) -> ModuleRoutePolicy | None:
        with self._lock:
            return self._policies.get(import_name)

    def quarantine(self, variant_id: str) -> None:
        with self._lock:
            self._quarantined.add(variant_id)

    def unquarantine(self, variant_id: str) -> None:
        with self._lock:
            self._quarantined.discard(variant_id)

    def is_quarantined(self, variant_id: str) -> bool:
        with self._lock:
            return variant_id in self._quarantined

    def active_variant(self, import_name: str) -> ModuleVariant | None:
        with self._lock:
            selected = self._active_routes.get(import_name)
            if selected is None:
                return None
            return self._variants.get(import_name, {}).get(selected)

    def select(
        self,
        import_name: str,
        *,
        triggering_signal_ids: tuple[UUID, ...] = (),
    ) -> tuple[ModuleVariant | None, ImportRouteDecision]:
        with self._lock:
            policy = self._policies.get(import_name)
            variants = self._variants.get(import_name, {})
            if policy is None:
                decision = ImportRouteDecision(
                    decision_id=uuid4(),
                    import_name=import_name,
                    requested_variant_id=None,
                    selected_variant_id=None,
                    action="DEFAULT_IMPORT",
                    reason="No Caretaker route policy registered",
                    triggering_signal_ids=triggering_signal_ids,
                    policy_fingerprint="none",
                )
                self.decisions.append(decision)
                return None, decision
            candidates = (policy.preferred_variant_id,) + policy.fallback_variant_ids
            selected: ModuleVariant | None = None
            for variant_id in candidates:
                candidate = variants.get(variant_id)
                if candidate is None or variant_id in self._quarantined:
                    continue
                source_path = Path(candidate.source_location)
                if not source_path.exists():
                    continue
                if candidate.source_hash is not None:
                    observed_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
                    if observed_hash != candidate.source_hash:
                        self._quarantined.add(variant_id)
                        continue
                if policy.require_signed_variant and candidate.integrity_state not in {
                    "SIGNED_RELEASE",
                    "VERIFIED",
                    "TRUSTED",
                }:
                    continue
                if policy.require_accepted_baseline and candidate.behavior_baseline_id is None:
                    continue
                selected = candidate
                break
            if selected is None:
                action = "DENY_IMPORT"
                reason = "No approved, non-quarantined module variant is available"
            else:
                action = "SUBSTITUTE_MODULE" if selected.variant_id != policy.preferred_variant_id else "ALLOW_IMPORT"
                reason = f"Selected approved module variant {selected.variant_id}"
                self._active_routes[import_name] = selected.variant_id
            fingerprint = hashlib.sha256(repr(policy).encode("utf-8")).hexdigest()
            decision = ImportRouteDecision(
                decision_id=uuid4(),
                import_name=import_name,
                requested_variant_id=policy.preferred_variant_id,
                selected_variant_id=selected.variant_id if selected else None,
                action=action,
                reason=reason,
                triggering_signal_ids=triggering_signal_ids,
                policy_fingerprint=fingerprint,
            )
            self.decisions.append(decision)
            return selected, decision

    def clear_module_for_restart(self, import_name: str) -> None:
        with self._lock:
            names = [name for name in sys.modules if name == import_name or name.startswith(import_name + ".")]
        for name in names:
            sys.modules.pop(name, None)


class GuardedLoader(importlib.abc.Loader):
    def __init__(
        self,
        loader: importlib.abc.Loader,
        *,
        module_name: str,
        inspector: RuntimeInspector,
        control_plane: RuntimeControlPlane | None,
        run_id: UUID,
        pre_load: Callable[[str], None] | None = None,
        post_load: Callable[[ModuleType], None] | None = None,
    ) -> None:
        self.loader = loader
        self.module_name = module_name
        self.inspector = inspector
        self.control_plane = control_plane
        self.run_id = run_id
        self.pre_load = pre_load
        self.post_load = post_load

    def create_module(self, spec):
        create = getattr(self.loader, "create_module", None)
        return create(spec) if create else None

    def exec_module(self, module: ModuleType) -> None:
        if self.pre_load is not None:
            self.pre_load(self.module_name)
        tokens = set_runtime_context(call_id=uuid4(), operation=f"module-import:{self.module_name}")
        try:
            pre = self.inspector.inspect_module(module, kind=InspectionKind.PRE_LOAD)
            self.loader.exec_module(module)
            inspection = self.inspector.inspect_module(module, kind=InspectionKind.POST_LOAD)
        finally:
            tokens.reset()
        if self.post_load is not None:
            self.post_load(module)
        if inspection.differences_from_load and self.control_plane is not None:
            signal = RuntimeSignal.create(
                domain=SignalDomain.IMPORT,
                kind="load-time-state-change",
                severity=SignalSeverity.LOW,
                run_id=self.run_id,
                source_component="guard.import-loader",
                module_identity=inspection.subject,
                evidence_refs=(pre.inspection_id, inspection.inspection_id),
                attributes={
                    "difference_count": len(inspection.differences_from_load),
                    "expected_module_initialization": True,
                },
            )
            self.control_plane.submit(signal)


class CaretakerModuleFinder(importlib.abc.MetaPathFinder):
    def __init__(
        self,
        *,
        router: ModuleRouter,
        inspector: RuntimeInspector,
        run_id: UUID,
        control_plane: RuntimeControlPlane | None = None,
        observed_modules: tuple[str, ...] = (),
    ) -> None:
        self.router = router
        self.inspector = inspector
        self.run_id = run_id
        self.control_plane = control_plane
        self.observed_modules = observed_modules
        self._installed = False
        self._resolving = threading.local()

    def install(self, position: int = 0) -> None:
        if self._installed:
            return
        sys.meta_path.insert(position, self)
        self._installed = True

    def uninstall(self) -> None:
        if self in sys.meta_path:
            sys.meta_path.remove(self)
        self._installed = False

    def find_spec(self, fullname: str, path=None, target=None):
        if (fullname == "caretaker" or fullname.startswith("caretaker.")) or getattr(self._resolving, "active", False):
            return None
        route_policy = self.router.policy_for(fullname)
        observed = self._matches(fullname)
        if route_policy is None and not observed:
            return None
        self._resolving.active = True
        try:
            selected, decision = self.router.select(fullname)
            if route_policy is not None and selected is None:
                signal = RuntimeSignal.create(
                    domain=SignalDomain.IMPORT,
                    kind="module-route-unavailable",
                    severity=SignalSeverity.HIGH,
                    run_id=self.run_id,
                    source_component="guard.import-router",
                    module_identity=identify_module(fullname),
                    requires_immediate_decision=True,
                    attributes={"quarantined": True},
                )
                if self.control_plane is not None:
                    self.control_plane.submit(signal)
                raise GuardImportError(f"Caretaker denied import of {fullname}: {decision.reason}")
            if selected is not None:
                location = Path(selected.source_location)
                if not location.exists():
                    raise GuardImportError(
                        f"Caretaker module variant {selected.variant_id} does not exist: {location}"
                    )
                spec = importlib.util.spec_from_file_location(fullname, location)
            else:
                spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
            if spec is None or spec.loader is None:
                return spec
            spec.loader = GuardedLoader(
                spec.loader,
                module_name=fullname,
                inspector=self.inspector,
                control_plane=self.control_plane,
                run_id=self.run_id,
            )
            return spec
        finally:
            self._resolving.active = False

    def _matches(self, fullname: str) -> bool:
        return any(
            fullname == pattern
            or (pattern.endswith(".*") and fullname.startswith(pattern[:-1]))
            for pattern in self.observed_modules
        )


class CaretakerSupervisor:
    """Small restart boundary for demonstrations and command-line services.

    This re-enters ``main`` in the same process. Production-grade module rollback
    should use an external process supervisor so native state and background
    threads are discarded as well.
    """

    def __init__(self, router: ModuleRouter, *, maximum_restarts: int = 1) -> None:
        self.router = router
        self.maximum_restarts = maximum_restarts

    def run(self, main: Callable[[], object]) -> object:
        restarts = 0
        while True:
            try:
                return main()
            except RestartRequested as request:
                if restarts >= self.maximum_restarts:
                    raise
                restarts += 1
                self.router.clear_module_for_restart(request.import_name)
