from __future__ import annotations

import importlib
import sys
from pathlib import Path
from uuid import uuid4

from caretaker import (
    InMemoryEvidenceStore,
    RuntimeActionKind,
    RuntimeControlPlane,
    RuntimeSignal,
    SignalDomain,
    SignalSeverity,
)
from caretaker.guard.imports import CaretakerModuleFinder, ModuleRouter
from caretaker.guard.introspection import RuntimeInspector
from caretaker.guard.models import ModuleRoutePolicy, ModuleVariant


def test_control_plane_maps_requested_guard_actions() -> None:
    plane = RuntimeControlPlane()
    signal = RuntimeSignal.create(
        domain=SignalDomain.BEHAVIOR,
        kind="candidate-deviation",
        severity=SignalSeverity.HIGH,
        run_id=uuid4(),
        source_component="test",
        attributes={"requested_action": "ROLLBACK_ACTIVE_CANDIDATE"},
    )
    decision = plane.submit(signal)
    assert RuntimeActionKind.ROLLBACK_REPAIR in decision.actions


def test_module_router_selects_non_quarantined_fallback(tmp_path: Path) -> None:
    module_name = "caretaker_guard_routed_example"
    preferred = tmp_path / "preferred.py"
    fallback = tmp_path / "fallback.py"
    preferred.write_text("VALUE = 'preferred'\n", encoding="utf-8")
    fallback.write_text("VALUE = 'fallback'\n", encoding="utf-8")

    router = ModuleRouter()
    router.register_variant(
        ModuleVariant(
            variant_id="preferred",
            import_name=module_name,
            distribution_name=None,
            distribution_version=None,
            source_location=str(preferred),
            source_hash=None,
            integrity_state="TRUSTED",
            behavior_baseline_id=None,
        )
    )
    router.register_variant(
        ModuleVariant(
            variant_id="fallback",
            import_name=module_name,
            distribution_name=None,
            distribution_version=None,
            source_location=str(fallback),
            source_hash=None,
            integrity_state="TRUSTED",
            behavior_baseline_id=None,
        )
    )
    router.register_policy(
        ModuleRoutePolicy(
            import_name=module_name,
            preferred_variant_id="preferred",
            fallback_variant_ids=("fallback",),
        )
    )
    router.quarantine("preferred")

    finder = CaretakerModuleFinder(
        router=router,
        inspector=RuntimeInspector(InMemoryEvidenceStore()),
        run_id=uuid4(),
    )
    finder.install()
    try:
        imported = importlib.import_module(module_name)
        assert imported.VALUE == "fallback"
        assert router.active_variant(module_name).variant_id == "fallback"
    finally:
        finder.uninstall()
        sys.modules.pop(module_name, None)
