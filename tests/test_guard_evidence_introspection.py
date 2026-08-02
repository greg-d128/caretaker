from __future__ import annotations

import importlib
import sys
from pathlib import Path

from caretaker import (
    InMemoryEvidenceStore,
    InspectionKind,
    RuntimeInspector,
    SQLiteEvidenceStore,
    identify_function,
    identify_module,
)
from caretaker.guard.collectors import AuditEventCollector
from caretaker.guard.policy import CollectorPolicy
from tests import guard_targets


def test_code_identity_tracks_function_and_module_versions() -> None:
    function_identity = identify_function(guard_targets.stable)
    module_identity = identify_module(guard_targets)

    assert function_identity.module_name == "tests.guard_targets"
    assert function_identity.qualified_name == "stable"
    assert function_identity.bytecode_hash
    assert module_identity.module_name == "tests.guard_targets"
    assert module_identity.source_hash


def test_runtime_inspector_detects_function_code_replacement() -> None:
    store = InMemoryEvidenceStore()
    inspector = RuntimeInspector(store)
    function = guard_targets.stable
    original_code = function.__code__
    inspector.inspect_function(function, kind=InspectionKind.POST_LOAD)
    try:
        function.__code__ = guard_targets.replacement_shape.__code__
        current = inspector.inspect_function(function, kind=InspectionKind.PERIODIC)
    finally:
        function.__code__ = original_code

    assert any(item.path == "function.bytecode" for item in current.differences_from_load)


def test_runtime_inspector_detects_module_function_monkeypatch() -> None:
    store = InMemoryEvidenceStore()
    inspector = RuntimeInspector(store)
    module = guard_targets
    original = module.stable
    inspector.inspect_module(module, kind=InspectionKind.POST_LOAD)
    try:
        module.stable = guard_targets.replacement_shape
        current = inspector.inspect_module(module, kind=InspectionKind.PERIODIC)
    finally:
        module.stable = original

    assert any(item.path == "functions.stable" for item in current.differences_from_load)


def test_audit_collector_normalizes_file_and_network_events() -> None:
    events = []
    collector = AuditEventCollector(
        run_id=__import__("uuid").uuid4(),
        sink=events.append,
        collectors=CollectorPolicy(),
    )
    file_event = collector._normalize("open", ("/tmp/example.txt", "r", 0))
    network_event = collector._normalize("socket.connect", (object(), ("example.org", 443)))

    assert file_event is not None and file_event.resource is not None
    assert file_event.resource.kind == "file"
    assert network_event is not None and network_event.resource is not None
    assert network_event.resource.kind == "network"


def test_sqlite_evidence_store_supports_interactive_queries(tmp_path: Path) -> None:
    store = SQLiteEvidenceStore(tmp_path / "guard.sqlite")
    inspector = RuntimeInspector(store)
    inspector.inspect_function(guard_targets.stable, kind=InspectionKind.POST_LOAD)

    rows = store.query(
        "SELECT module_name, qualified_name, significant_change_count "
        "FROM runtime_inspections"
    )
    assert rows[0]["module_name"] == "tests.guard_targets"
    assert rows[0]["qualified_name"] == "stable"
