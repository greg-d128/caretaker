from __future__ import annotations

import os
from pathlib import Path

from caretaker.system import (
    ProcessSelector,
    SystemCollectionPolicy,
    SystemDataCollector,
    SystemOutputPolicy,
    SystemSourceDefinition,
)


def test_system_collector_uses_shared_cycle_timestamp_and_separate_output(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("alpha\nbeta\n")
    policy = SystemCollectionPolicy(
        enabled=True,
        host_sources=(SystemSourceDefinition("demo", str(source)),),
        process_sources=(),
        output=SystemOutputPolicy(directory=str(tmp_path / "system")),
    )
    collector = SystemDataCollector(policy, application_pid=os.getpid())
    cycle = collector.collect_once()
    assert len(cycle.source_results) == 1
    result = cycle.source_results[0]
    assert result.state == "CAPTURED"
    output = Path(result.output_path).read_text()
    assert f"cycle_id={cycle.cycle_id}" in output
    assert f"timestamp_utc={cycle.capture_timestamp_utc.isoformat()}" in output
    assert "alpha\nbeta" in output
    collector.close()


def test_process_selector_includes_application_process_tree(tmp_path):
    policy = SystemCollectionPolicy(
        enabled=True,
        host_sources=(),
        process_sources=(),
        process_selector=ProcessSelector(include_application_root=True, include_descendants=True),
        output=SystemOutputPolicy(directory=str(tmp_path / "system")),
    )
    collector = SystemDataCollector(policy, application_pid=os.getpid())
    selected = collector.select_processes()
    assert any(item.pid == os.getpid() for item in selected)
