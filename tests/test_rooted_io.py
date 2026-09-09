from __future__ import annotations

from pathlib import Path

import pytest

from caretaker.rooted_io import RootedFilesystem, RootedWriteError


def test_rooted_filesystem_rejects_escape_and_symlinked_parent(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    rooted = RootedFilesystem(root)

    with pytest.raises(RootedWriteError, match="escapes"):
        rooted.open_append(tmp_path / "outside.log")
    with pytest.raises(RootedWriteError, match="unsafe component"):
        rooted.open_append(root / ".." / "outside.log")

    (root / "nested").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        rooted.open_append(root / "nested" / "events.log")
    assert not (outside / "events.log").exists()


def test_rooted_filesystem_rejects_final_symlink_and_confines_atomic_write(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.log"
    outside.write_bytes(b"original")
    destination = root / "events.log"
    destination.symlink_to(outside)
    rooted = RootedFilesystem(root)

    with pytest.raises(OSError):
        rooted.open_append(destination)
    with pytest.raises(RootedWriteError, match="symlink"):
        rooted.atomic_write(destination, b"replacement")
    assert outside.read_bytes() == b"original"


def test_rooted_filesystem_atomic_write_uses_rooted_destination(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    rooted = RootedFilesystem(root)

    result = rooted.atomic_write(root / "nested" / "result.json", b"{}")

    assert result.read_bytes() == b"{}"
    assert result.parent == root / "nested"
    assert not list(root.rglob("*.tmp"))


def test_configured_writers_reject_symlinked_outputs(tmp_path: Path) -> None:
    from uuid import uuid4

    from caretaker.logging.audit import AuditStreamError, AuditStreamWriter
    from caretaker.logging.metrics import MonitoringStreamPolicy, MonitoringStreamWriter
    from caretaker.logging.policy import AuditStreamPolicy

    outside = tmp_path / "outside.log"
    outside.write_bytes(b"unchanged")
    monitoring = tmp_path / "caretaker_monitoring.log"
    monitoring.symlink_to(outside)
    with pytest.raises(OSError):
        MonitoringStreamWriter(
            MonitoringStreamPolicy(enabled=True),
            directory=tmp_path,
            application_id="app",
            run_id=uuid4(),
            process_start_id=uuid4(),
        )

    audit = tmp_path / "caretaker_audit.log"
    audit.symlink_to(outside)
    with pytest.raises(AuditStreamError, match="symlink"):
        AuditStreamWriter(
            AuditStreamPolicy(),
            directory=tmp_path,
            run_id=uuid4(),
            process_start_id=uuid4(),
        )
    assert outside.read_bytes() == b"unchanged"
