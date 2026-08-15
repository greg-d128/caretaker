from __future__ import annotations

import json
import tarfile
from pathlib import Path

from caretaker.behavior import BehaviorSnapshotStore, compare_snapshots


def _capture(*, code_hash: str, events: int, destination: str = "api.example:443"):
    return {
        "scope": "function",
        "subject_key": "function:lab.divide",
        "subject": {
            "target_id": "lab.divide",
            "module_name": "examples.lab",
            "qualified_name": "divide",
        },
        "code_hash": code_hash,
        "code_hash_kind": "function-source-sha256",
        "profile": {
            "window_count": 1,
            "call_count": 10,
            "event_count": events,
            "event_kind_counts": {"FUNCTION_CALL": events},
            "network_destinations": [destination],
            "filesystem_roots": [],
            "subprocesses": [],
            "imports": [],
            "dynamic_code_operations": [],
        },
        "children": [],
    }


def test_snapshot_store_verifies_content_hash_and_compares_across_code_hashes(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    first = store.create(_capture(code_hash="a" * 64, events=10))
    second = store.create(
        _capture(code_hash="b" * 64, events=20, destination="new.example:443")
    )

    listed = store.list()
    assert len(listed) == 2
    assert all(item["verified"] for item in listed)

    comparison = compare_snapshots(first, second)
    assert first["snapshot"]["generation_id"] != second["snapshot"]["generation_id"]
    assert comparison["code_hash_changed"] is True
    assert comparison["generation_changed"] is True
    assert comparison["events"]["absolute"] == 10
    assert comparison["resource_changes"]["network_destinations"]["added"] == [
        "new.example:443"
    ]
    assert comparison["resource_changes"]["network_destinations"]["removed"] == [
        "api.example:443"
    ]


def test_archive_contains_manifest_and_removes_snapshot(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    envelope = store.create(_capture(code_hash="a" * 64, events=10))
    snapshot_id = envelope["snapshot"]["snapshot_id"]

    archive_path = store.archive([snapshot_id], remove=True)

    assert archive_path.exists()
    assert not (store.snapshot_directory / f"{snapshot_id}.json").exists()
    with tarfile.open(archive_path, "r:gz") as archive:
        names = set(archive.getnames())
        assert "manifest.json" in names
        assert f"snapshots/{snapshot_id}.json" in names
        manifest_file = archive.extractfile("manifest.json")
        assert manifest_file is not None
        manifest = json.loads(manifest_file.read())
        assert manifest["snapshots"][0]["snapshot_id"] == snapshot_id


def test_snapshot_chain_survives_archive_and_delete(tmp_path):
    store = BehaviorSnapshotStore(tmp_path)
    first = store.create(_capture(code_hash="a" * 64, events=10))
    first_snapshot = first["snapshot"]
    first_hash = first["integrity"]["content_sha256"]

    archive = store.archive([first_snapshot["snapshot_id"]], remove=True)
    assert archive.exists()
    second = store.create(_capture(code_hash="a" * 64, events=10))
    assert second["snapshot"]["snapshot_sequence"] == first_snapshot["snapshot_sequence"] + 1
    assert second["snapshot"]["previous_snapshot_hash"] == first_hash

    second_hash = second["integrity"]["content_sha256"]
    store.delete(second["snapshot"]["snapshot_id"])
    third = store.create(_capture(code_hash="a" * 64, events=10))
    assert third["snapshot"]["snapshot_sequence"] == second["snapshot"]["snapshot_sequence"] + 1
    assert third["snapshot"]["previous_snapshot_hash"] == second_hash
    assert (store.tombstone_directory / f"{second['snapshot']['snapshot_id']}.json").exists()
