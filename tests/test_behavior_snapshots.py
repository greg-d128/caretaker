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
    assert comparison["snapshot_a"]["subject_key"] == "function:lab.divide"
    assert comparison["snapshot_a"]["call_count"] == 10
    assert comparison["snapshot_b"]["snapshot_id"] == second["snapshot"]["snapshot_id"]
    assert comparison["semantic_changes"] == [
        {
            "kind": "network",
            "change": "started",
            "value": "new.example:443",
            "description": "Started contacting new.example:443",
        },
        {
            "kind": "network",
            "change": "stopped",
            "value": "api.example:443",
            "description": "Stopped contacting api.example:443",
        },
    ]
    assert comparison["events"]["absolute"] == 10
    assert comparison["resource_changes"]["network_destinations"]["added"] == [
        "new.example:443"
    ]
    assert comparison["resource_changes"]["network_destinations"]["removed"] == [
        "api.example:443"
    ]


def test_snapshot_list_summaries_omit_large_profile_details(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    capture = _capture(code_hash="a" * 64, events=10)
    capture["profile"]["filesystem_roots"] = [f"/large/path/{index}" for index in range(10_000)]
    envelope = store.create(capture)

    summaries = store.list_summaries(limit=10)

    assert len(summaries) == 1
    assert summaries[0]["snapshot_id"] == envelope["snapshot"]["snapshot_id"]
    assert summaries[0]["profile"]["call_count"] == 10
    assert summaries[0]["profile"]["event_count"] == 10
    assert "filesystem_roots" not in summaries[0]["profile"]


def test_snapshot_summaries_collapse_disjoint_windows_to_latest_generation(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    capture = _capture(code_hash="a" * 64, events=3)
    capture["seal_reason"] = "sample-target-reached"
    capture["profile"]["call_count"] = 1
    capture["profile"]["sampling_provenance"] = {"statistics_target": 1000}
    store.create(capture)
    store.create(capture)
    store.create(capture)

    summaries = store.list_summaries()

    assert len(summaries) == 1
    assert summaries[0]["profile"]["coverage_call_count"] == 3
    assert summaries[0]["profile"]["coverage_snapshot_count"] == 3
    assert summaries[0]["profile"]["coverage_kind"] == "generation"
    assert summaries[0]["snapshot_count"] == 3
    assert [item["calls"] for item in summaries[0]["activity_windows"]] == [1, 1, 1]


def test_snapshot_summary_cache_is_invalidated_when_new_epoch_is_saved(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    capture = _capture(code_hash="a" * 64, events=2)
    capture["seal_reason"] = "sample-target-reached"
    capture["profile"]["call_count"] = 1

    store.create(capture)
    assert store.list_summaries()[0]["profile"]["coverage_call_count"] == 1

    store.create(capture)
    assert store.list_summaries()[0]["profile"]["coverage_call_count"] == 2


def test_snapshot_row_cache_rechecks_filesystem_metadata_for_tampering(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    envelope = store.create(_capture(code_hash="a" * 64, events=2))
    assert store.list()[0]["verified"] is True

    path = store.snapshot_directory / f"{envelope['snapshot']['snapshot_id']}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["snapshot"]["profile"]["event_count"] = 999
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert store.list()[0]["verified"] is False


def test_snapshot_summary_uses_largest_contiguous_coverage_when_epochs_materialize_out_of_order(
    tmp_path: Path,
):
    store = BehaviorSnapshotStore(tmp_path)
    captures = []
    for epoch in (1, 2, 3):
        capture = _capture(code_hash="a" * 64, events=2)
        capture["profile"]["call_count"] = 1
        capture["profile"]["sampling_provenance"] = {"statistics_target": 1000}
        capture.update({
            "complete_epoch": True,
            "epoch_sequence": epoch,
            "first_sample_sequence": epoch,
            "last_sample_sequence": epoch,
            "seal_reason": "sample-target-reached",
        })
        captures.append(capture)

    # Snapshot creation time reflects supervisor materialization order, which is
    # not necessarily application epoch order.
    store.create(captures[2])
    store.create(captures[0])
    store.create(captures[1])

    summary = store.list_summaries()[0]

    assert summary["epoch_sequence"] == 3
    assert summary["profile"]["coverage_call_count"] == 3
    assert summary["profile"]["coverage_snapshot_count"] == 3


def test_snapshot_summaries_sort_subject_then_newest_generation(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    old = _capture(code_hash="a" * 64, events=1)
    store.create(old)
    newer = _capture(code_hash="b" * 64, events=2)
    store.create(newer)
    other = _capture(code_hash="c" * 64, events=3)
    other["subject_key"] = "function:lab.alpha"
    other["subject"] = {"target_id": "lab.alpha"}
    other.pop("generation_id", None)
    store.create(other)

    summaries = store.list_summaries()

    assert [item["subject_key"] for item in summaries] == [
        "function:lab.alpha",
        "function:lab.divide",
        "function:lab.divide",
    ]
    divide = [item for item in summaries if item["subject_key"] == "function:lab.divide"]
    assert [item["code_hash"] for item in divide] == ["b" * 64, "a" * 64]


def test_snapshot_summaries_aggregate_bounded_hourly_call_activity(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    first = _capture(code_hash="a" * 64, events=2)
    first["profile"]["call_frequency_buckets"] = {
        "2026-08-17T10:00:00+00:00": 2,
    }
    second = _capture(code_hash="a" * 64, events=3)
    second["profile"]["call_frequency_buckets"] = {
        "2026-08-17T10:00:00+00:00": 1,
        "2026-08-17T11:00:00+00:00": 2,
    }
    store.create(first)
    store.create(second)

    summary = store.list_summaries()[0]

    assert summary["activity_kind"] == "utc-hour"
    assert summary["activity_windows"] == [
        {"started_at": "2026-08-17T10:00:00+00:00", "calls": 1},
        {"started_at": "2026-08-17T11:00:00+00:00", "calls": 2},
    ]


def test_partial_capture_does_not_mask_cumulative_generation_summary(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    epoch = _capture(code_hash="a" * 64, events=1)
    epoch["seal_reason"] = "sample-target-reached"
    epoch["profile"]["call_count"] = 1
    cumulative = store.create(epoch)["snapshot"]
    partial = _capture(code_hash="a" * 64, events=10)
    store.create(partial)

    summary = store.list_summaries()[0]

    assert summary["snapshot_id"] == cumulative["snapshot_id"]
    assert summary["profile"]["coverage_kind"] == "generation"
    assert summary["profile"]["coverage_call_count"] == 1


def test_summary_limit_allocates_three_generations_per_subject_before_older_rows(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    for subject in ("function:lab.alpha", "function:lab.zeta"):
        for generation in range(4):
            capture = _capture(code_hash=str(generation) * 64, events=1)
            capture["subject_key"] = subject
            capture["subject"] = {"target_id": subject.removeprefix("function:")}
            capture.pop("generation_id", None)
            store.create(capture)

    summaries = store.list_summaries(limit=6)

    counts = {
        subject: sum(item["subject_key"] == subject for item in summaries)
        for subject in ("function:lab.alpha", "function:lab.zeta")
    }
    assert counts == {"function:lab.alpha": 3, "function:lab.zeta": 3}


def test_overlapping_epoch_range_cannot_mask_prior_generation_coverage(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    first = _capture(code_hash="a" * 64, events=2)
    first["profile"]["call_count"] = 2
    first.update({
        "complete_epoch": True,
        "epoch_sequence": 1,
        "first_sample_sequence": 1,
        "last_sample_sequence": 2,
        "seal_reason": "operator-epoch-cut",
    })
    overlap = _capture(code_hash="a" * 64, events=2)
    overlap["profile"]["call_count"] = 2
    overlap.update({
        "complete_epoch": True,
        "epoch_sequence": 2,
        "first_sample_sequence": 2,
        "last_sample_sequence": 3,
        "seal_reason": "operator-epoch-cut",
    })
    valid = store.create(first)["snapshot"]
    store.create(overlap)

    summary = store.list_summaries()[0]

    assert summary["snapshot_id"] == valid["snapshot_id"]
    assert summary["profile"]["coverage_kind"] == "generation"
    assert summary["profile"]["coverage_call_count"] == 2


def test_missing_epoch_is_disclosed_without_discarding_later_disjoint_coverage(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    for epoch, first, last, calls in ((1, 1, 2, 2), (3, 101, 200, 100)):
        capture = _capture(code_hash="a" * 64, events=calls * 2)
        capture["profile"]["call_count"] = calls
        capture.update({
            "complete_epoch": True,
            "epoch_sequence": epoch,
            "first_sample_sequence": first,
            "last_sample_sequence": last,
            "seal_reason": "sample-target-reached",
        })
        store.create(capture)

    summary = store.list_summaries()[0]

    assert summary["profile"]["coverage_call_count"] == 102
    assert summary["profile"]["coverage_snapshot_count"] == 2
    assert summary["profile"]["coverage_gap_count"] == 1
    assert summary["profile"]["coverage_missing_sample_count"] == 98


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
