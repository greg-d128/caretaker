from __future__ import annotations

import json
import tarfile
from datetime import datetime, timezone
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
    assert comparison["return_novelty"]["state"] == "incomparable"
    assert comparison["return_novelty"]["reason"] == "different-generation"


def test_return_novelty_report_is_generation_and_sample_bound(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    older = _capture(code_hash="a" * 64, events=20)
    older["profile"].update({
        "success_count": 20,
        "return_categories": {"integer:builtins.int": 20},
        "return_shapes": {"scalar": 20},
    })
    newer = _capture(code_hash="a" * 64, events=20)
    newer["profile"].update({
        "success_count": 20,
        "return_categories": {
            "integer:builtins.int": 19,
            "text:builtins.str": 1,
        },
        "return_shapes": {"scalar": 19, "text:length-small": 1},
    })
    left = store.create(older)
    right = store.create(newer)

    novelty = compare_snapshots(left, right)["return_novelty"]

    assert novelty["state"] == "new-observations"
    assert novelty["new_categories"] == ["text:builtins.str"]
    assert novelty["new_category_counts"] == {"text:builtins.str": 1}
    assert novelty["new_shapes"] == ["text:length-small"]
    assert novelty["coverage_complete"] is True
    assert novelty["absence_claim_allowed"] is True
    assert novelty["evidence_only"] is True


def test_return_novelty_does_not_claim_absence_when_coverage_is_incomplete(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    older = _capture(code_hash="a" * 64, events=20)
    older["profile"].update({
        "success_count": 20,
        "return_categories": {"integer:builtins.int": 20},
        "return_category_coverage_complete": False,
        "return_shapes": {"scalar": 20},
        "return_shape_coverage_complete": False,
    })
    newer = _capture(code_hash="a" * 64, events=20)
    newer["profile"].update({
        "success_count": 20,
        "return_categories": {"integer:builtins.int": 20},
        "return_category_coverage_complete": False,
        "return_shapes": {"scalar": 20},
        "return_shape_coverage_complete": False,
    })
    left = store.create(older)
    right = store.create(newer)

    novelty = compare_snapshots(left, right)["return_novelty"]

    assert novelty["state"] == "no-new-observations"
    assert novelty["coverage_complete"] is False
    assert novelty["absence_claim_allowed"] is False


def test_return_novelty_requires_successful_sample_minimum(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    older = _capture(code_hash="a" * 64, events=19)
    older["profile"].update({
        "success_count": 19,
        "return_categories": {"integer:builtins.int": 19},
        "return_shapes": {"scalar": 19},
    })
    newer = _capture(code_hash="a" * 64, events=20)
    newer["profile"].update({
        "success_count": 20,
        "return_categories": {"text:builtins.str": 20},
        "return_shapes": {"text:length-small": 20},
    })
    left = store.create(older)
    right = store.create(newer)

    novelty = compare_snapshots(left, right)["return_novelty"]

    assert novelty["state"] == "insufficient-evidence"
    assert novelty["reason"] == "minimum-success-samples-not-reached"
    assert novelty["new_categories"] == []
    assert novelty["absence_claim_allowed"] is False


def test_duration_distribution_report_surfaces_three_sigma_shift(
    tmp_path: Path, monkeypatch
):
    store = BehaviorSnapshotStore(tmp_path)
    older = _capture(code_hash="a" * 64, events=100)
    older["profile"]["statistics"] = {
        "duration_seconds": {
            "count": 100,
            "average": 0.010,
            "standard_deviation": 0.001,
            "p50": 0.010,
            "p95": 0.012,
        }
    }
    newer = _capture(code_hash="a" * 64, events=100)
    newer["profile"]["statistics"] = {
        "duration_seconds": {
            "count": 100,
            "average": 0.020,
            "standard_deviation": 0.001,
            "p50": 0.020,
            "p95": 0.022,
        }
    }
    timestamps = iter(
        (
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
            datetime(2026, 1, 2, tzinfo=timezone.utc),
            datetime(2026, 1, 3, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("caretaker.behavior.utcnow", lambda: next(timestamps))

    left = store.create(older)
    right = store.create(newer)
    report = compare_snapshots(left, right)["duration_distribution"]

    assert report["evidence_only"] is True
    assert report["state"] == "shift-signal"
    assert report["reason"] == "three-sigma-distribution-signal"
    assert report["mean_shift_at_three_sigma"] is True
    assert report["spread_shift_at_three_sigma"] is False
    assert report["reference"]["count"] == 100
    assert report["selected"]["count"] == 100
    assert report["mean_sigma"] > 3.0
    assert report["quantile_changes"]["p50"]["absolute"] == 0.010

    monkeypatch.setattr(
        "caretaker.behavior.utcnow",
        lambda: datetime(2026, 1, 3, tzinfo=timezone.utc),
    )
    configured_report = compare_snapshots(
        left,
        right,
        duration_distribution_sigma_threshold=100.0,
    )["duration_distribution"]
    assert configured_report["state"] == "no-shift-signal"
    assert configured_report["reason"] == "no-configured-distribution-threshold-signal"
    assert configured_report["mean_shift_at_threshold"] is False


def test_duration_distribution_report_preserves_insufficient_or_legacy_evidence(
    tmp_path: Path, monkeypatch
):
    store = BehaviorSnapshotStore(tmp_path)
    older = _capture(code_hash="a" * 64, events=10)
    older["profile"]["statistics"] = {
        "duration_seconds": {"count": 10, "average": 0.010}
    }
    newer = _capture(code_hash="a" * 64, events=100)
    newer["profile"]["statistics"] = {
        "duration_seconds": {
            "count": 100,
            "average": 0.020,
            "standard_deviation": 0.001,
        }
    }
    timestamps = iter(
        (
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            datetime(2026, 2, 2, tzinfo=timezone.utc),
            datetime(2026, 2, 2, tzinfo=timezone.utc),
            datetime(2026, 2, 3, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("caretaker.behavior.utcnow", lambda: next(timestamps))

    report = compare_snapshots(store.create(older), store.create(newer))[
        "duration_distribution"
    ]

    assert report["state"] == "insufficient-evidence"
    assert report["reason"] == "minimum-duration-samples-not-reached"
    assert report["mean_shift_at_three_sigma"] is False
    assert report["absence_claim_allowed"] is False


def test_duration_distribution_report_bounds_zero_variance_signals(
    tmp_path: Path, monkeypatch
):
    store = BehaviorSnapshotStore(tmp_path)
    older = _capture(code_hash="a" * 64, events=20)
    older["profile"]["statistics"] = {
        "duration_seconds": {
            "count": 20,
            "average": 0.010,
            "standard_deviation": 0.0,
        }
    }
    newer = _capture(code_hash="a" * 64, events=20)
    newer["profile"]["statistics"] = {
        "duration_seconds": {
            "count": 20,
            "average": 0.010,
            "standard_deviation": 0.100,
        }
    }
    timestamps = iter(
        (
            datetime(2026, 3, 1, tzinfo=timezone.utc),
            datetime(2026, 3, 1, tzinfo=timezone.utc),
            datetime(2026, 3, 2, tzinfo=timezone.utc),
            datetime(2026, 3, 2, tzinfo=timezone.utc),
            datetime(2026, 3, 3, tzinfo=timezone.utc),
        )
    )
    monkeypatch.setattr("caretaker.behavior.utcnow", lambda: next(timestamps))

    report = compare_snapshots(store.create(older), store.create(newer))[
        "duration_distribution"
    ]

    assert report["state"] == "shift-signal"
    assert report["mean_shift_at_three_sigma"] is False
    assert report["spread_shift_at_three_sigma"] is True
    assert report["spread_ratio"] is None
    assert report["spread_ratio_unbounded"] is True
    assert json.dumps(report, allow_nan=False)


def test_operator_capture_provenance_is_bounded_persisted_and_hash_protected(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    capture = _capture(code_hash="a" * 64, events=3)
    capture["collection_request"] = {
        "request_id": "request-1",
        "requested_at": "2026-08-29T12:00:00+00:00",
        "requested_by": "uid:1001",
        "reason": "r" * 600,
        "scope": "function",
        "subject": "lab.divide",
        "requested_calls": 5000,
        "requested_generation": "generation-requested",
        "observed_generation": "generation-observed",
        "observed_calls": -4,
        "outcome": "CAPTURED",
        "completed_at": "2026-08-29T12:00:01+00:00",
        "authority_policy_generation": "authority-3",
        "authority_policy_fingerprint": "f" * 64,
        "untrusted_extra": "not retained",
    }

    envelope = store.create(capture)
    request = envelope["snapshot"]["collection_request"]

    assert request["request_id"] == "request-1"
    assert request["requested_by"] == "uid:1001"
    assert len(request["reason"]) == 500
    assert request["requested_calls"] == 1000
    assert request["observed_calls"] == 0
    assert "untrusted_extra" not in request
    assert store.load(envelope["snapshot"]["snapshot_id"]) == envelope

    path = store.snapshot_directory / f"{envelope['snapshot']['snapshot_id']}.json"
    tampered = envelope.copy()
    tampered["snapshot"] = dict(envelope["snapshot"])
    tampered["snapshot"]["collection_request"] = dict(request)
    tampered["snapshot"]["collection_request"]["reason"] = "tampered"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    assert store.list()[0]["verified"] is False


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


def test_archive_generation_removes_all_epochs_and_records_reason(tmp_path: Path):
    store = BehaviorSnapshotStore(tmp_path)
    first = store.create(_capture(code_hash="a" * 64, events=10))
    second = store.create(_capture(code_hash="a" * 64, events=20))
    other = store.create(_capture(code_hash="b" * 64, events=30))
    subject_key = first["snapshot"]["subject_key"]
    generation_id = first["snapshot"]["generation_id"]

    archive_path, archived_ids = store.archive_generation(
        subject_key,
        generation_id,
        reason="Superseded by the deployed generation",
    )

    assert set(archived_ids) == {
        first["snapshot"]["snapshot_id"],
        second["snapshot"]["snapshot_id"],
    }
    assert {item["snapshot_id"] for item in store.list()} == {
        other["snapshot"]["snapshot_id"]
    }
    with tarfile.open(archive_path, "r:gz") as archive:
        manifest_file = archive.extractfile("manifest.json")
        assert manifest_file is not None
        manifest = json.loads(manifest_file.read())
    assert manifest["reason"] == "Superseded by the deployed generation"
    assert manifest["subject_key"] == subject_key
    assert manifest["generation_id"] == generation_id


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
