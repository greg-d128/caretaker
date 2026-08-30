from __future__ import annotations

import asyncio
import stat
from pathlib import Path

from caretaker.console import CaretakerConsoleApp
from rich.text import Text
from textual.widgets import Button, Checkbox, DataTable, Input, RichLog, Static, TextArea


def test_target_runtime_state_marks_candidate_probation_as_validating():
    slot_state, candidate_state = CaretakerConsoleApp._target_runtime_states(
        {
            "ok": True,
            "state": {
                "slot": {
                    "state": "CANDIDATE_ACTIVE",
                    "observation": {"state": "ACTIVE_PROBATION"},
                }
            },
        }
    )
    target = {
        "slot_state": slot_state,
        "candidate_state": candidate_state,
        "repair_in_progress": False,
    }

    assert slot_state == "CANDIDATE_ACTIVE"
    assert candidate_state == "ACTIVE_PROBATION"
    assert CaretakerConsoleApp._target_status(target) == "VALIDATING"


def test_overview_displays_release_integrity_separately_from_policy(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app.socket_path = tmp_path / "control.sock"

            async def request(command: str, **payload):
                assert command == "status"
                return {
                    "ok": True,
                    "application_pid": 42,
                    "application_running": True,
                    "behavior_collection_id": "collection",
                    "behavior_revision": 0,
                    "workers": [],
                    "runtime": {"current_status": "READY", "alert_level": "NONE"},
                    "authority_policy": {
                        "overall_assurance": "UNCONFIGURED",
                        "violations": 0,
                        "runtime_matches_supervisor": True,
                    },
                    "release_integrity": {"status": "TRUSTED", "root_anchored": True},
                }

            app._request = request  # type: ignore[method-assign]
            await app.refresh_status()

            status = str(app.query_one("#operator-status", Static).render())
            details = str(app.query_one("#overview-details", Static).render())
            assert "Policy UNCONFIGURED" in status
            assert "Release integrity TRUSTED" in status
            assert "Release root externally anchored: yes" in details

    asyncio.run(exercise())


def test_target_status_preserves_terminal_slot_states():
    assert CaretakerConsoleApp._target_status(
        {"slot_state": "INITIALLY_VALIDATED"}
    ) == "INITIALLY_VALIDATED"
    assert CaretakerConsoleApp._target_status(
        {"slot_state": "LONG_TERM_ACCEPTED"}
    ) == "LONG_TERM_ACCEPTED"
    assert CaretakerConsoleApp._target_status(
        {"slot_state": "QUARANTINED"}
    ) == "QUARANTINED"


def test_target_filter_supports_named_fields_and_free_text():
    target = {
        "target_id": "lab.divide",
        "display_name": "Divide two values",
        "module": "examples.interactive_caretaker_lab",
        "qualified_name": "divide_values",
        "repair_mode": "AUTOMATIC",
        "repair_authority": "REQUIRE_OPERATOR_APPROVAL",
        "function_version": 1,
        "guard_enabled": True,
        "slot_state": "CANDIDATE_ACTIVE",
        "candidate_state": "ACTIVE_PROBATION",
        "slot_role": "TARGET_IMPLEMENTATION",
        "observation_level": "BEHAVIOR",
        "lifecycle_stage": "pre-repair-behavior",
        "lifecycle_label": "BEHAVIOR",
        "status": "VALIDATING",
    }

    assert CaretakerConsoleApp._target_matches_filter(target, "divide")
    assert CaretakerConsoleApp._target_matches_filter(
        target, "status:validating authority:approval guard:yes"
    )
    assert CaretakerConsoleApp._target_matches_filter(
        target, "state:probation mode:auto version:1"
    )
    assert CaretakerConsoleApp._target_matches_filter(
        target, "role:target level:behavior lifecycle:pre-repair"
    )
    assert not CaretakerConsoleApp._target_matches_filter(target, "guard:no")
    assert not CaretakerConsoleApp._target_matches_filter(target, "status:healthy")


def test_overview_presents_slot_role_and_escalation_level():
    assert CaretakerConsoleApp._slot_role_display("TARGET_IMPLEMENTATION") == "target"
    assert CaretakerConsoleApp._slot_role_display("OUTPUT_VALIDATOR") == "validator"
    assert CaretakerConsoleApp._observation_display("LIGHTWEIGHT") == "normal"
    assert CaretakerConsoleApp._observation_display("BEHAVIOR") == "escalated: behavior"
    assert CaretakerConsoleApp._observation_display(
        None, "TARGET_IMPLEMENTATION"
    ) == "not adaptive"
    app = CaretakerConsoleApp(None, Path("."))
    assert app._target_attention_reason({
        "target_id": "lab.probe",
        "status": "READY",
        "observation_level": "BEHAVIOR",
    }) == "behavior escalation"


def test_repair_source_extracts_pending_approval_source():
    record = {
        "record_kind": "pending_approval",
        "payload": {
            "episode_id": "episode-1",
            "source": "def divide_values(left, right):\n    return left / right\n",
        },
    }

    assert CaretakerConsoleApp._repair_source(record) == (
        "def divide_values(left, right):\n    return left / right\n"
    )
    assert CaretakerConsoleApp._repair_source({"payload": {}}) is None


def test_investigation_candidates_prioritize_security_channels_and_warnings():
    assert CaretakerConsoleApp._is_investigation_candidate(
        {"severity": 20, "channel": "GUARD"}
    )
    assert CaretakerConsoleApp._is_investigation_candidate(
        {"severity": 40, "channel": "APPLICATION"}
    )
    assert not CaretakerConsoleApp._is_investigation_candidate(
        {"severity": 20, "channel": "APPLICATION"}
    )


def test_guard_last_check_uses_latest_evidence_timestamp():
    assert CaretakerConsoleApp._latest_evidence_time(
        [{"created_at": "2026-08-16T10:00:00+00:00"}],
        [{"created_at": "2026-08-16T11:30:00+00:00"}],
    ) == "2026-08-16 11:30:00"
    assert CaretakerConsoleApp._latest_evidence_time([], []) == "never"


def test_guard_decision_subject_resolves_target_without_manual_identifier():
    assert CaretakerConsoleApp._subject_target(
        {"subject": {"target_id": "lab.divide"}}
    ) == "lab.divide"


def test_behavior_evidence_distinguishes_preliminary_from_collection_target():
    assert CaretakerConsoleApp._behavior_evidence({
        "profile": {
            "call_count": 1,
            "sampling_provenance": {"statistics_target": 1000},
        }
    }) == ("PRELIMINARY", "partial 1/1000")
    assert CaretakerConsoleApp._behavior_evidence({
        "profile": {
            "call_count": 1000,
            "sampling_provenance": {"statistics_target": 1000},
        }
    }) == ("TARGET REACHED", "partial 1000/1000")
    assert CaretakerConsoleApp._behavior_evidence({
        "profile": {
            "call_count": 1,
            "coverage_call_count": 12,
            "coverage_kind": "generation",
            "sampling_provenance": {"statistics_target": 1000},
        }
    }) == ("PRELIMINARY", "12/1000")


def test_behavior_activity_histogram_is_bounded_and_relative():
    record = {"activity_windows": [
        {"calls": 1}, {"calls": 5}, {"calls": 10}, {"calls": 0},
    ]}

    histogram = CaretakerConsoleApp._behavior_activity_histogram(record)

    assert len(histogram) == 4
    assert histogram[2] == "█"
    assert CaretakerConsoleApp._behavior_activity_histogram({}) == "-"


def test_behavior_zero_call_evidence_is_forensic_not_analytical():
    assert CaretakerConsoleApp._behavior_is_zero_call({
        "profile": {
            "call_count": 0,
            "event_count": 12,
            "coverage_kind": "snapshot",
        }
    }) is True
    assert CaretakerConsoleApp._behavior_is_zero_call({
        "profile": {
            "coverage_call_count": 0,
            "coverage_kind": "generation",
        }
    }) is True
    assert CaretakerConsoleApp._behavior_is_zero_call({
        "profile": {
            "call_count": 1,
            "coverage_kind": "snapshot",
        }
    }) is False


def test_behavior_list_hides_zero_call_evidence_until_requested(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)) as pilot:
            app._behavior_records = [
                {
                    "snapshot_id": "event-only",
                    "subject_key": "function:lab.event_only",
                    "profile": {"call_count": 0, "event_count": 4, "coverage_kind": "snapshot"},
                },
                {
                    "snapshot_id": "analyzable",
                    "subject_key": "function:lab.called",
                    "profile": {"coverage_call_count": 2, "coverage_kind": "generation"},
                },
            ]
            app._apply_behavior_filter()
            assert [item["snapshot_id"] for item in app._displayed_behavior_records] == ["analyzable"]
            title = str(app.query_one("#behavior-list-title", Static).render())
            assert "1 zero-call generation hidden" in title

            app.query_one("#behavior-show-zero-calls", Checkbox).value = True
            await pilot.pause()
            assert {item["snapshot_id"] for item in app._displayed_behavior_records} == {
                "event-only", "analyzable",
            }

    asyncio.run(exercise())


def test_behavior_list_shows_three_latest_generations_per_subject_by_default(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)) as pilot:
            app._behavior_records = [
                {
                    "snapshot_id": f"generation-{number}",
                    "subject_key": "function:lab.probe",
                    "generation_id": str(number),
                    "profile": {"coverage_call_count": number, "coverage_kind": "generation"},
                }
                for number in (4, 3, 2, 1)
            ]
            app._apply_behavior_filter()
            assert [item["snapshot_id"] for item in app._displayed_behavior_records] == [
                "generation-4", "generation-3", "generation-2",
            ]
            assert "1 older generation hidden" in str(
                app.query_one("#behavior-list-title", Static).render()
            )

            app.query_one("#behavior-show-older", Checkbox).value = True
            await pilot.pause()
            assert len(app._displayed_behavior_records) == 4

    asyncio.run(exercise())


def test_active_behavior_tab_refreshes_when_supervisor_revision_changes(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app.socket_path = tmp_path / "control.sock"
            app.query_one("TabbedContent").active = "behavior"
            app._behavior_collection_id = "collection-a"
            app._behavior_loaded_revision = 1
            app._behavior_records = [{
                "snapshot_id": "old-epoch",
                "subject_key": "function:lab.behavior_probe",
                "generation_id": "stable-generation",
                "profile": {"coverage_call_count": 50, "coverage_kind": "generation"},
            }]
            app._selected_behavior_snapshot = "old-epoch"
            requests: list[str] = []

            async def request(command: str, **payload):
                requests.append(command)
                if command == "status":
                    return {
                        "ok": True,
                        "application_running": False,
                        "behavior_collection_id": "collection-a",
                        "behavior_revision": 2,
                    }
                if command == "behavior-list":
                    return {
                        "ok": True,
                        "collection_id": "collection-a",
                        "revision": 2,
                        "snapshots": [{
                            "snapshot_id": "new-epoch",
                            "subject_key": "function:lab.behavior_probe",
                            "generation_id": "stable-generation",
                            "profile": {"coverage_call_count": 100, "coverage_kind": "generation"},
                        }],
                    }
                if command == "behavior-get":
                    assert payload["snapshot_id"] == "new-epoch"
                    return {
                        "ok": True,
                        "envelope": {
                            "snapshot": {
                                "snapshot_id": "new-epoch",
                                "subject_key": "function:lab.behavior_probe",
                                "generation_id": "stable-generation",
                                "profile": {"call_count": 100},
                            },
                            "integrity": {},
                        },
                    }
                raise AssertionError(command)

            app._request = request  # type: ignore[method-assign]
            await app.refresh_status()

            assert requests == ["status", "behavior-list", "behavior-get"]
            assert app._behavior_loaded_revision == 2
            assert app._behavior_collection_id == "collection-a"
            assert app._behavior_records[0]["snapshot_id"] == "new-epoch"
            assert app._selected_behavior_snapshot == "new-epoch"

    asyncio.run(exercise())


def test_behavior_auto_refresh_failure_is_contained_and_retried(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app.socket_path = tmp_path / "control.sock"
            app.query_one("TabbedContent").active = "behavior"
            app._behavior_loaded_revision = 1

            async def request(command: str, **payload):
                if command == "status":
                    return {
                        "ok": True,
                        "application_running": False,
                        "behavior_collection_id": "collection-a",
                        "behavior_revision": 2,
                    }
                if command == "behavior-list":
                    raise TimeoutError("summary scan still running")
                raise AssertionError(command)

            app._request = request  # type: ignore[method-assign]
            await app.refresh_status()

            assert app._behavior_loaded_revision == 1
            assert "auto-refresh delayed" in str(
                app.query_one("#behavior-list-title", Static).render()
            )

    asyncio.run(exercise())


def test_behavior_auto_refresh_preserves_open_comparison(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app.socket_path = tmp_path / "control.sock"
            app.query_one("TabbedContent").active = "behavior"
            app._behavior_collection_id = "collection-a"
            app._behavior_loaded_revision = 1
            app._behavior_view_mode = "comparison"
            app._behavior_last_comparison = {"snapshot_a_id": "reference", "snapshot_b_id": "selected"}
            app._behavior_records = [{
                "snapshot_id": "selected",
                "subject_key": "function:lab.behavior_probe",
                "generation_id": "generation-a",
                "profile": {"coverage_call_count": 100, "coverage_kind": "generation"},
            }]
            app._selected_behavior_snapshot = "selected"
            requests: list[str] = []

            async def request(command: str, **payload):
                requests.append(command)
                if command == "status":
                    return {
                        "ok": True,
                        "application_running": False,
                        "behavior_collection_id": "collection-a",
                        "behavior_revision": 2,
                    }
                if command == "behavior-list":
                    return {
                        "ok": True,
                        "collection_id": "collection-a",
                        "revision": 2,
                        "snapshots": [{
                            "snapshot_id": "selected-new",
                            "subject_key": "function:lab.behavior_probe",
                            "generation_id": "generation-a",
                            "profile": {"coverage_call_count": 200, "coverage_kind": "generation"},
                        }],
                    }
                raise AssertionError(f"comparison refresh must not request {command}")

            app._request = request  # type: ignore[method-assign]
            await app.refresh_status()

            assert requests == ["status", "behavior-list"]
            assert app._behavior_view_mode == "comparison"
            assert app._behavior_last_comparison is not None
            assert app._selected_behavior_snapshot == "selected-new"

    asyncio.run(exercise())


def test_behavior_refresh_pins_exact_reference_when_generation_representative_advances(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app.socket_path = tmp_path / "control.sock"
            app._behavior_collection_id = "collection-a"
            app._behavior_loaded_revision = 1
            app._behavior_records = [{
                "snapshot_id": "good-reference-epoch",
                "subject_key": "function:lab.behavior_probe",
                "generation_id": "unchanged-code",
                "created_at": "2026-08-17T10:00:00+00:00",
                "profile": {"coverage_call_count": 100, "coverage_kind": "generation"},
            }]
            app._behavior_references = {
                "function:lab.behavior_probe": "good-reference-epoch",
            }

            async def request(command: str, **payload):
                assert command == "behavior-list"
                return {
                    "ok": True,
                    "collection_id": "collection-a",
                    "revision": 2,
                    "snapshots": [{
                        "snapshot_id": "bad-new-epoch",
                        "subject_key": "function:lab.behavior_probe",
                        "generation_id": "unchanged-code",
                        "created_at": "2026-08-17T11:00:00+00:00",
                        "profile": {"coverage_call_count": 200, "coverage_kind": "generation"},
                    }],
                }

            app._request = request  # type: ignore[method-assign]
            await app.refresh_behavior()

            assert app._behavior_references == {
                "function:lab.behavior_probe": "good-reference-epoch",
            }
            assert {item["snapshot_id"] for item in app._behavior_records} == {
                "good-reference-epoch", "bad-new-epoch",
            }
            pinned = app._behavior_record("good-reference-epoch")
            assert pinned is not None
            assert pinned["pinned_reference_epoch"] is True
            app._selected_behavior_snapshot = "bad-new-epoch"
            app._refresh_behavior_actions()
            assert app.query_one("#behavior-compare", Button).disabled is False

    asyncio.run(exercise())


def test_behavior_collection_identity_clears_stale_state_when_revision_restarts(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app.socket_path = tmp_path / "control.sock"
            app.query_one("TabbedContent").active = "behavior"
            app._behavior_collection_id = "old-collection"
            app._behavior_loaded_revision = 0
            app._behavior_records = [{
                "snapshot_id": "old-snapshot",
                "subject_key": "function:lab.behavior_probe",
                "profile": {"coverage_call_count": 1000, "coverage_kind": "generation"},
            }]
            app._selected_behavior_snapshot = "old-snapshot"
            app._behavior_references = {
                "function:lab.behavior_probe": "old-snapshot",
            }

            async def request(command: str, **payload):
                if command == "status":
                    return {
                        "ok": True,
                        "application_running": False,
                        "behavior_collection_id": "new-collection",
                        "behavior_revision": 0,
                    }
                if command == "behavior-list":
                    return {
                        "ok": True,
                        "collection_id": "new-collection",
                        "revision": 0,
                        "snapshots": [],
                    }
                raise AssertionError(command)

            app._request = request  # type: ignore[method-assign]
            await app.refresh_status()

            assert app._behavior_collection_id == "new-collection"
            assert app._behavior_records == []
            assert app._selected_behavior_snapshot is None
            assert app._behavior_references == {}

    asyncio.run(exercise())


def test_behavior_table_marks_one_green_reference_per_subject(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app._behavior_records = [
                {
                    "snapshot_id": "alpha-new",
                    "subject_key": "function:lab.alpha",
                    "generation_id": "a2",
                    "profile": {"coverage_call_count": 2, "coverage_kind": "generation"},
                },
                {
                    "snapshot_id": "alpha-old",
                    "subject_key": "function:lab.alpha",
                    "generation_id": "a1",
                    "profile": {"coverage_call_count": 1, "coverage_kind": "generation"},
                },
                {
                    "snapshot_id": "beta-new",
                    "subject_key": "function:lab.beta",
                    "generation_id": "b1",
                    "profile": {"coverage_call_count": 1, "coverage_kind": "generation"},
                },
            ]
            app._behavior_references = {
                "function:lab.alpha": "alpha-new",
                "function:lab.beta": "beta-new",
            }
            app._apply_behavior_filter()
            table = app.query_one("#behavior-table")
            roles = [str(table.get_row_at(index)[1]) for index in range(table.row_count)]
            assert roles == ["REFERENCE", "", "REFERENCE"]
            reference = table.get_row_at(0)[1]
            assert isinstance(reference, Text)
            assert "green" in str(reference.style)

    asyncio.run(exercise())


def test_behavior_actions_use_subject_scoped_reference_workflow(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)) as pilot:
            app._activate_tab("behavior")
            await pilot.pause()
            app._application_running = True
            app._behavior_records = [
                {
                    "snapshot_id": "older",
                    "subject_key": "function:lab.probe",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "code_hash": "a" * 64,
                },
                {
                    "snapshot_id": "newer",
                    "subject_key": "function:lab.probe",
                    "created_at": "2026-01-02T00:00:00+00:00",
                    "code_hash": "b" * 64,
                },
            ]
            app._behavior_references = {"function:lab.probe": "newer"}
            app._selected_behavior_snapshot = "newer"
            app._refresh_behavior_actions()
            assert app.query_one("#behavior-set-reference", Button).disabled is True
            assert app.query_one("#behavior-compare", Button).disabled is True
            assert app.query_one("#behavior-archive", Button).disabled is True
            assert str(app.query_one("#behavior-archive", Button).label) == "Archive generation"
            assert str(app.query_one("#behavior-manage-confirm", Checkbox).label) == (
                "Confirm archive generation"
            )

            app.query_one("#behavior-archive-reason").value = "Superseded behavior"
            await pilot.pause()
            app.query_one("#behavior-manage-confirm", Checkbox).value = True
            await pilot.pause()
            assert app.query_one("#behavior-archive", Button).disabled is False

            app._selected_behavior_snapshot = "older"
            app._refresh_behavior_actions()
            assert app.query_one("#behavior-set-reference", Button).disabled is False
            assert app.query_one("#behavior-compare", Button).disabled is False
            status = str(app.query_one("#behavior-selection-status", Static).render())
            assert "Reference:" in status
            assert "Compare is available" in status

            await pilot.click("#behavior-set-reference")
            assert app._behavior_references["function:lab.probe"] == "older"
            assert app.query_one("#behavior-set-reference", Button).disabled is True
            assert app.query_one("#behavior-compare", Button).disabled is True

    asyncio.run(exercise())


def test_stale_table_selection_after_refresh_is_ignored(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            table = app.query_one("#behavior-table", DataTable)
            stale_key = table.add_row("1", "function", "lab.probe")
            table.clear()
            event = DataTable.RowSelected(table, 0, stale_key)
            await app.on_data_table_row_selected(event)

    asyncio.run(exercise())


def test_behavior_archive_controls_fit_in_console(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(100, 55)) as pilot:
            app._activate_tab("behavior")
            await pilot.pause()
            reason = app.query_one("#behavior-archive-reason")
            archive = app.query_one("#behavior-archive", Button)
            assert reason.region.width >= 18
            assert archive.region.width > 0
            assert archive.region.right <= app.size.width

    asyncio.run(exercise())


def test_behavior_snapshot_displays_collection_request_provenance(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(120, 55)) as pilot:
            app._activate_tab("behavior")
            app._show_behavior_snapshot(
                {
                    "snapshot": {
                        "snapshot_id": "snapshot-1",
                        "subject_key": "function:lab.probe",
                        "scope": "function",
                        "subject": {"module_name": "lab", "qualified_name": "probe"},
                        "profile": {"call_count": 2, "event_count": 2},
                        "collection_request": {
                            "request_id": "request-1",
                            "requested_by": "uid:1001",
                            "reason": "Investigate [untrusted] output",
                            "requested_calls": 50,
                            "observed_calls": 2,
                            "outcome": "CAPTURED",
                        },
                    },
                    "integrity": {"signature_state": "UNSIGNED"},
                }
            )
            await pilot.pause()
            path = app._save_active_report()
            report = path.read_text(encoding="utf-8")
            assert "Collection request provenance" in report
            assert "Investigate [untrusted] output" in report
            assert "uid:1001" in report

    asyncio.run(exercise())


def test_save_report_exports_active_tab_as_private_text(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(120, 55)) as pilot:
            app._activate_tab("behavior")
            await pilot.pause()
            app.query_one("#behavior-archive-reason").value = "Ticket CT-42"
            table = app.query_one("#behavior-table", DataTable)
            table.add_row(
                "1", "REFERENCE", "lab.probe", "abc123", "first", "last",
                "10/1000", "recent", "preliminary", "valid",
            )
            app.query_one("#behavior-output").write("Behavior comparison details")

            path = app._save_active_report()
            report = path.read_text(encoding="utf-8")
            assert path.parent == tmp_path / "reports"
            assert path.name.startswith("caretaker-behavior-")
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert "Tab: behavior" in report
            assert "behavior-archive-reason: Ticket CT-42" in report
            assert "lab.probe" in report
            assert "Behavior comparison details" in report

    asyncio.run(exercise())


def test_console_saves_current_operator_view_to_selected_incident_capsule(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(120, 55)):
            requests = []

            async def request(command: str, **payload):
                requests.append((command, payload))
                return {
                    "ok": True,
                    "artifact": {"artifact_id": "artifact-1"},
                }

            app._request = request  # type: ignore[method-assign]
            app._set_operator_context(
                target="lab.probe",
                incident="00000000-0000-0000-0000-000000000001",
                call="00000000-0000-0000-0000-000000000002",
            )
            button = app.query_one("#save-capsule-view", Button)
            assert button.disabled is False
            await app.on_button_pressed(Button.Pressed(button))

            assert len(requests) == 1
            command, payload = requests[0]
            assert command == "incident-capsule-attach-view"
            assert payload["incident_id"] == "00000000-0000-0000-0000-000000000001"
            assert payload["target_id"] == "lab.probe"
            assert payload["call_id"] == "00000000-0000-0000-0000-000000000002"
            assert payload["operator_view"].startswith("Caretaker Console Report")

    asyncio.run(exercise())


def test_console_incident_explorer_loads_verified_capsule_and_side_artifact(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)
    incident_id = "00000000-0000-0000-0000-000000000001"
    capsule_id = "00000000-0000-0000-0000-000000000011"
    artifact_id = "00000000-0000-0000-0000-000000000021"

    async def exercise() -> None:
        async with app.run_test(size=(120, 55)):
            requests = []

            async def request(command: str, **payload):
                requests.append((command, payload))
                if command == "incident-capsule-list":
                    return {"ok": True, "capsules": [{
                        "capsule_id": capsule_id,
                        "incident_id": incident_id,
                        "revision": 2,
                        "created_at": "2026-08-29T12:00:00+00:00",
                        "artifact_count": 1,
                        "communication_count": 0,
                        "integrity_status": "VERIFIED",
                    }]}
                if command == "incident-capsule-get":
                    return {"ok": True, "integrity_verified": True, "envelope": {
                        "capsule": {
                            "capsule_id": capsule_id,
                            "incident_id": incident_id,
                            "revision": 2,
                            "incident_state": {
                                "target": {
                                    "module_name": "lab",
                                    "qualified_name": "probe",
                                    "source_hash": "a" * 64,
                                },
                                "call": {
                                    "process_id": 42,
                                    "thread_id": 7,
                                    "bound_arguments": {"value": 3},
                                },
                                "failure": {
                                    "traceback": [{"locals": {"value": 3}}],
                                },
                                "state_differences": [],
                                "logs": [],
                            },
                            "artifacts": [{
                                "artifact_id": artifact_id,
                                "kind": "operator-view",
                                "created_at": "2026-08-29T12:01:00+00:00",
                                "source": "caretaker-console",
                                "content_sha256": "a" * 64,
                            }],
                            "communications": [],
                        },
                        "integrity": {"content_sha256": "b" * 64},
                    }}
                if command == "incident-capsule-artifact":
                    return {"ok": True, "integrity_verified": True, "envelope": {
                        "artifact": {"artifact_id": artifact_id, "content": {"view": "saved"}},
                        "integrity": {"content_sha256": "a" * 64},
                    }}
                if command == "incident-capsule-timeline":
                    return {"ok": True, "evidence_status": "PERSISTED_LOG_WINDOW", "records": [{
                        "record_id": "record-1",
                        "occurred_at": "2026-08-29T12:02:00+00:00",
                        "severity": 40,
                        "channel": "REPAIR",
                        "target_id": "lab.probe",
                        "message": "Incident created",
                        "evidence_status": "PERSISTED_LOG_RECORD",
                    }]}
                raise AssertionError(command)

            app._request = request  # type: ignore[method-assign]
            await app.refresh_incident_capsules()
            assert app.query_one("#incident-capsule-table", DataTable).row_count == 1
            await app._select_incident_capsule(app._capsule_records[0])
            assert app.query_one("#incident-artifact-table", DataTable).row_count == 1
            assert app.query_one("#incident-timeline-table", DataTable).row_count == 1
            evidence_sections = str(
                app.query_one("#incident-capsule-evidence-sections", Static).render()
            )
            assert "function state: CAPTURED" in evidence_sections
            assert "failure: CAPTURED" in evidence_sections
            assert "captured variables: CAPTURED" in evidence_sections
            assert "state differences: EMPTY" in evidence_sections
            assert "capsule integrity: VERIFIED" in evidence_sections
            await app._select_incident_timeline(app._incident_timeline_records[0])
            await app._select_incident_artifact(app._incident_artifact_records[0])
            assert requests == [
                ("incident-capsule-list", {"limit": 200}),
                ("incident-capsule-get", {"capsule_id": capsule_id}),
                ("incident-capsule-timeline", {"incident_id": incident_id, "limit": 200}),
                ("incident-capsule-artifact", {"artifact_id": artifact_id}),
            ]
            assert app._context_incident == incident_id

    asyncio.run(exercise())


def test_console_incident_explorer_requests_read_only_isolated_replay(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)
    incident_id = "00000000-0000-0000-0000-000000000001"
    capsule_id = "00000000-0000-0000-0000-000000000011"
    fixture_id = "00000000-0000-0000-0000-000000000021"
    source = "def charge(value):\n    return value + 1\n"

    async def exercise() -> None:
        async with app.run_test(size=(140, 60)):
            requests = []

            async def request(command: str, **payload):
                requests.append((command, payload))
                if command == "incident-capsule-list":
                    return {"ok": True, "capsules": [{
                        "capsule_id": capsule_id,
                        "incident_id": incident_id,
                        "revision": 1,
                        "created_at": "2026-08-29T12:00:00+00:00",
                        "artifact_count": 0,
                        "communication_count": 0,
                        "integrity_status": "VERIFIED",
                    }]}
                if command == "incident-capsule-get":
                    return {"ok": True, "envelope": {
                        "capsule": {
                            "capsule_id": capsule_id,
                            "incident_id": incident_id,
                            "revision": 1,
                            "incident_state": {"trigger": "exception"},
                            "artifacts": [],
                            "communications": [],
                        },
                        "integrity": {"content_sha256": "a" * 64},
                    }}
                if command == "incident-capsule-timeline":
                    return {"ok": True, "records": []}
                if command == "incident-capsule-replay":
                    return {
                        "ok": True,
                        "capsule_id": capsule_id,
                        "fixture_id": fixture_id,
                        "outcome": "PASSED",
                        "capsule_modified": False,
                        "integrity_verified": True,
                    }
                raise AssertionError(command)

            app._request = request  # type: ignore[method-assign]
            await app.refresh_incident_capsules()
            await app._select_incident_capsule(app._capsule_records[0])
            app.query_one("#incident-capsule-replay-fixture", Input).value = fixture_id
            app.query_one("#incident-capsule-replay-entrypoint", Input).value = "charge"
            app.query_one("#incident-capsule-replay-source", TextArea).text = source
            button = app.query_one("#incident-capsule-replay", Button)
            assert button.disabled is False
            await app.on_button_pressed(Button.Pressed(button))
            assert requests[-1] == (
                "incident-capsule-replay",
                {
                    "capsule_id": capsule_id,
                    "fixture_id": fixture_id,
                    "entrypoint": "charge",
                    "source": source,
                },
            )
            assert "PASSED" in str(
                app.query_one("#incident-capsule-detail-title", Static).render()
            )

    asyncio.run(exercise())


def test_console_creates_policy_governed_reviewable_communication_draft(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)
    incident_id = "00000000-0000-0000-0000-000000000001"
    capsule_id = "00000000-0000-0000-0000-000000000011"

    async def exercise() -> None:
        async with app.run_test(size=(140, 60)):
            requests = []

            async def request(command: str, **payload):
                requests.append((command, payload))
                if command == "incident-capsule-list":
                    return {"ok": True, "capsules": [{
                        "capsule_id": capsule_id,
                        "incident_id": incident_id,
                        "revision": 1,
                        "created_at": "2026-08-29T12:00:00+00:00",
                        "artifact_count": 0,
                        "communication_count": 0,
                        "integrity_status": "VERIFIED",
                    }]}
                if command == "incident-capsule-get":
                    return {"ok": True, "integrity_verified": True, "envelope": {
                        "capsule": {
                            "capsule_id": capsule_id,
                            "incident_id": incident_id,
                            "revision": 1,
                            "created_at": "2026-08-29T12:00:00+00:00",
                            "incident_state": {"trigger": "exception"},
                            "artifacts": [],
                            "communications": [],
                        },
                        "integrity": {"content_sha256": "b" * 64},
                    }}
                if command == "incident-capsule-timeline":
                    return {"ok": True, "records": []}
                if command == "incident-communication-draft":
                    return {
                        "ok": True,
                        "reviewable": True,
                        "delivery_authorized": False,
                        "recording": {"status": "RECORDED"},
                        "draft": {
                            "draft_id": "00000000-0000-0000-0000-000000000031",
                            "audience_profile_id": "operators-v1",
                        },
                    }
                if command == "incident-communication-review":
                    return {
                        "ok": True,
                        "reviewable": True,
                        "delivery_authorized": False,
                        "status": "RECORDED",
                    }
                raise AssertionError(command)

            app._request = request  # type: ignore[method-assign]
            await app.refresh_incident_capsules()
            await app._select_incident_capsule(app._capsule_records[0])
            assert "trigger" in str(app.query_one("#incident-capsule-facts", Static).render())
            assert "No communication records" in str(
                app.query_one("#incident-capsule-communications", Static).render()
            )
            app.query_one("#incident-communication-audience", Input).value = "operators-v1"
            button = app.query_one("#incident-communication-draft", Button)
            assert button.disabled is False
            await app.on_button_pressed(Button.Pressed(button))

            assert requests[-1] == (
                "incident-communication-draft",
                {
                    "capsule_id": capsule_id,
                    "audience_profile_id": "operators-v1",
                    "record": True,
                },
            )
            app.query_one("#incident-communication-review-reason", Input).value = "Reviewed facts"
            approve = app.query_one("#incident-communication-approve", Button)
            await app.on_button_pressed(Button.Pressed(approve))
            assert requests[-1] == (
                "incident-communication-review",
                {
                    "capsule_id": capsule_id,
                    "draft_id": "00000000-0000-0000-0000-000000000031",
                    "decision": "approved",
                    "reason": "Reviewed facts",
                },
            )

    asyncio.run(exercise())


def test_console_displays_read_only_worker_failure_recovery_status(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)):
            requests = []

            async def request(command: str, **payload):
                requests.append((command, payload))
                assert command == "worker-failure-recovery-status"
                return {
                    "ok": True,
                    "available": True,
                    "read_only": True,
                    "authority_granted": False,
                    "bounded": True,
                    "failure_count": 1,
                    "recovery_count": 1,
                    "conflict_count": 1,
                    "failures": [{
                        "failure_id": "failure-1",
                        "worker_id": "worker-1",
                        "reconciliation_scope": "transaction:one",
                        "target_id": "app:charge",
                        "postmortem_status": "INCOMPLETE",
                        "critical_evidence": True,
                        "observed_at": "2026-08-30T12:00:00+00:00",
                    }],
                    "recoveries": [{
                        "recovery_id": "recovery-1",
                        "scope": "transaction:one",
                        "target_id": "app:charge",
                        "action": "GENERATE_INCIDENT",
                        "critical_evidence_conflict": True,
                        "action_execution": {"status": "PENDING"},
                        "observed_at": "2026-08-30T12:00:00+00:00",
                    }],
                    "conflicts": [{
                        "report_id": "report-1",
                        "scope": "transaction:one",
                        "reason": "incomplete post-mortem",
                        "observed_at": "2026-08-30T12:00:00+00:00",
                    }],
                }

            app._request = request  # type: ignore[method-assign]
            await app.refresh_worker_failure_recovery()

            assert requests == [
                ("worker-failure-recovery-status", {"limit": 200})
            ]
            assert app.query_one("#worker-failure-recovery-table", DataTable).row_count == 3
            status = str(
                app.query_one("#worker-failure-recovery-status", Static).render()
            )
            assert "Failures 1" in status
            assert "Checkpoints 1" in status
            assert "Conflicts 1" in status
            assert "Read-only" in status

    asyncio.run(exercise())


def test_console_displays_read_only_adaptive_transition_deadlines(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(160, 55)):
            requests = []

            async def request(command: str, **payload):
                requests.append((command, payload))
                assert command == "adaptive-aggregation-status"
                return {
                    "ok": True,
                    "store": {"aggregates": 1, "transition_requests": 1},
                    "aggregates": [{
                        "target_id": "app:charge",
                        "aggregation_target_id": "app:charge::aggregation-scope::blue",
                        "aggregation_scope": "blue",
                        "generation_id": "generation-1",
                        "enabled": True,
                        "total_batches": 4,
                        "workers": {"worker-a": {"worker_pid": 123}},
                    }],
                    "transitions": [{
                        "request_id": "request-1",
                        "target_id": "app:charge",
                        "aggregation_target_id": "app:charge::aggregation-scope::blue",
                        "aggregation_scope": "blue",
                        "generation_id": "generation-1",
                        "status": "EXPIRED",
                        "deadline_status": "EXPIRED",
                        "required_workers": [{"worker_id": "worker-a"}],
                        "acknowledgement_count": 0,
                        "stale_worker_ids": ["worker-a"],
                        "expires_at": "2026-08-30T12:00:30+00:00",
                    }],
                }

            app._request = request  # type: ignore[method-assign]
            await app.refresh_adaptive_aggregation()

            assert requests == [("adaptive-aggregation-status", {})]
            assert app.query_one("#adaptive-aggregation-table", DataTable).row_count == 2
            status = str(
                app.query_one("#adaptive-aggregation-status", Static).render()
            )
            assert "Aggregates 1" in status
            assert "Transitions 1" in status
            assert "Expired 1" in status
            assert "Read-only" in status

    asyncio.run(exercise())


def test_consequential_console_actions_fail_closed(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)) as pilot:
            app._application_running = True
            app._selected_repair_approval = "episode-1"
            repair_confirm = app.query_one("#repair-approve-confirm", Checkbox)
            repair_confirm.disabled = False
            repair_confirm.value = True
            await pilot.pause()
            assert app.query_one("#repair-approve", Button).disabled is False
            assert app.query_one("#repair-reject", Button).disabled is False

            app.query_one("#policy-reason").value = "incident-42"
            app.query_one("#policy-signed-descriptor").value = "lease.json"
            await pilot.pause()
            signed_confirm = app.query_one("#policy-signed-confirm", Checkbox)
            assert signed_confirm.disabled is False
            assert app.query_one("#policy-apply-signed", Button).disabled is True
            signed_confirm.value = True
            await pilot.pause()
            assert app.query_one("#policy-apply-signed", Button).disabled is False

            app._selected_authority_lease = "lease-1"
            release_confirm = app.query_one("#policy-release-confirm", Checkbox)
            release_confirm.disabled = False
            release_confirm.value = True
            await pilot.pause()
            assert app.query_one("#policy-release", Button).disabled is False

    asyncio.run(exercise())


def test_attention_view_combines_operator_issues_and_shared_context(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app._last_runtime = {
                "active_incidents": [{
                    "incident_id": "incident-1",
                    "target_id": "lab.probe",
                    "trigger": "unexpected filesystem activity",
                }],
                "degraded_components": ["guard:audit_hooks"],
            }
            app._repair_records = [{
                "state": "WAITING",
                "target_id": "lab.probe",
                "description": "Validated repair awaiting approval",
                "payload": {"incident_id": "incident-1"},
            }]
            app._authority_snapshot = {
                "violations": [{"target": "lab.*", "message": "deployment guarantee violated"}]
            }
            app._refresh_attention()

            assert {item["kind"] for item in app._attention_records} == {
                "ACTIVE INCIDENT",
                "DEGRADED",
                "REPAIR WAITING",
                "POLICY VIOLATION",
            }
            app._set_operator_context(target="lab.probe", incident="incident-1")
            rendered = str(app.query_one("#operator-context-label", Static).render())
            assert "target=lab.probe" in rendered
            assert "incident=incident-1" in rendered
            assert app.query_one("#context-clear", Button).disabled is False

    asyncio.run(exercise())


def test_guard_operator_state_distinguishes_no_evidence_learning_and_findings():
    assert CaretakerConsoleApp._guard_state(None, [], []) == "NO EVIDENCE"
    assert CaretakerConsoleApp._guard_state({"calls": 1}, [], []) == "LEARNING"
    assert CaretakerConsoleApp._guard_state({"calls": 10}, [], [{"ok": True}]) == "HEALTHY"
    assert CaretakerConsoleApp._guard_state({}, [{"severity": "HIGH"}], []) == "DEVIATION"
    assert CaretakerConsoleApp._guard_severity([
        {"severity": "LOW"},
        {"severity": "HIGH"},
    ]) == "HIGH"


def test_behavior_title_exposes_collection_queue_state(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
            app._behavior_collection_status = {
                "collections": [{
                    "enabled": True,
                    "active": 1,
                    "maximum_active": 2,
                    "queued": 3,
                    "maximum_pending": 10,
                    "counts": {"failed": 1, "cancelled": 2},
                    "backlog": {"counts": {"armed_waiting": 4, "sufficiently_covered": 2}},
                }]
            }
            app._behavior_records = []
            app._apply_behavior_filter()
            title = str(app.query_one("#behavior-list-title", Static).render())
            assert "collection queue active 1/2, queued 3/10; terminal failed 1, cancelled 2; backlog armed_waiting 4, sufficiently_covered 2" in title

    asyncio.run(exercise())


def test_policy_change_requires_preview_and_acknowledgement(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)) as pilot:
            app._activate_tab("policy")
            await pilot.pause()
            app.query_one("#policy-target").value = "lab.probe"
            app.query_one("#policy-path").value = "repair.authority"
            app.query_one("#policy-value").value = "REQUIRE_OPERATOR_APPROVAL"
            app.query_one("#policy-reason").value = "incident review"
            await pilot.pause()
            await pilot.click("#policy-preview")

            assert app._policy_preview == {
                "path": "repair.authority",
                "value": "REQUIRE_OPERATOR_APPROVAL",
                "target": "lab.probe",
                "duration_seconds": 3600,
                "reason": "incident review",
                "override_constraints": False,
            }
            assert app.query_one("#policy-confirm", Checkbox).disabled is False
            assert app.query_one("#policy-apply", Button).disabled is True

            app.query_one("#policy-confirm", Checkbox).value = True
            await pilot.pause()
            assert app.query_one("#policy-apply", Button).disabled is False

            app.query_one("#policy-value").value = "AUTOMATIC_ELIGIBLE_REPAIRS"
            await pilot.pause()
            assert app._policy_preview is None
            assert app.query_one("#policy-apply", Button).disabled is True

    asyncio.run(exercise())


def test_investigation_candidates_explain_why_they_are_selected():
    assert CaretakerConsoleApp._investigation_reason({
        "channel": "GUARD", "severity": 20,
    }) == "Guard evidence"
    assert CaretakerConsoleApp._investigation_reason({
        "channel": "APPLICATION", "severity": 40,
    }) == "Error-level event"
    assert CaretakerConsoleApp._investigation_reason({
        "channel": "APPLICATION", "severity": 30,
    }) == "Warning-level event"
