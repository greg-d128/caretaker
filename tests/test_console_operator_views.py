from __future__ import annotations

import asyncio

from caretaker.console import CaretakerConsoleApp
from rich.text import Text
from textual.widgets import Button, Checkbox, DataTable, Static


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
        "status": "VALIDATING",
    }

    assert CaretakerConsoleApp._target_matches_filter(target, "divide")
    assert CaretakerConsoleApp._target_matches_filter(
        target, "status:validating authority:approval guard:yes"
    )
    assert CaretakerConsoleApp._target_matches_filter(
        target, "state:probation mode:auto version:1"
    )
    assert not CaretakerConsoleApp._target_matches_filter(target, "guard:no")
    assert not CaretakerConsoleApp._target_matches_filter(target, "status:healthy")


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
