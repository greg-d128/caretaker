from __future__ import annotations

import asyncio

from caretaker.console import CaretakerConsoleApp
from textual.widgets import Button, Static


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
    }) == ("PRELIMINARY", "window 1/1000")
    assert CaretakerConsoleApp._behavior_evidence({
        "profile": {
            "call_count": 1000,
            "sampling_provenance": {"statistics_target": 1000},
        }
    }) == ("TARGET REACHED", "window 1000/1000")
    assert CaretakerConsoleApp._behavior_evidence({
        "profile": {
            "call_count": 1,
            "coverage_call_count": 12,
            "coverage_kind": "generation",
            "sampling_provenance": {"statistics_target": 1000},
        }
    }) == ("PRELIMINARY", "gen 12/1000")


def test_behavior_actions_explain_and_enforce_a_b_workflow(tmp_path):
    app = CaretakerConsoleApp(None, tmp_path)

    async def exercise() -> None:
        async with app.run_test(size=(180, 55)):
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
            app._selected_behavior_snapshot = "newer"
            app._refresh_behavior_actions()
            assert app.query_one("#behavior-compare-live", Button).disabled is False
            assert app.query_one("#behavior-compare-previous", Button).disabled is False
            assert app.query_one("#behavior-compare-a", Button).disabled is True

            app._behavior_compare_anchor = "older"
            app._refresh_behavior_actions()
            assert app.query_one("#behavior-compare-a", Button).disabled is False
            assert app.query_one("#behavior-compare-latest", Button).disabled is False
            status = str(app.query_one("#behavior-selection-status", Static).render())
            assert "cross-generation allowed" in status
            assert "A↔latest" in status

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
