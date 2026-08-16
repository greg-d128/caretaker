from __future__ import annotations

from caretaker.console import CaretakerConsoleApp


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
    }) == ("PRELIMINARY", "1/1000")
    assert CaretakerConsoleApp._behavior_evidence({
        "profile": {
            "call_count": 1000,
            "sampling_provenance": {"statistics_target": 1000},
        }
    }) == ("TARGET REACHED", "1000/1000")
