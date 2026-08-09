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
