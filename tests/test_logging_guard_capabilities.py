from __future__ import annotations

import pytest

from caretaker.guard import GuardEngine, GuardPolicy
from caretaker.logging import LoggingCapability, RequiredCapabilityFailureAction


def test_guard_can_continue_degraded_with_missing_logging_capabilities():
    engine = GuardEngine(policy=GuardPolicy(
        logging_failure_action=RequiredCapabilityFailureAction.CONTINUE_DEGRADED,
    ))
    missing = engine.update_logging_capabilities(frozenset({LoggingCapability.APPLICATION_LOGS}))
    assert missing


def test_strict_guard_refuses_transition_without_required_logging():
    engine = GuardEngine(policy=GuardPolicy(
        logging_failure_action=RequiredCapabilityFailureAction.REFUSE_MODE_TRANSITION,
    ))
    with pytest.raises(RuntimeError, match="required logging"):
        engine.update_logging_capabilities(frozenset())
