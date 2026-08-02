from __future__ import annotations

from caretaker import RepairPolicy
from caretaker.registry import build_target
from caretaker.domain import TargetCapability
import caretaker.runtime


def test_caretaker_internal_code_is_never_repairable():
    target = build_target(caretaker.runtime.snapshot_context, policy=RepairPolicy())
    assert target.support.capability is TargetCapability.DIAGNOSTIC_ONLY
    assert any("never eligible" in reason for reason in target.support.reasons)
