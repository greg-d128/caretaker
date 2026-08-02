from __future__ import annotations

from uuid import uuid4

from caretaker import InMemoryEvidenceStore, RuntimeControlPlane
from caretaker.guard.hooks import GuardHookManager
from caretaker.guard.introspection import RuntimeInspector
from caretaker.guard.models import (
    AssessmentSeverity,
    BehaviorAssessment,
)
from caretaker.guard.provider import BehaviorAssessmentRequest, StaticBehaviorAssessmentProvider
from caretaker.guard.models import GuardEvidenceBundle
from caretaker.evidence import identify_function
from tests.guard_targets import stable


def test_global_hook_adapter_emits_post_mortem_signal() -> None:
    plane = RuntimeControlPlane()
    hooks = GuardHookManager(
        run_id=uuid4(),
        control_plane=plane,
        inspector=RuntimeInspector(InMemoryEvidenceStore()),
    )
    hooks._capture("sys.excepthook", RuntimeError("failure"), None)
    assert plane.signals[-1].kind == "sys.excepthook"
    assert plane.signals[-1].attributes["post_mortem_only"] is True


def test_behavior_assessment_provider_is_separate_from_repair_provider() -> None:
    subject = identify_function(stable)
    assessment = BehaviorAssessment(
        assessment_id=uuid4(),
        subject=subject,
        baseline_id=None,
        deviation_ids=(),
        severity=AssessmentSeverity.LOW,
        confidence=0.8,
        significant_changes=("new import",),
        suspicious_patterns=(),
        plausible_benign_explanations=("new optional feature",),
        recommended_actions=("collect more evidence",),
        requested_additional_evidence=("stack sample",),
        provider_name="static",
        model_name=None,
        prompt_version="test",
        response_hash="abc",
    )
    provider = StaticBehaviorAssessmentProvider(assessment)
    bundle = GuardEvidenceBundle(
        subject=subject,
        baseline_summary=None,
        observation_summary=None,
        deviations=(),
        representative_events=(),
    )
    assert provider.assess(BehaviorAssessmentRequest(bundle, "policy")) is assessment
