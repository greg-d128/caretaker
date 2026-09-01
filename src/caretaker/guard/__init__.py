"""Caretaker Guard behavior-observation subsystem.

Imports are intentionally lazy so the repair policy can reference ``GuardBinding``
without importing audit collectors and the state-capture subsystem during package
initialization.
"""
from __future__ import annotations

from importlib import import_module

from .policy import (
    AggregationPolicy,
    AttributionPolicy,
    BaselinePolicy,
    CandidateGuardPolicy,
    CollectorPolicy,
    DeviationPolicy,
    GuardActionPolicy,
    GuardBinding,
    GuardPolicy,
    GuardTargetPolicy,
    LLMReviewPolicy,
    PeriodicInspectionPolicy,
    RetentionPolicy,
    SamplingPolicy,
)

_LAZY = {
    "BaselineManager": ("analytics", "BaselineManager"),
    "BehaviorAggregator": ("analytics", "BehaviorAggregator"),
    "DeviationDetector": ("analytics", "DeviationDetector"),
    "sensitive_file_network_sequences": ("analytics", "sensitive_file_network_sequences"),
    "StaticCandidateBehaviorAnalyzer": ("analytics", "StaticCandidateBehaviorAnalyzer"),
    "AuditEventCollector": ("collectors", "AuditEventCollector"),
    "DependencyCollector": ("collectors", "DependencyCollector"),
    "GuardEngine": ("engine", "GuardEngine"),
    "GuardFacade": ("facade", "GuardFacade"),
    "GuardHookManager": ("hooks", "GuardHookManager"),
    "CaretakerModuleFinder": ("imports", "CaretakerModuleFinder"),
    "CaretakerSupervisor": ("imports", "CaretakerSupervisor"),
    "GuardImportError": ("imports", "GuardImportError"),
    "ModuleRouter": ("imports", "ModuleRouter"),
    "RestartRequested": ("imports", "RestartRequested"),
    "PeriodicInspector": ("introspection", "PeriodicInspector"),
    "RuntimeInspector": ("introspection", "RuntimeInspector"),
    "AssessmentSeverity": ("models", "AssessmentSeverity"),
    "BaselineState": ("models", "BaselineState"),
    "BaselineAcceptanceRecord": ("models", "BaselineAcceptanceRecord"),
    "BehaviorAssessment": ("models", "BehaviorAssessment"),
    "BehaviorBaseline": ("models", "BehaviorBaseline"),
    "BehaviorDeviation": ("models", "BehaviorDeviation"),
    "BehavioralCandidateScore": ("models", "BehavioralCandidateScore"),
    "BehaviorProfile": ("models", "BehaviorProfile"),
    "BehaviorProfileSummary": ("models", "BehaviorProfileSummary"),
    "DeviationCategory": ("models", "DeviationCategory"),
    "GuardAction": ("models", "GuardAction"),
    "GuardDecision": ("models", "GuardDecision"),
    "GuardDeviationAction": ("models", "GuardDeviationAction"),
    "GuardEvidenceBundle": ("models", "GuardEvidenceBundle"),
    "GuardMode": ("models", "GuardMode"),
    "ImportRouteDecision": ("models", "ImportRouteDecision"),
    "InspectionLevel": ("models", "InspectionLevel"),
    "InstrumentationLease": ("models", "InstrumentationLease"),
    "ModuleRoutePolicy": ("models", "ModuleRoutePolicy"),
    "ModuleVariant": ("models", "ModuleVariant"),
    "BehaviorAssessmentProvider": ("provider", "BehaviorAssessmentProvider"),
    "BehaviorAssessmentRequest": ("provider", "BehaviorAssessmentRequest"),
    "OllamaBehaviorAssessmentProvider": ("provider", "OllamaBehaviorAssessmentProvider"),
    "StaticBehaviorAssessmentProvider": ("provider", "StaticBehaviorAssessmentProvider"),
}


def __getattr__(name: str):
    try:
        module_name, attribute = _LAZY[name]
    except KeyError as exc:
        raise AttributeError(name) from exc
    value = getattr(import_module(f"{__name__}.{module_name}"), attribute)
    globals()[name] = value
    return value


__all__ = [
    "AggregationPolicy",
    "AttributionPolicy",
    "BaselinePolicy",
    "CandidateGuardPolicy",
    "CollectorPolicy",
    "DeviationPolicy",
    "GuardActionPolicy",
    "GuardBinding",
    "GuardPolicy",
    "GuardTargetPolicy",
    "LLMReviewPolicy",
    "PeriodicInspectionPolicy",
    "RetentionPolicy",
    "SamplingPolicy",
    *_LAZY.keys(),
]
