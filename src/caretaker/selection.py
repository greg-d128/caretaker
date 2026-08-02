from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable

from .domain import (
    CandidateScoreCard,
    CheckOutcome,
    RepairCandidate,
    ScorePenalty,
    ValidationCheckKind,
)
from .policy import RepairPolicy
from .validation import ValidationReport


@dataclass(frozen=True, slots=True)
class EvaluatedCandidate:
    candidate: RepairCandidate
    report: ValidationReport
    score: CandidateScoreCard


class CandidateScorer:
    def score(
        self,
        candidate: RepairCandidate,
        report: ValidationReport,
        policy: RepairPolicy,
    ) -> CandidateScoreCard:
        required_failures = [
            check for check in report.checks
            if check.outcome in {CheckOutcome.FAILED, CheckOutcome.ERROR}
            and check.kind not in {
                ValidationCheckKind.PERFORMANCE,
                ValidationCheckKind.GENERATED_TESTS,
            }
        ]
        correctness = 100.0 if not required_failures else 0.0
        contract_checks = [
            check for check in report.checks
            if check.kind in {
                ValidationCheckKind.FUNCTION_NAME,
                ValidationCheckKind.SIGNATURE,
                ValidationCheckKind.CALLABLE_KIND,
                ValidationCheckKind.RESPONSE_STRUCTURE,
            }
        ]
        contract = _pass_rate(contract_checks)

        penalties: list[ScorePenalty] = []
        safety = 100.0
        for finding in report.risk_findings:
            points = _risk_penalty(finding)
            safety -= points
            penalties.append(ScorePenalty(category="safety", points=points, reason=finding))
        safety = max(0.0, safety)

        original = report.measurements.get("original_median_seconds", 0.0)
        candidate_time = report.measurements.get("candidate_median_seconds", 0.0)
        if candidate_time <= 0:
            performance = 100.0
        elif original <= 0:
            performance = 90.0
        else:
            ratio = candidate_time / original
            performance = max(0.0, min(100.0, 110.0 - 50.0 * ratio))

        test_check = next(
            (check for check in report.checks if check.kind is ValidationCheckKind.REGISTERED_TESTS),
            None,
        )
        generated_check = next(
            (check for check in report.checks if check.kind is ValidationCheckKind.GENERATED_TESTS),
            None,
        )
        evidence = 50.0
        if test_check and test_check.outcome is CheckOutcome.PASSED:
            evidence += 35.0
        if generated_check and generated_check.outcome is CheckOutcome.PASSED:
            evidence += 15.0
        elif generated_check and generated_check.outcome is CheckOutcome.FAILED:
            evidence -= 15.0
        evidence = max(0.0, min(100.0, evidence))
        source = candidate.artifact.files[0].content
        maintainability = _maintainability_score(source)

        weights = policy.scoring
        total = (
            correctness * weights.correctness_weight
            + contract * weights.contract_weight
            + safety * weights.safety_weight
            + performance * weights.performance_weight
            + evidence * weights.evidence_weight
            + maintainability * weights.maintainability_weight
        )
        disqualifications = tuple(
            dict.fromkeys(
                tuple(check.summary for check in required_failures)
                + report.hard_disqualifications
                + report.review_required_findings
            )
        )
        eligible = (
            report.eligible
            and not disqualifications
            and total >= policy.selection.minimum_total_score
        )
        return CandidateScoreCard(
            candidate_id=candidate.candidate_id,
            scoring_profile_id=weights.profile_id,
            scoring_profile_version=weights.profile_version,
            eligible=eligible,
            total_score=round(total, 3),
            correctness_score=round(correctness, 3),
            contract_score=round(contract, 3),
            safety_score=round(safety, 3),
            performance_score=round(performance, 3),
            evidence_score=round(evidence, 3),
            maintainability_score=round(maintainability, 3),
            disqualifications=disqualifications,
            penalties=tuple(penalties),
            measurements=report.measurements,
        )


class CandidateSelector:
    def select(
        self,
        evaluated: Iterable[EvaluatedCandidate],
        policy: RepairPolicy,
    ) -> EvaluatedCandidate | None:
        eligible = [item for item in evaluated if item.score.eligible]
        if not eligible:
            return None
        if policy.selection.mode.name == "FIRST_ACCEPTABLE":
            return eligible[0]
        tie_breakers = policy.selection.tie_breakers
        scoring_weights = {
            "correctness_score": policy.scoring.correctness_weight,
            "contract_score": policy.scoring.contract_weight,
            "safety_score": policy.scoring.safety_weight,
            "performance_score": policy.scoring.performance_weight,
            "evidence_score": policy.scoring.evidence_weight,
            "maintainability_score": policy.scoring.maintainability_weight,
        }

        def key(item: EvaluatedCandidate) -> tuple[float, ...]:
            values = [item.score.total_score]
            for attribute in tie_breakers:
                if scoring_weights.get(attribute, 1.0) <= 0:
                    continue
                values.append(float(getattr(item.score, attribute, 0.0)))
            values.append(-float(len(item.candidate.artifact.files[0].content)))
            return tuple(values)

        return max(eligible, key=key)


def _pass_rate(checks: list[object]) -> float:
    if not checks:
        return 100.0
    passed = sum(
        1 for check in checks
        if getattr(check, "outcome", None) in {CheckOutcome.PASSED, CheckOutcome.SKIPPED}
    )
    return 100.0 * passed / len(checks)


def _risk_penalty(finding: str) -> float:
    lower = finding.lower()
    if "exec" in lower or "eval" in lower or "system" in lower:
        return 50.0
    if "import" in lower or "concurrency" in lower:
        return 20.0
    if "global" in lower or "nonlocal" in lower:
        return 15.0
    return 5.0


def _maintainability_score(source: str) -> float:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0.0
    branches = sum(
        isinstance(node, (ast.If, ast.For, ast.While, ast.Try, ast.Match, ast.BoolOp))
        for node in ast.walk(tree)
    )
    lines = len([line for line in source.splitlines() if line.strip()])
    return max(0.0, min(100.0, 105.0 - branches * 5.0 - max(0, lines - 30) * 0.5))
