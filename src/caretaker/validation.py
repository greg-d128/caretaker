from __future__ import annotations

import ast
import json
import os
import pickle
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from .domain import (
    CheckOutcome,
    RepairArtifactKind,
    RepairCandidate,
    ValidationCheckKind,
    ValidationCheckResult,
    utcnow,
)
from .registry import RepairTarget


@dataclass(frozen=True, slots=True)
class StaticAssessment:
    hard_disqualifications: tuple[str, ...]
    review_required_findings: tuple[str, ...]
    risk_findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationReport:
    candidate_id: object
    eligible: bool
    checks: tuple[ValidationCheckResult, ...]
    measurements: dict[str, float]
    risk_findings: tuple[str, ...]
    hard_disqualifications: tuple[str, ...] = ()
    review_required_findings: tuple[str, ...] = ()
    worker_stdout: str = ""
    worker_stderr: str = ""


class SubprocessValidationBackend:
    def __init__(self, python_executable: str | None = None) -> None:
        self.python_executable = python_executable or sys.executable

    def validate_candidate(
        self,
        candidate: RepairCandidate,
        target: RepairTarget,
        *,
        timeout_seconds: float,
        regression_cases: tuple[Any, ...] = (),
    ) -> ValidationReport:
        if candidate.artifact.kind is not RepairArtifactKind.FUNCTION_REPLACEMENT:
            now = utcnow()
            check = ValidationCheckResult(
                kind=ValidationCheckKind.RESPONSE_STRUCTURE,
                outcome=CheckOutcome.FAILED,
                started_at=now,
                finished_at=now,
                summary=f"Unsupported repair artifact kind: {candidate.artifact.kind.name}",
            )
            return ValidationReport(
                candidate_id=candidate.candidate_id,
                eligible=False,
                checks=(check,),
                measurements={},
                risk_findings=(),
                hard_disqualifications=(check.summary,),
            )

        source = candidate.artifact.files[0].content
        assessment = assess_candidate_source(source)
        registered_cases = (
            target.registered_cases + tuple(regression_cases)
            if target.policy.validation.run_registered_tests
            else ()
        )
        generated_tests = (
            tuple(test.source for test in candidate.generated_tests)
            if target.policy.validation.run_generated_tests
            else ()
        )
        payload = {
            "mode": "function",
            "source": source,
            "entrypoint": candidate.artifact.entrypoint,
            "module_name": target.source.module_name,
            "qualified_name": target.source.qualified_name,
            "signature_text": target.contract.signature_text,
            "callable_kind": target.contract.kind.name,
            "allow_imports": target.policy.validation.allow_imports,
            "registered_cases": registered_cases,
            "generated_tests": generated_tests,
            "run_registered_tests": target.policy.validation.run_registered_tests,
            "run_generated_tests": target.policy.validation.run_generated_tests,
        }
        result = self._run_worker(payload, timeout_seconds=timeout_seconds)
        checks = tuple(_check_from_dict(item) for item in result.get("checks", []))
        mandatory_failures = [
            check
            for check in checks
            if check.outcome in {CheckOutcome.FAILED, CheckOutcome.ERROR}
            and check.kind not in {
                ValidationCheckKind.PERFORMANCE,
                ValidationCheckKind.GENERATED_TESTS,
            }
        ]
        hard = tuple(
            dict.fromkeys(
                assessment.hard_disqualifications
                + tuple(result.get("hard_disqualifications", ()))
            )
        )
        review = tuple(
            dict.fromkeys(
                assessment.review_required_findings
                + tuple(result.get("review_required_findings", ()))
            )
        )
        eligible = bool(result.get("eligible", False)) and not mandatory_failures and not hard and not review
        return ValidationReport(
            candidate_id=candidate.candidate_id,
            eligible=eligible,
            checks=checks,
            measurements={
                str(key): float(value)
                for key, value in result.get("measurements", {}).items()
            },
            risk_findings=tuple(
                dict.fromkeys(
                    assessment.risk_findings
                    + tuple(result.get("risk_findings", ()))
                )
            ),
            hard_disqualifications=hard,
            review_required_findings=review,
            worker_stdout=result.get("worker_stdout", ""),
            worker_stderr=result.get("worker_stderr", ""),
        )

    def validate_auxiliary(
        self,
        *,
        source: str,
        entrypoint: str,
        valid_examples: tuple[Any, ...],
        invalid_examples: tuple[Any, ...],
        timeout_seconds: float,
        maximum_runtime_seconds: float,
    ) -> dict[str, Any]:
        payload = {
            "mode": "auxiliary_validator",
            "source": source,
            "entrypoint": entrypoint,
            "valid_examples": valid_examples,
            "invalid_examples": invalid_examples,
            "maximum_runtime_seconds": maximum_runtime_seconds,
        }
        return self._run_worker(payload, timeout_seconds=timeout_seconds)

    def _run_worker(self, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="caretaker-validation-") as temporary:
            temp = Path(temporary)
            input_path = temp / "request.pickle"
            output_path = temp / "result.json"
            with input_path.open("wb") as handle:
                pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)

            environment = {
                "PYTHONPATH": os.pathsep.join(
                    (os.getcwd() if item == "" else item)
                    for item in sys.path
                    if isinstance(item, str)
                ),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONIOENCODING": "utf-8",
            }
            command = [
                self.python_executable,
                "-m",
                "caretaker.validation_worker",
                str(input_path),
                str(output_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    cwd=temporary,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                now = utcnow()
                timeout_check = ValidationCheckResult(
                    kind=ValidationCheckKind.PERFORMANCE,
                    outcome=CheckOutcome.FAILED,
                    started_at=now - timedelta(seconds=timeout_seconds),
                    finished_at=now,
                    summary=f"Validation worker exceeded {timeout_seconds:g}s timeout.",
                    error_type="TimeoutExpired",
                    error_message=str(exc),
                )
                return {
                    "eligible": False,
                    "checks": [_check_to_dict(timeout_check)],
                    "measurements": {},
                    "risk_findings": ["validation worker timed out"],
                    "hard_disqualifications": [],
                    "review_required_findings": [],
                    "worker_stdout": exc.stdout or "",
                    "worker_stderr": exc.stderr or "",
                }
            if not output_path.exists():
                now = utcnow()
                return {
                    "eligible": False,
                    "checks": [
                        _check_to_dict(
                            ValidationCheckResult(
                                kind=ValidationCheckKind.COMPILE,
                                outcome=CheckOutcome.ERROR,
                                started_at=now,
                                finished_at=now,
                                summary="Validation worker did not produce a result.",
                                details={"returncode": completed.returncode},
                                error_type="WorkerProtocolError",
                                error_message=completed.stderr[-2000:],
                            )
                        )
                    ],
                    "measurements": {},
                    "risk_findings": ["validation worker crashed or corrupted its protocol"],
                    "hard_disqualifications": [],
                    "review_required_findings": [],
                    "worker_stdout": completed.stdout[-20_000:],
                    "worker_stderr": completed.stderr[-20_000:],
                }
            result = json.loads(output_path.read_text(encoding="utf-8"))
            result["worker_stdout"] = completed.stdout[-20_000:]
            result["worker_stderr"] = completed.stderr[-20_000:]
            if completed.returncode != 0:
                result["eligible"] = False
                result.setdefault("risk_findings", []).append(
                    f"validation worker exited with status {completed.returncode}"
                )
            return result


_DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "system",
    "popen",
    "fork",
    "spawn",
    "Popen",
    "run",
    "call",
    "check_call",
    "check_output",
}
_CONCURRENCY_PARTS = {"threading", "multiprocessing", "concurrent", "asyncio", "Thread", "Process"}


def assess_candidate_source(source: str) -> StaticAssessment:
    hard: list[str] = []
    review: list[str] = []
    risks: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return StaticAssessment((), (), ())
    definitions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            review.append("candidate introduces imports; manual approval is required")
            risks.append("candidate introduces imports")
        elif isinstance(node, ast.Call):
            name = _call_name(node.func)
            leaf = name.split(".")[-1]
            if leaf in _DANGEROUS_CALLS:
                hard.append(f"candidate calls prohibited operation {name}")
            if any(part in _CONCURRENCY_PARTS for part in name.split(".")):
                review.append(f"candidate introduces concurrency through {name}")
                risks.append(f"candidate introduces concurrency through {name}")
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            hard.append("candidate declares global or nonlocal state")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            hard.append(f"candidate accesses prohibited dunder attribute {node.attr}")
    for definition in definitions:
        defaults = tuple(definition.args.defaults) + tuple(
            item for item in definition.args.kw_defaults if item is not None
        )
        for default in defaults:
            if not _is_safe_literal(default):
                hard.append("candidate contains executable or non-literal default arguments")
        annotations: list[ast.expr] = []
        annotations.extend(
            arg.annotation
            for arg in (
                list(definition.args.posonlyargs)
                + list(definition.args.args)
                + list(definition.args.kwonlyargs)
            )
            if arg.annotation is not None
        )
        if definition.args.vararg and definition.args.vararg.annotation:
            annotations.append(definition.args.vararg.annotation)
        if definition.args.kwarg and definition.args.kwarg.annotation:
            annotations.append(definition.args.kwarg.annotation)
        if definition.returns is not None:
            annotations.append(definition.returns)
        for annotation in annotations:
            if not _is_safe_annotation(annotation):
                hard.append("candidate contains executable or unsupported annotation expressions")
    return StaticAssessment(
        hard_disqualifications=tuple(dict.fromkeys(hard)),
        review_required_findings=tuple(dict.fromkeys(review)),
        risk_findings=tuple(dict.fromkeys(risks)),
    )


def sanitized_function_tree(source: str) -> ast.Module:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node.returns = None
            for arg in (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            ):
                arg.annotation = None
            if node.args.vararg:
                node.args.vararg.annotation = None
            if node.args.kwarg:
                node.args.kwarg.annotation = None
    return ast.fix_missing_locations(tree)


def _is_safe_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_safe_literal(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_safe_literal(key) and _is_safe_literal(value)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_safe_literal(node.operand)
    return False


def _is_safe_annotation(node: ast.AST) -> bool:
    if isinstance(node, (ast.Name, ast.Constant)):
        return True
    if isinstance(node, ast.Attribute):
        return not node.attr.startswith("__") and _is_safe_annotation(node.value)
    if isinstance(node, ast.Subscript):
        return _is_safe_annotation(node.value) and _is_safe_annotation(node.slice)
    if isinstance(node, ast.Tuple):
        return all(_is_safe_annotation(item) for item in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_safe_annotation(node.left) and _is_safe_annotation(node.right)
    return False


def _call_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return "<dynamic>"


def _check_from_dict(payload: dict[str, Any]) -> ValidationCheckResult:
    return ValidationCheckResult(
        kind=ValidationCheckKind[payload["kind"]],
        outcome=CheckOutcome[payload["outcome"]],
        started_at=utcnow(),
        finished_at=utcnow(),
        summary=payload.get("summary", ""),
        details=payload.get("details", {}),
        error_type=payload.get("error_type"),
        error_message=payload.get("error_message"),
    )


def _check_to_dict(check: ValidationCheckResult) -> dict[str, Any]:
    return {
        "kind": check.kind.name,
        "outcome": check.outcome.name,
        "summary": check.summary,
        "details": dict(check.details),
        "error_type": check.error_type,
        "error_message": check.error_message,
    }
