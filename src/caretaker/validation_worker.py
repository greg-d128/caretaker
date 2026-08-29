from __future__ import annotations

import ast
import builtins
import importlib
import inspect
import io
import json
import os
import statistics
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

from .validation import (
    VALIDATION_PROTOCOL_VERSION,
    _VALIDATION_BINDING_FIELDS,
    _decode_validation_data,
    _encode_validation_data,
    assess_candidate_source,
    sanitized_function_tree,
)


def _install_validation_audit_hook(payload: dict[str, Any], output_path: Path) -> None:
    """Deny common external side effects during candidate execution.

    This is defense in depth inside the same-UID validation process, not an OS
    security sandbox. Strong isolation still requires a container/VM boundary.
    """
    allow_network = bool(payload.get("allow_network", False))
    allow_subprocesses = bool(payload.get("allow_subprocesses", False))
    allow_filesystem_writes = bool(payload.get("allow_filesystem_writes", False))
    allowed_output = str(output_path.resolve())
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def audit(event: str, args: tuple[Any, ...]) -> None:
        if not allow_network and event.startswith("socket."):
            raise PermissionError(f"validation policy blocks network operation: {event}")
        if not allow_subprocesses and (event.startswith("subprocess.") or event in {"os.system", "os.posix_spawn", "os.posix_spawnp"}):
            raise PermissionError(f"validation policy blocks subprocess operation: {event}")
        if not allow_filesystem_writes:
            if event == "open" and len(args) >= 3:
                path, _mode, flags = args[:3]
                if isinstance(flags, int) and flags & write_flags and str(Path(path).resolve()) != allowed_output:
                    raise PermissionError(f"validation policy blocks filesystem write: {path}")
            if event in {"os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.link", "os.symlink"}:
                raise PermissionError(f"validation policy blocks filesystem mutation: {event}")

    sys.addaudithook(audit)


def check(kind: str, outcome: str, summary: str, **details: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "outcome": outcome,
        "summary": summary,
        "details": details,
    }


def resolve_qualname(root: object, qualname: str) -> object:
    current = root
    for component in qualname.split("."):
        if component == "<locals>":
            raise AttributeError("Nested local targets are unsupported")
        current = getattr(current, component)
    return current


def validate_structure(
    source: str,
    entrypoint: str,
    allow_imports: bool,
) -> tuple[ast.Module, list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source)
        checks.append(check("AST_PARSE", "PASSED", "Candidate parses as Python."))
    except SyntaxError as exc:
        checks.append(
            check(
                "AST_PARSE",
                "FAILED",
                "Candidate contains invalid Python syntax.",
                error=str(exc),
            )
        )
        raise

    definitions = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    forbidden = [
        node for node in tree.body
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not (allow_imports and isinstance(node, (ast.Import, ast.ImportFrom)))
    ]
    if len(definitions) != 1 or forbidden:
        checks.append(
            check(
                "RESPONSE_STRUCTURE",
                "FAILED",
                "V1 requires exactly one function definition and no other top-level statements.",
                function_count=len(definitions),
                forbidden_nodes=[type(node).__name__ for node in forbidden],
            )
        )
        raise ValueError("invalid candidate structure")
    definition = definitions[0]
    if definition.name != entrypoint:
        checks.append(
            check(
                "FUNCTION_NAME",
                "FAILED",
                f"Expected function {entrypoint!r}, received {definition.name!r}.",
            )
        )
        raise ValueError("function name mismatch")
    if definition.decorator_list:
        checks.append(
            check(
                "STATIC_POLICY",
                "FAILED",
                "Generated function decorators are not permitted in V1.",
            )
        )
        raise ValueError("decorators not permitted")
    checks.append(
        check("RESPONSE_STRUCTURE", "PASSED", "Candidate has the required V1 structure.")
    )
    checks.append(check("FUNCTION_NAME", "PASSED", "Function name is preserved."))
    return tree, checks


def signature_shape(function: object) -> inspect.Signature:
    signature = inspect.signature(function)
    parameters = [
        parameter.replace(annotation=inspect.Signature.empty)
        for parameter in signature.parameters.values()
    ]
    return signature.replace(
        parameters=parameters,
        return_annotation=inspect.Signature.empty,
    )


def run_function(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload["source"]
    entrypoint = payload["entrypoint"]
    checks: list[dict[str, Any]] = []
    assessment = assess_candidate_source(source)
    if assessment.hard_disqualifications:
        checks.append(
            check(
                "STATIC_POLICY",
                "FAILED",
                "Candidate violates mandatory static security policy.",
                findings=list(assessment.hard_disqualifications),
            )
        )
        return _result(
            eligible=False,
            checks=checks,
            hard=assessment.hard_disqualifications,
            review=assessment.review_required_findings,
            risks=assessment.risk_findings,
        )
    if assessment.review_required_findings:
        checks.append(
            check(
                "STATIC_POLICY",
                "FAILED",
                "Candidate requires manual review and cannot be auto-activated.",
                findings=list(assessment.review_required_findings),
            )
        )
        return _result(
            eligible=False,
            checks=checks,
            hard=assessment.hard_disqualifications,
            review=assessment.review_required_findings,
            risks=assessment.risk_findings,
        )

    try:
        tree, structure_checks = validate_structure(
            source, entrypoint, payload["allow_imports"]
        )
        checks.extend(structure_checks)
        definition = next(
            node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        expected_async = payload.get("callable_kind") == "COROUTINE"
        if isinstance(definition, ast.AsyncFunctionDef) != expected_async:
            checks.append(
                check(
                    "CALLABLE_KIND",
                    "FAILED",
                    "Candidate callable kind differs from the original.",
                )
            )
            return _result(False, checks, assessment)
        checks.append(
            check("CALLABLE_KIND", "PASSED", "Candidate callable kind is preserved.")
        )
        safe_tree = sanitized_function_tree(source)
        compiled = compile(
            safe_tree, "<caretaker-candidate>", "exec", dont_inherit=True
        )
        checks.append(check("COMPILE", "PASSED", "Candidate compiles."))
    except Exception as exc:
        if not any(item["kind"] == "COMPILE" for item in checks):
            checks.append(
                check(
                    "COMPILE",
                    "FAILED",
                    "Candidate could not be compiled.",
                    error=str(exc),
                )
            )
        return _result(False, checks, assessment)

    try:
        module = importlib.import_module(payload["module_name"])
        target_object = resolve_qualname(module, payload["qualified_name"])
        original = getattr(
            getattr(target_object, "__caretaker_target__", None), "slot", None
        )
        original_function = (
            original.load().implementation if original is not None else target_object
        )
        namespace = dict(original_function.__globals__)
        exec(compiled, namespace, namespace)
        candidate = namespace[entrypoint]
        candidate.__annotations__ = dict(getattr(original_function, "__annotations__", {}))
    except Exception as exc:
        checks.append(
            check(
                "COMPILE",
                "ERROR",
                "Candidate could not be loaded in the target module context.",
                error=str(exc),
            )
        )
        return _result(False, checks, assessment)

    candidate_signature = signature_shape(candidate)
    original_signature = signature_shape(original_function)
    if candidate_signature != original_signature:
        checks.append(
            check(
                "SIGNATURE",
                "FAILED",
                "Candidate signature differs from the original.",
                expected=str(original_signature),
                actual=str(candidate_signature),
            )
        )
        return _result(False, checks, assessment)
    checks.append(check("SIGNATURE", "PASSED", "Candidate signature is compatible."))

    candidate_times: list[float] = []
    original_times: list[float] = []
    cases = payload.get("registered_cases", ()) if payload.get("run_registered_tests") else ()
    case_failures: list[dict[str, Any]] = []
    for case in cases:
        case_name = case.name
        for _ in range(max(1, case.repeat)):
            started = time.perf_counter()
            candidate_exception: BaseException | None = None
            try:
                candidate_result = candidate(*case.args, **dict(case.kwargs))
            except BaseException as exc:
                candidate_exception = exc
                candidate_result = None
            candidate_times.append(time.perf_counter() - started)

            if case.expected_exception:
                if (
                    candidate_exception is None
                    or type(candidate_exception).__name__ != case.expected_exception
                ):
                    case_failures.append(
                        {
                            "case": case_name,
                            "reason": (
                                f"expected exception {case.expected_exception}, received "
                                f"{type(candidate_exception).__name__ if candidate_exception else 'no exception'}"
                            ),
                        }
                    )
            elif candidate_exception is not None:
                case_failures.append(
                    {
                        "case": case_name,
                        "reason": (
                            f"raised {type(candidate_exception).__name__}: "
                            f"{candidate_exception}"
                        ),
                    }
                )
            elif candidate_result != case.expected:
                case_failures.append(
                    {
                        "case": case_name,
                        "reason": "unexpected result",
                        "expected": repr(case.expected),
                        "actual": repr(candidate_result),
                    }
                )

            started = time.perf_counter()
            try:
                original_function(*case.args, **dict(case.kwargs))
            except BaseException:
                pass
            original_times.append(time.perf_counter() - started)

    if case_failures:
        checks.append(
            check(
                "REGISTERED_TESTS",
                "FAILED",
                f"{len(case_failures)} registered or regression validation case(s) failed.",
                failures=case_failures[:20],
            )
        )
    else:
        checks.append(
            check(
                "REGISTERED_TESTS",
                "PASSED" if cases else "SKIPPED",
                (
                    "All registered and regression validation cases passed."
                    if cases
                    else "No registered or regression validation cases were supplied."
                ),
                case_count=len(cases),
            )
        )

    generated_failures: list[dict[str, Any]] = []
    generated_tests = payload.get("generated_tests", ()) if payload.get("run_generated_tests") else ()
    for index, source_text in enumerate(generated_tests, start=1):
        try:
            _run_generated_test(source_text, candidate)
        except BaseException as exc:
            generated_failures.append(
                {
                    "test": index,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
    if generated_tests:
        checks.append(
            check(
                "GENERATED_TESTS",
                "FAILED" if generated_failures else "PASSED",
                (
                    f"{len(generated_failures)} generated test(s) failed."
                    if generated_failures
                    else "All generated tests passed."
                ),
                failures=generated_failures[:20],
                test_count=len(generated_tests),
                advisory=True,
            )
        )
    else:
        checks.append(
            check(
                "GENERATED_TESTS",
                "SKIPPED",
                "No generated tests were requested or supplied.",
            )
        )

    measurements = {
        "candidate_median_seconds": statistics.median(candidate_times)
        if candidate_times
        else 0.0,
        "original_median_seconds": statistics.median(original_times)
        if original_times
        else 0.0,
        "candidate_max_seconds": max(candidate_times) if candidate_times else 0.0,
        "source_lines": float(len(source.splitlines())),
        "generated_tests_passed": float(
            max(0, len(generated_tests) - len(generated_failures))
        ),
        "generated_tests_total": float(len(generated_tests)),
    }
    checks.append(
        check(
            "PERFORMANCE",
            "PASSED",
            "Candidate timing measurements were collected.",
            **measurements,
        )
    )
    eligible = not case_failures
    return _result(
        eligible,
        checks,
        assessment,
        measurements=measurements,
    )


def _run_generated_test(source: str, candidate: Any) -> None:
    tree = ast.parse(source)
    assessment = assess_candidate_source(source)
    if assessment.hard_disqualifications or assessment.review_required_findings:
        raise ValueError(
            "generated test violates static policy: "
            + "; ".join(
                assessment.hard_disqualifications
                + assessment.review_required_findings
            )
        )
    if any(isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)) for node in ast.walk(tree)):
        raise ValueError("generated tests may not import modules or mutate global state")
    safe_builtins = {
        name: getattr(builtins, name)
        for name in (
            "abs",
            "all",
            "any",
            "bool",
            "dict",
            "enumerate",
            "float",
            "int",
            "isinstance",
            "len",
            "list",
            "max",
            "min",
            "range",
            "round",
            "set",
            "str",
            "sum",
            "tuple",
            "zip",
        )
    }
    namespace: dict[str, Any] = {
        "candidate": candidate,
        "__builtins__": safe_builtins,
    }
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if len(definitions) == 1 and len(tree.body) == 1:
        exec(compile(tree, "<caretaker-generated-test>", "exec"), namespace, namespace)
        test_function = namespace[definitions[0].name]
        signature = inspect.signature(test_function)
        if len(signature.parameters) == 0:
            test_function()
        elif len(signature.parameters) == 1:
            test_function(candidate)
        else:
            raise ValueError("generated test functions must accept zero or one argument")
    else:
        exec(compile(tree, "<caretaker-generated-test>", "exec"), namespace, namespace)


def run_auxiliary(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload["source"]
    entrypoint = payload["entrypoint"]
    checks: list[dict[str, Any]] = []
    assessment = assess_candidate_source(source)
    if assessment.hard_disqualifications or assessment.review_required_findings:
        checks.append(
            check(
                "STATIC_POLICY",
                "FAILED",
                "Auxiliary function violates static policy.",
                findings=list(
                    assessment.hard_disqualifications
                    + assessment.review_required_findings
                ),
            )
        )
        return _result(False, checks, assessment)
    try:
        tree, structure_checks = validate_structure(source, entrypoint, False)
        checks.extend(structure_checks)
        namespace: dict[str, Any] = {}
        exec(
            compile(
                sanitized_function_tree(source),
                "<caretaker-auxiliary>",
                "exec",
                dont_inherit=True,
            ),
            namespace,
            namespace,
        )
        validator = namespace[entrypoint]
        checks.append(check("COMPILE", "PASSED", "Auxiliary function compiles."))
    except Exception as exc:
        checks.append(
            check(
                "COMPILE",
                "FAILED",
                "Auxiliary function could not be loaded.",
                error=str(exc),
            )
        )
        return _result(False, checks, assessment)

    valid_failures = []
    for value in payload["valid_examples"]:
        try:
            if validator(value) is not True:
                valid_failures.append(repr(value))
        except Exception as exc:
            valid_failures.append(
                f"{repr(value)} raised {type(exc).__name__}: {exc}"
            )
    checks.append(
        check(
            "AUXILIARY_VALID_EXAMPLES",
            "FAILED" if valid_failures else "PASSED",
            "Validator was checked against known-valid examples.",
            failures=valid_failures[:20],
        )
    )

    invalid_failures = []
    for value in payload["invalid_examples"]:
        try:
            if validator(value) is not False:
                invalid_failures.append(repr(value))
        except Exception as exc:
            invalid_failures.append(
                f"{repr(value)} raised {type(exc).__name__}: {exc}"
            )
    checks.append(
        check(
            "AUXILIARY_INVALID_EXAMPLES",
            "FAILED" if invalid_failures else "PASSED",
            "Validator was checked against known-invalid examples.",
            failures=invalid_failures[:20],
        )
    )

    samples = tuple(payload["valid_examples"]) + tuple(payload["invalid_examples"])
    started = time.perf_counter()
    iterations = max(1, 1000 // max(1, len(samples)))
    for _ in range(iterations):
        for value in samples:
            validator(value)
    elapsed = time.perf_counter() - started
    per_call = elapsed / max(1, iterations * len(samples))
    performance_passed = per_call <= payload["maximum_runtime_seconds"]
    checks.append(
        check(
            "PERFORMANCE",
            "PASSED" if performance_passed else "FAILED",
            "Auxiliary function runtime was benchmarked.",
            seconds_per_call=per_call,
            maximum_runtime_seconds=payload["maximum_runtime_seconds"],
        )
    )
    return _result(
        not valid_failures and not invalid_failures and performance_passed,
        checks,
        assessment,
        measurements={"seconds_per_call": per_call},
    )


def _result(
    eligible: bool,
    checks: list[dict[str, Any]],
    assessment: Any | None = None,
    *,
    hard: tuple[str, ...] = (),
    review: tuple[str, ...] = (),
    risks: tuple[str, ...] = (),
    measurements: dict[str, float] | None = None,
) -> dict[str, Any]:
    if assessment is not None:
        hard = assessment.hard_disqualifications
        review = assessment.review_required_findings
        risks = assessment.risk_findings
    return {
        "eligible": eligible,
        "checks": checks,
        "measurements": measurements or {},
        "risk_findings": list(risks),
        "hard_disqualifications": list(hard),
        "review_required_findings": list(review),
    }


def main() -> int:
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    envelope = json.loads(input_path.read_text(encoding="utf-8"))
    if (
        not isinstance(envelope, dict)
        or envelope.get("protocol_version") != VALIDATION_PROTOCOL_VERSION
    ):
        raise ValueError("unsupported validation request protocol version")
    payload = _decode_validation_data(envelope["payload"])
    if not isinstance(payload, dict):
        raise ValueError("validation request payload must be an object")
    _install_validation_audit_hook(payload, output_path)
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if payload["mode"] == "function":
                result = run_function(payload)
            elif payload["mode"] == "auxiliary_validator":
                result = run_auxiliary(payload)
            else:
                raise ValueError(f"Unknown validation mode: {payload['mode']}")
    except BaseException as exc:
        result = {
            "eligible": False,
            "checks": [
                check(
                    "COMPILE",
                    "ERROR",
                    "Validation worker raised an internal exception.",
                    error=f"{type(exc).__name__}: {exc}",
                )
            ],
            "measurements": {},
            "risk_findings": ["validation worker internal failure"],
            "hard_disqualifications": [],
            "review_required_findings": [],
        }
    # Binding values are supervisor-owned.  Echoing the request envelope lets
    # the parent verify that this result belongs to the transaction it sent;
    # the worker never gets authority to invent those values.
    if payload.get("protocol_version") == VALIDATION_PROTOCOL_VERSION:
        for field in _VALIDATION_BINDING_FIELDS:
            if field in payload:
                result[field] = payload[field]
    result["captured_stdout"] = stdout.getvalue()[-20_000:]
    result["captured_stderr"] = stderr.getvalue()[-20_000:]
    output_path.write_text(
        json.dumps(
            {
                "protocol_version": VALIDATION_PROTOCOL_VERSION,
                "result": _encode_validation_data(result),
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
