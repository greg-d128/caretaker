"""Deterministic application-level failure stimuli for the corpus.

This module is a small, side-effect-bounded laboratory. It does not load
production code, contact external services, or infer commands from the corpus
manifest. The process runner supplies a scenario summary and this explicit
mapping executes the corresponding local stimulus.
"""

from __future__ import annotations

import json
import sys
import time


def _exception() -> dict[str, object]:
    try:
        return {"value": 1 / 0}
    except ZeroDivisionError:
        return {
            "signal": "EXCEPTION",
            "caretaker_action": "CAPTURE_INCIDENT",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {"stimulus": "division by zero", "exception": "ZeroDivisionError"},
        }


def _timeout() -> dict[str, object]:
    started = time.monotonic()
    time.sleep(0.01)
    if time.monotonic() - started >= 0.005:
        return {
            "signal": "TIMEOUT",
            "caretaker_action": "RECORD_EVIDENCE",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {"stimulus": "bounded slow operation", "timeout_mode": "soft"},
        }
    raise RuntimeError("laboratory timeout stimulus did not cross its soft budget")


def _invalid_output() -> dict[str, object]:
    result = ["not", "a", "record"]
    if not isinstance(result, dict):
        return {
            "signal": "INVALID_OUTPUT",
            "caretaker_action": "ROLLBACK_REPAIR",
            "authority_effect": "ROLLBACK",
            "details": {"stimulus": "returned list instead of object"},
        }
    raise RuntimeError("laboratory invalid-output stimulus was accepted")


def _configuration_changed() -> dict[str, object]:
    baseline = {"mode": "safe"}
    current = dict(baseline)
    current["mode"] = "unsafe"
    if current != baseline:
        return {
            "signal": "CONFIGURATION_FAILURE",
            "caretaker_action": "CAPTURE_INCIDENT",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {"changed_field": "mode"},
        }
    raise RuntimeError("laboratory configuration stimulus did not change state")


def _dependency_changed() -> dict[str, object]:
    configured_response = "baseline-response"
    dependency_response = "changed-response"
    if dependency_response != configured_response:
        return {
            "signal": "DEPENDENCY_FAILURE",
            "caretaker_action": "CAPTURE_INCIDENT",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {
                "dependency": "laboratory-provider",
                "baseline_response": configured_response,
                "observed_response": dependency_response,
            },
        }
    raise RuntimeError("laboratory dependency-change stimulus did not diverge")


def _dependency_version_drift() -> dict[str, object]:
    accepted_version = "1.0"
    observed_version = "2.0"
    if observed_version != accepted_version:
        return {
            "signal": "DEPENDENCY_FAILURE",
            "caretaker_action": "CAPTURE_INCIDENT",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {
                "dependency": "laboratory-provider",
                "accepted_version": accepted_version,
                "observed_version": observed_version,
            },
        }
    raise RuntimeError("laboratory dependency-version stimulus did not drift")


def _concurrency_conflict() -> dict[str, object]:
    first = {"transaction_id": "transaction-1", "policy_fingerprint": "policy-a"}
    second = {"transaction_id": "transaction-1", "policy_fingerprint": "policy-b"}
    if first != second:
        return {
            "signal": "CONCURRENCY_CONFLICT",
            "caretaker_action": "REQUIRE_OPERATOR_REVIEW",
            "authority_effect": "OPERATOR_REVIEW",
            "details": {"conflict": "same transaction has incompatible policy lineage"},
        }
    raise RuntimeError("laboratory concurrency stimulus did not conflict")


def _deployment_bad() -> dict[str, object]:
    accepted_behavior = {"result": "stable"}
    deployed_behavior = {"result": "regressed"}
    if deployed_behavior != accepted_behavior:
        return {
            "signal": "DEPLOYMENT_FAILURE",
            "caretaker_action": "ROLLBACK_REPAIR",
            "authority_effect": "ROLLBACK",
            "details": {"comparison": "deployment differs from accepted baseline"},
        }
    raise RuntimeError("laboratory deployment stimulus matched the baseline")


def _resource_pressure() -> dict[str, object]:
    soft_budget = 1024
    observed = 2048
    if observed > soft_budget:
        return {
            "signal": "RESOURCE_PRESSURE",
            "caretaker_action": "CONTINUE_DEGRADED",
            "authority_effect": "DEGRADED",
            "details": {
                "resource": "bounded-work-budget",
                "soft_budget": soft_budget,
                "observed": observed,
            },
        }
    raise RuntimeError("laboratory resource-pressure stimulus stayed within budget")


def _intermittent() -> dict[str, object]:
    results = ["baseline", "baseline", "deviation"]
    if len(set(results)) > 1:
        return {
            "signal": "BEHAVIOR_DEVIATION",
            "caretaker_action": "RECORD_EVIDENCE",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {"samples": len(results), "distinct_results": len(set(results))},
        }
    raise RuntimeError("laboratory intermittent stimulus did not deviate")


def _storage_full() -> dict[str, object]:
    capacity = 0
    try:
        if capacity <= 0:
            raise OSError("evidence store capacity exhausted")
    except OSError:
        return {
            "signal": "RESOURCE_PRESSURE",
            "caretaker_action": "STOP_APPLICATION",
            "authority_effect": "APPLICATION_STOP",
            "details": {"resource": "evidence-storage", "policy_response": "stop"},
        }
    raise RuntimeError("laboratory storage-full stimulus was accepted")


def _worker_failed() -> dict[str, object]:
    try:
        raise RuntimeError("controlled worker failed at transaction milestone")
    except RuntimeError:
        return {
            "signal": "WORKER_FAILURE",
            "caretaker_action": "REPLACE_WORKER",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {"milestone": "in-flight-transaction"},
        }


def _validation_failed() -> dict[str, object]:
    try:
        compile("def broken(:\n    pass", "<laboratory-candidate>", "exec")
    except SyntaxError:
        return {
            "signal": "REPAIR_FAILURE",
            "caretaker_action": "ROLLBACK_REPAIR",
            "authority_effect": "ROLLBACK",
            "details": {"failed_gate": "AST_PARSE"},
        }
    raise RuntimeError("laboratory validation-failure stimulus was accepted")


def _secondary_failure() -> dict[str, object]:
    initially_validated = True
    post_repair_failure = True
    if initially_validated and post_repair_failure:
        return {
            "signal": "REPAIR_FAILURE",
            "caretaker_action": "ROLLBACK_REPAIR",
            "authority_effect": "ROLLBACK",
            "details": {"phase": "post-repair-observation"},
        }
    raise RuntimeError("laboratory secondary-failure stimulus did not fail")


def _llm_unavailable() -> dict[str, object]:
    try:
        raise ConnectionError("advisory model endpoint unavailable")
    except ConnectionError:
        return {
            "signal": "LLM_UNAVAILABLE",
            "caretaker_action": "RECORD_EVIDENCE",
            "authority_effect": "NO_AUTHORITY_CHANGE",
            "details": {"mode": "advisory-only", "network_contacted": False},
        }


_STIMULI = {
    "exception.unhandled": _exception,
    "timeout.soft": _timeout,
    "output.invalid": _invalid_output,
    "configuration.changed": _configuration_changed,
    "dependency.changed": _dependency_changed,
    "dependency.version-drift": _dependency_version_drift,
    "concurrency.conflict": _concurrency_conflict,
    "deployment.bad": _deployment_bad,
    "resource.pressure": _resource_pressure,
    "behavior.intermittent": _intermittent,
    "resource.storage-full": _storage_full,
    "worker.failed": _worker_failed,
    "repair.validation-fails": _validation_failed,
    "repair.secondary-failure": _secondary_failure,
    "llm.unavailable": _llm_unavailable,
}


def main() -> int:
    request = json.load(sys.stdin)
    scenario = request.get("scenario") if isinstance(request, dict) else None
    scenario_id = scenario.get("scenario_id") if isinstance(scenario, dict) else None
    if not isinstance(scenario_id, str) or scenario_id not in _STIMULI:
        raise SystemExit("application laboratory received an unsupported scenario")
    print(json.dumps(_STIMULI[scenario_id](), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
