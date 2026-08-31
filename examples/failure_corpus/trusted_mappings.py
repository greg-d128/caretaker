"""Explicit repository-owned oracle mappings for the reviewed corpus.

These mappings model expected Caretaker observations for harness contract
tests. They do not execute the manifest stimulus and are not evidence that the
underlying application behavior has been exercised.
"""

from __future__ import annotations

from typing import Any

from caretaker.failure_corpus import (
    FailureCorpus,
    FailureCorpusError,
    FailureCorpusExecutionPolicy,
    FailureCorpusHarness,
)


REVIEWED_CORPUS_ID = "caretaker-default-failure-corpus-v1"
REVIEWED_RESULTS: dict[str, dict[str, str]] = {
    "exception.unhandled": {
        "signal": "EXCEPTION",
        "caretaker_action": "CAPTURE_INCIDENT",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "timeout.soft": {
        "signal": "TIMEOUT",
        "caretaker_action": "RECORD_EVIDENCE",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "output.invalid": {
        "signal": "INVALID_OUTPUT",
        "caretaker_action": "ROLLBACK_REPAIR",
        "authority_effect": "ROLLBACK",
    },
    "dependency.changed": {
        "signal": "DEPENDENCY_FAILURE",
        "caretaker_action": "CAPTURE_INCIDENT",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "configuration.changed": {
        "signal": "CONFIGURATION_FAILURE",
        "caretaker_action": "CAPTURE_INCIDENT",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "corruption.capsule": {
        "signal": "CORRUPT_CAPSULE",
        "caretaker_action": "REQUIRE_OPERATOR_REVIEW",
        "authority_effect": "OPERATOR_REVIEW",
    },
    "concurrency.conflict": {
        "signal": "CONCURRENCY_CONFLICT",
        "caretaker_action": "REQUIRE_OPERATOR_REVIEW",
        "authority_effect": "OPERATOR_REVIEW",
    },
    "deployment.bad": {
        "signal": "DEPLOYMENT_FAILURE",
        "caretaker_action": "ROLLBACK_REPAIR",
        "authority_effect": "ROLLBACK",
    },
    "behavior.intermittent": {
        "signal": "BEHAVIOR_DEVIATION",
        "caretaker_action": "RECORD_EVIDENCE",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "resource.pressure": {
        "signal": "RESOURCE_PRESSURE",
        "caretaker_action": "CONTINUE_DEGRADED",
        "authority_effect": "DEGRADED",
    },
    "resource.storage-full": {
        "signal": "RESOURCE_PRESSURE",
        "caretaker_action": "STOP_APPLICATION",
        "authority_effect": "APPLICATION_STOP",
    },
    "worker.failed": {
        "signal": "WORKER_FAILURE",
        "caretaker_action": "REPLACE_WORKER",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "repair.validation-fails": {
        "signal": "REPAIR_FAILURE",
        "caretaker_action": "ROLLBACK_REPAIR",
        "authority_effect": "ROLLBACK",
    },
    "repair.secondary-failure": {
        "signal": "REPAIR_FAILURE",
        "caretaker_action": "ROLLBACK_REPAIR",
        "authority_effect": "ROLLBACK",
    },
    "dependency.version-drift": {
        "signal": "DEPENDENCY_FAILURE",
        "caretaker_action": "CAPTURE_INCIDENT",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
    "evidence.malicious": {
        "signal": "MALICIOUS_EVIDENCE",
        "caretaker_action": "REQUIRE_OPERATOR_REVIEW",
        "authority_effect": "OPERATOR_REVIEW",
    },
    "llm.unavailable": {
        "signal": "LLM_UNAVAILABLE",
        "caretaker_action": "RECORD_EVIDENCE",
        "authority_effect": "NO_AUTHORITY_CHANGE",
    },
}


def build_reviewed_harness(
    corpus: FailureCorpus,
    *,
    isolation: str = "PROCESS",
    policy: FailureCorpusExecutionPolicy | None = None,
) -> FailureCorpusHarness:
    """Build the explicit oracle harness for the repository's default corpus."""
    if corpus.corpus_id != REVIEWED_CORPUS_ID:
        raise FailureCorpusError(
            f"reviewed mappings only support {REVIEWED_CORPUS_ID!r}"
        )
    scenario_ids = {scenario.scenario_id for scenario in corpus.scenarios}
    if scenario_ids != set(REVIEWED_RESULTS):
        raise FailureCorpusError("reviewed mappings do not cover the loaded corpus exactly")
    return FailureCorpusHarness(
        corpus,
        runners={
            scenario_id: (lambda _scenario, result=result: dict(result))
            for scenario_id, result in REVIEWED_RESULTS.items()
        },
        isolation=isolation,
        policy=policy,
    )
