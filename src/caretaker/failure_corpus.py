"""Bounded, reviewable metadata for the Caretaker failure corpus.

Corpus manifests describe test stimuli and expected Caretaker boundaries.  They
are deliberately not runners: a manifest cannot name a Python callable, shell
command, URL, or executable entrypoint.  A separate, explicitly authorized
test harness may map a scenario ID to code in its own trusted test suite.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


FAILURE_CORPUS_SCHEMA_VERSION = 1
MAX_CORPUS_BYTES = 1_048_576
MAX_SCENARIOS = 500
MAX_TEXT_CHARS = 2_048
MAX_TAGS = 32
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")

FAILURE_CATEGORIES = frozenset({
    "exception",
    "timeout",
    "invalid-output",
    "dependency",
    "configuration",
    "resource",
    "worker",
    "repair",
    "malicious-evidence",
    "llm",
})
EXPECTED_SIGNALS = frozenset({
    "EXCEPTION",
    "TIMEOUT",
    "INVALID_OUTPUT",
    "DEPENDENCY_FAILURE",
    "CONFIGURATION_FAILURE",
    "RESOURCE_PRESSURE",
    "WORKER_FAILURE",
    "REPAIR_FAILURE",
    "MALICIOUS_EVIDENCE",
    "LLM_UNAVAILABLE",
})
CARETAKER_ACTIONS = frozenset({
    "CAPTURE_INCIDENT",
    "RECORD_EVIDENCE",
    "ROLLBACK_REPAIR",
    "REPLACE_WORKER",
    "CONTINUE_DEGRADED",
    "STOP_APPLICATION",
    "REQUIRE_OPERATOR_REVIEW",
})
AUTHORITY_EFFECTS = frozenset({
    "NO_AUTHORITY_CHANGE",
    "PROPOSAL_ONLY",
    "OPERATOR_REVIEW",
    "ROLLBACK",
    "DEGRADED",
    "APPLICATION_STOP",
})
ISOLATION_LEVELS = frozenset({"PROCESS", "CONTAINER", "VM"})


class FailureCorpusError(ValueError):
    """Raised when a failure corpus manifest is malformed or unsafe."""


def _text(value: Any, *, field: str, maximum: int = MAX_TEXT_CHARS) -> str:
    if not isinstance(value, str):
        raise FailureCorpusError(f"{field} must be a string")
    result = value.strip()
    if not result:
        raise FailureCorpusError(f"{field} must not be empty")
    if len(result) > maximum:
        raise FailureCorpusError(f"{field} exceeds {maximum} characters")
    if any(ord(character) < 32 and character not in "\n\t" for character in result):
        raise FailureCorpusError(f"{field} contains a control character")
    return result


def _identifier(value: Any, *, field: str) -> str:
    result = _text(value, field=field, maximum=128)
    if _IDENTIFIER.fullmatch(result) is None:
        raise FailureCorpusError(f"{field} is not a valid corpus identifier")
    return result


@dataclass(frozen=True, slots=True)
class FailureScenario:
    """One non-executable failure scenario declaration."""

    scenario_id: str
    category: str
    description: str
    stimulus: str
    expected_signal: str
    caretaker_action: str
    authority_effect: str
    minimum_isolation: str
    tags: tuple[str, ...] = ()

    def summary(self) -> dict[str, Any]:
        """Return bounded metadata suitable for reports and console views."""
        return {
            "scenario_id": self.scenario_id,
            "category": self.category,
            "description": self.description,
            "stimulus": self.stimulus,
            "expected_signal": self.expected_signal,
            "caretaker_action": self.caretaker_action,
            "authority_effect": self.authority_effect,
            "minimum_isolation": self.minimum_isolation,
            "tags": list(self.tags),
            "executable": False,
        }


class FailureCorpus:
    """Immutable in-memory view of a validated corpus manifest."""

    def __init__(self, *, corpus_id: str, description: str, scenarios: tuple[FailureScenario, ...]) -> None:
        self.corpus_id = corpus_id
        self.description = description
        self.scenarios = scenarios
        self._by_id = {scenario.scenario_id: scenario for scenario in scenarios}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FailureCorpus":
        if set(value) != {"schema_version", "corpus_id", "description", "scenarios"}:
            raise FailureCorpusError(
                "corpus manifest fields must be schema_version, corpus_id, description, and scenarios"
            )
        if value.get("schema_version") != FAILURE_CORPUS_SCHEMA_VERSION:
            raise FailureCorpusError("unsupported failure corpus schema version")
        corpus_id = _identifier(value.get("corpus_id"), field="corpus_id")
        description = _text(value.get("description"), field="description")
        raw_scenarios = value.get("scenarios")
        if not isinstance(raw_scenarios, list):
            raise FailureCorpusError("scenarios must be a list")
        if not raw_scenarios:
            raise FailureCorpusError("failure corpus must contain at least one scenario")
        if len(raw_scenarios) > MAX_SCENARIOS:
            raise FailureCorpusError(f"failure corpus exceeds {MAX_SCENARIOS} scenarios")
        scenarios: list[FailureScenario] = []
        seen: set[str] = set()
        for index, raw in enumerate(raw_scenarios):
            if not isinstance(raw, Mapping):
                raise FailureCorpusError(f"scenario {index} must be an object")
            if set(raw) != {
                "scenario_id", "category", "description", "stimulus", "expected", "tags"
            }:
                raise FailureCorpusError(
                    f"scenario {index} contains unsupported or missing fields"
                )
            scenario_id = _identifier(raw.get("scenario_id"), field=f"scenario {index}.scenario_id")
            if scenario_id in seen:
                raise FailureCorpusError(f"duplicate scenario_id {scenario_id!r}")
            seen.add(scenario_id)
            category = _text(raw.get("category"), field=f"scenario {index}.category", maximum=64)
            if category not in FAILURE_CATEGORIES:
                raise FailureCorpusError(f"scenario {scenario_id} has unknown category {category!r}")
            expected = raw.get("expected")
            if not isinstance(expected, Mapping) or set(expected) != {
                "signal", "caretaker_action", "authority_effect", "minimum_isolation"
            }:
                raise FailureCorpusError(
                    f"scenario {scenario_id}.expected has an unsupported shape"
                )
            signal = _text(expected.get("signal"), field=f"scenario {scenario_id}.expected.signal", maximum=64)
            action = _text(expected.get("caretaker_action"), field=f"scenario {scenario_id}.expected.caretaker_action", maximum=64)
            effect = _text(expected.get("authority_effect"), field=f"scenario {scenario_id}.expected.authority_effect", maximum=64)
            isolation = _text(expected.get("minimum_isolation"), field=f"scenario {scenario_id}.expected.minimum_isolation", maximum=32)
            if signal not in EXPECTED_SIGNALS:
                raise FailureCorpusError(f"scenario {scenario_id} has unknown expected signal {signal!r}")
            if action not in CARETAKER_ACTIONS:
                raise FailureCorpusError(f"scenario {scenario_id} has unknown Caretaker action {action!r}")
            if effect not in AUTHORITY_EFFECTS:
                raise FailureCorpusError(f"scenario {scenario_id} has unknown authority effect {effect!r}")
            if isolation not in ISOLATION_LEVELS:
                raise FailureCorpusError(f"scenario {scenario_id} has unknown isolation {isolation!r}")
            raw_tags = raw.get("tags")
            if not isinstance(raw_tags, list) or len(raw_tags) > MAX_TAGS:
                raise FailureCorpusError(f"scenario {scenario_id}.tags must contain at most {MAX_TAGS} strings")
            tags = tuple(sorted({
                _identifier(tag, field=f"scenario {scenario_id}.tag")
                for tag in raw_tags
            }))
            scenarios.append(FailureScenario(
                scenario_id=scenario_id,
                category=category,
                description=_text(raw.get("description"), field=f"scenario {scenario_id}.description"),
                stimulus=_text(raw.get("stimulus"), field=f"scenario {scenario_id}.stimulus"),
                expected_signal=signal,
                caretaker_action=action,
                authority_effect=effect,
                minimum_isolation=isolation,
                tags=tags,
            ))
        return cls(corpus_id=corpus_id, description=description, scenarios=tuple(scenarios))

    @classmethod
    def load(cls, path: str | Path, *, maximum_bytes: int = MAX_CORPUS_BYTES) -> "FailureCorpus":
        """Load one bounded JSON manifest without executing any declared value."""
        if maximum_bytes <= 0:
            raise ValueError("maximum_bytes must be greater than zero")
        manifest_path = Path(path)
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise FailureCorpusError("failure corpus manifest must be a regular file")
        try:
            raw = manifest_path.read_bytes()
        except OSError as exc:
            raise FailureCorpusError(f"cannot read failure corpus manifest: {exc}") from exc
        if len(raw) > maximum_bytes:
            raise FailureCorpusError("failure corpus manifest exceeds its byte limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FailureCorpusError("failure corpus manifest is not valid UTF-8 JSON") from exc
        if not isinstance(value, Mapping):
            raise FailureCorpusError("failure corpus manifest must be an object")
        return cls.from_mapping(value)

    def get(self, scenario_id: str) -> FailureScenario:
        try:
            return self._by_id[scenario_id]
        except KeyError as exc:
            raise KeyError(f"unknown failure corpus scenario {scenario_id!r}") from exc

    def list_summaries(self, *, category: str | None = None, limit: int = 100) -> tuple[dict[str, Any], ...]:
        bounded_limit = max(1, min(int(limit), MAX_SCENARIOS))
        return tuple(
            scenario.summary()
            for scenario in self.scenarios
            if category is None or scenario.category == category
        )[:bounded_limit]
