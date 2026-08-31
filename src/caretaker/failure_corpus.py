"""Bounded, reviewable metadata for the Caretaker failure corpus.

Corpus manifests describe test stimuli and expected Caretaker boundaries.  They
are deliberately not runners: a manifest cannot name a Python callable, shell
command, URL, or executable entrypoint.  A separate, explicitly authorized
test harness may map a scenario ID to code in its own trusted test suite.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Callable
from typing import Any, Mapping
from uuid import UUID, uuid4


FAILURE_CORPUS_SCHEMA_VERSION = 1
MAX_CORPUS_BYTES = 1_048_576
MAX_SCENARIOS = 500
MAX_TEXT_CHARS = 2_048
MAX_TAGS = 32
MAX_OBSERVATION_BYTES = 16_384
MAX_STORED_OBSERVATION_BYTES = 32_768
MAX_OUTCOME_REPORT_BYTES = 65_536
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
OBSERVED_RESULT_FIELDS = frozenset({"signal", "caretaker_action", "authority_effect", "details"})
OBSERVATION_STATUSES = frozenset({
    "MATCHED",
    "MISMATCHED",
    "INVALID_RESULT",
    "ERROR",
    "NOT_MAPPED",
    "ISOLATION_UNAVAILABLE",
})


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


@dataclass(frozen=True, slots=True)
class FailureObservation:
    """The bounded result of one explicitly mapped trusted-harness run."""

    scenario_id: str
    status: str
    executed: bool
    required_isolation: str
    used_isolation: str
    expected_signal: str
    expected_caretaker_action: str
    expected_authority_effect: str
    observed: Mapping[str, Any] | None = None
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": FAILURE_CORPUS_SCHEMA_VERSION,
            "scenario_id": self.scenario_id,
            "status": self.status,
            "executed": self.executed,
            "required_isolation": self.required_isolation,
            "used_isolation": self.used_isolation,
            "expected": {
                "signal": self.expected_signal,
                "caretaker_action": self.expected_caretaker_action,
                "authority_effect": self.expected_authority_effect,
            },
            "observed": dict(self.observed) if self.observed is not None else None,
            "error": self.error,
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


class FailureCorpusHarness:
    """Run only explicitly supplied trusted mappings for a validated corpus.

    This harness does not discover imports, commands, or entrypoints from the
    manifest.  The caller supplies each runner and declares the isolation it
    actually provides.  Isolation is checked before the runner is called; the
    harness itself is not a sandbox and must be used only by a trusted test
    environment.
    """

    def __init__(
        self,
        corpus: FailureCorpus,
        runners: Mapping[str, Callable[[FailureScenario], Mapping[str, Any]]],
        *,
        isolation: str = "PROCESS",
    ) -> None:
        normalized_isolation = str(isolation).strip().upper()
        if normalized_isolation not in ISOLATION_LEVELS:
            raise FailureCorpusError(f"unknown harness isolation {isolation!r}")
        self.corpus = corpus
        self.runners = dict(runners)
        self.isolation = normalized_isolation

    def _base_observation(self, scenario: FailureScenario, *, status: str, executed: bool, error: str | None = None, observed: Mapping[str, Any] | None = None) -> FailureObservation:
        return FailureObservation(
            scenario_id=scenario.scenario_id,
            status=status,
            executed=executed,
            required_isolation=scenario.minimum_isolation,
            used_isolation=self.isolation,
            expected_signal=scenario.expected_signal,
            expected_caretaker_action=scenario.caretaker_action,
            expected_authority_effect=scenario.authority_effect,
            observed=observed,
            error=error[:512] if error else None,
        )

    def run(self, scenario_id: str) -> FailureObservation:
        scenario = self.corpus.get(scenario_id)
        if scenario.scenario_id not in self.runners:
            return self._base_observation(scenario, status="NOT_MAPPED", executed=False)
        if ISOLATION_LEVELS_ORDER[self.isolation] < ISOLATION_LEVELS_ORDER[scenario.minimum_isolation]:
            return self._base_observation(
                scenario,
                status="ISOLATION_UNAVAILABLE",
                executed=False,
                error="trusted harness isolation is below the scenario minimum",
            )
        runner = self.runners[scenario.scenario_id]
        try:
            observed = runner(scenario)
        except Exception as exc:
            return self._base_observation(
                scenario,
                status="ERROR",
                executed=True,
                error=f"{type(exc).__name__}: {exc}",
            )
        if not isinstance(observed, Mapping):
            return self._base_observation(
                scenario,
                status="INVALID_RESULT",
                executed=True,
                error="trusted scenario runner must return a mapping",
            )
        observed_copy = dict(observed)
        unknown_fields = sorted(set(observed_copy) - OBSERVED_RESULT_FIELDS)
        if unknown_fields:
            return self._base_observation(
                scenario,
                status="INVALID_RESULT",
                executed=True,
                observed=observed_copy,
                error="observed result contains unsupported fields: " + ", ".join(unknown_fields),
            )
        try:
            encoded = json.dumps(observed_copy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            return self._base_observation(
                scenario,
                status="INVALID_RESULT",
                executed=True,
                error=f"observed result is not bounded JSON: {exc}",
            )
        if len(encoded) > MAX_OBSERVATION_BYTES:
            return self._base_observation(
                scenario,
                status="INVALID_RESULT",
                executed=True,
                error=f"observed result exceeds {MAX_OBSERVATION_BYTES} bytes",
            )
        signal = observed_copy.get("signal")
        action = observed_copy.get("caretaker_action")
        effect = observed_copy.get("authority_effect")
        if signal not in EXPECTED_SIGNALS or action not in CARETAKER_ACTIONS or effect not in AUTHORITY_EFFECTS:
            return self._base_observation(
                scenario,
                status="INVALID_RESULT",
                executed=True,
                observed=observed_copy,
                error="observed result has an unknown or missing signal, action, or authority effect",
            )
        status = "MATCHED" if (
            signal == scenario.expected_signal
            and action == scenario.caretaker_action
            and effect == scenario.authority_effect
        ) else "MISMATCHED"
        return self._base_observation(
            scenario,
            status=status,
            executed=True,
            observed=observed_copy,
        )

    def run_all(self, *, category: str | None = None, limit: int = 100) -> tuple[FailureObservation, ...]:
        bounded_limit = max(1, min(int(limit), MAX_SCENARIOS))
        selected = [
            scenario for scenario in self.corpus.scenarios
            if category is None or scenario.category == category
        ][:bounded_limit]
        return tuple(self.run(scenario.scenario_id) for scenario in selected)


class FailureCorpusObservationStore:
    """Immutable local storage for bounded trusted-harness observations."""

    def __init__(
        self,
        root: str | Path,
        *,
        maximum_observation_bytes: int = MAX_STORED_OBSERVATION_BYTES,
    ) -> None:
        if maximum_observation_bytes <= 0:
            raise ValueError("maximum_observation_bytes must be greater than zero")
        self.directory = Path(root).expanduser().resolve() / "failure-corpus-observations"
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass
        self.report_directory = self.directory.parent / "failure-corpus-reports"
        self.report_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.report_directory.chmod(0o700)
        except OSError:
            pass
        self.maximum_observation_bytes = maximum_observation_bytes

    @staticmethod
    def _canonical(value: Mapping[str, Any]) -> bytes:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")

    def record(
        self,
        observation: FailureObservation,
        *,
        corpus_id: str,
        environment_id: str | None = None,
        incident_id: str | None = None,
        recorded_at: datetime | None = None,
    ) -> dict[str, Any]:
        if not isinstance(observation, FailureObservation):
            raise FailureCorpusError("observation must be a FailureObservation")
        corpus_name = _identifier(corpus_id, field="corpus_id")
        environment = _text(environment_id, field="environment_id", maximum=128) if environment_id is not None else None
        incident = _text(incident_id, field="incident_id", maximum=128) if incident_id is not None else None
        timestamp = recorded_at or datetime.now(timezone.utc)
        if not isinstance(timestamp, datetime):
            raise FailureCorpusError("recorded_at must be a datetime")
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)
        payload: dict[str, Any] = {
            "schema_version": FAILURE_CORPUS_SCHEMA_VERSION,
            "observation_id": str(uuid4()),
            "corpus_id": corpus_name,
            "recorded_at": timestamp.isoformat(),
            "environment_id": environment,
            "incident_id": incident,
            "observation": observation.summary(),
        }
        encoded = self._canonical(payload)
        envelope = {
            "record": payload,
            "content_sha256": hashlib.sha256(encoded).hexdigest(),
        }
        serialized = self._canonical(envelope)
        if len(serialized) > self.maximum_observation_bytes:
            raise FailureCorpusError("failure corpus observation exceeds its byte limit")
        path = self.directory / f"{payload['observation_id']}.json"
        temporary = path.with_suffix(".json.tmp")
        temporary.write_bytes(serialized)
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        temporary.replace(path)
        return {**payload, "content_sha256": envelope["content_sha256"]}

    def _load_path(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise FailureCorpusError("observation record must be a regular file")
        try:
            raw = path.read_bytes()
            if len(raw) > self.maximum_observation_bytes:
                raise FailureCorpusError("observation record exceeds its byte limit")
            envelope = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FailureCorpusError("observation record is not valid JSON") from exc
        if not isinstance(envelope, Mapping):
            raise FailureCorpusError("observation record must be an object")
        record = envelope.get("record")
        observed_hash = envelope.get("content_sha256")
        if not isinstance(record, Mapping) or not isinstance(observed_hash, str):
            raise FailureCorpusError("observation record envelope is malformed")
        expected_hash = hashlib.sha256(self._canonical(record)).hexdigest()
        if observed_hash != expected_hash:
            raise FailureCorpusError("observation record content hash does not match")
        if record.get("schema_version") != FAILURE_CORPUS_SCHEMA_VERSION:
            raise FailureCorpusError("unsupported observation record schema version")
        observation = record.get("observation")
        if not isinstance(observation, Mapping):
            raise FailureCorpusError("observation record has no observation object")
        if observation.get("scenario_id") is None or observation.get("status") is None:
            raise FailureCorpusError("observation record is missing scenario identity or status")
        if observation.get("status") not in OBSERVATION_STATUSES:
            raise FailureCorpusError("observation record has an unknown status")
        return {**dict(record), "content_sha256": observed_hash}

    def load(self, observation_id: str | UUID) -> dict[str, Any]:
        try:
            parsed = observation_id if isinstance(observation_id, UUID) else UUID(str(observation_id))
        except (TypeError, ValueError) as exc:
            raise KeyError(f"unknown observation {observation_id!r}") from exc
        path = self.directory / f"{parsed}.json"
        if not path.exists():
            raise KeyError(f"unknown observation {parsed}")
        return self._load_path(path)

    def list_summaries(
        self,
        *,
        scenario_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        bounded_limit = max(1, min(int(limit), MAX_SCENARIOS))
        result: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("*.json")):
            if len(result) >= bounded_limit:
                break
            try:
                record = self._load_path(path)
            except FailureCorpusError:
                continue
            observation = record.get("observation") or {}
            if scenario_id is not None and str(observation.get("scenario_id")) != str(scenario_id):
                continue
            if status is not None and str(observation.get("status")) != str(status):
                continue
            result.append({
                "observation_id": record.get("observation_id"),
                "corpus_id": record.get("corpus_id"),
                "recorded_at": record.get("recorded_at"),
                "environment_id": record.get("environment_id"),
                "incident_id": record.get("incident_id"),
                "observation": dict(observation),
                "content_sha256": record.get("content_sha256"),
            })
        return tuple(result)

    def build_outcome_report(
        self,
        *,
        corpus_id: str | None = None,
        environment_id: str | None = None,
        scenario_id: str | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Build a deterministic, bounded summary of retained observations.

        The report contains counts and record hashes, not full observed details.
        It is a review artifact only: it cannot authorize a repair or alter a
        corpus, capsule, policy, or authority state.
        """
        corpus_filter = _identifier(corpus_id, field="corpus_id") if corpus_id is not None else None
        environment_filter = _text(environment_id, field="environment_id", maximum=128) if environment_id is not None else None
        scenario_filter = _identifier(scenario_id, field="scenario_id") if scenario_id is not None else None
        bounded_limit = max(1, min(int(limit), MAX_SCENARIOS))
        valid_records: list[dict[str, Any]] = []
        corrupt_records = 0
        paths = sorted(self.directory.glob("*.json"))
        for path in paths:
            try:
                record = self._load_path(path)
            except FailureCorpusError:
                corrupt_records += 1
                continue
            if corpus_filter is not None and record.get("corpus_id") != corpus_filter:
                continue
            if environment_filter is not None and record.get("environment_id") != environment_filter:
                continue
            observation = record.get("observation") or {}
            if scenario_filter is not None and observation.get("scenario_id") != scenario_filter:
                continue
            valid_records.append(record)

        selected = valid_records[:bounded_limit]
        status_counts: dict[str, int] = {}
        scenario_counts: dict[str, dict[str, Any]] = {}
        environment_counts: dict[str, int] = {}
        for record in selected:
            observation = record["observation"]
            status = str(observation["status"])
            scenario_name = str(observation["scenario_id"])
            environment_name = str(record.get("environment_id") or "unspecified")
            status_counts[status] = status_counts.get(status, 0) + 1
            environment_counts[environment_name] = environment_counts.get(environment_name, 0) + 1
            scenario = scenario_counts.setdefault(scenario_name, {"count": 0, "status_counts": {}})
            scenario["count"] += 1
            scenario_statuses = scenario["status_counts"]
            scenario_statuses[status] = scenario_statuses.get(status, 0) + 1

        payload: dict[str, Any] = {
            "schema_version": FAILURE_CORPUS_SCHEMA_VERSION,
            "report_type": "FAILURE_CORPUS_OUTCOME_REPORT",
            "corpus_id": corpus_filter,
            "environment_id": environment_filter,
            "scenario_id": scenario_filter,
            "records_available": len(valid_records),
            "records_included": len(selected),
            "corrupt_records": corrupt_records,
            "truncated": len(valid_records) > len(selected),
            "status_counts": dict(sorted(status_counts.items())),
            "scenario_counts": {
                key: {
                    "count": value["count"],
                    "status_counts": dict(sorted(value["status_counts"].items())),
                }
                for key, value in sorted(scenario_counts.items())
            },
            "environment_counts": dict(sorted(environment_counts.items())),
            "provenance": [
                {
                    "observation_id": record["observation_id"],
                    "content_sha256": record["content_sha256"],
                }
                for record in selected
            ],
        }
        payload["content_sha256"] = hashlib.sha256(self._canonical(payload)).hexdigest()
        return payload

    @classmethod
    def _verify_report(cls, report: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(report, Mapping):
            raise FailureCorpusError("outcome report must be an object")
        observed_hash = report.get("content_sha256")
        if not isinstance(observed_hash, str):
            raise FailureCorpusError("outcome report content hash is missing")
        payload = dict(report)
        payload.pop("content_sha256", None)
        expected_hash = hashlib.sha256(cls._canonical(payload)).hexdigest()
        if observed_hash != expected_hash:
            raise FailureCorpusError("outcome report content hash does not match")
        if payload.get("schema_version") != FAILURE_CORPUS_SCHEMA_VERSION:
            raise FailureCorpusError("unsupported outcome report schema version")
        if payload.get("report_type") != "FAILURE_CORPUS_OUTCOME_REPORT":
            raise FailureCorpusError("unsupported outcome report type")
        return {**payload, "content_sha256": observed_hash}

    def persist_outcome_report(self, report: Mapping[str, Any]) -> dict[str, Any]:
        """Persist one verified deterministic report as a content-addressed artifact."""
        verified = self._verify_report(report)
        serialized = self._canonical(verified)
        if len(serialized) > MAX_OUTCOME_REPORT_BYTES:
            raise FailureCorpusError("outcome report exceeds its byte limit")
        report_path = self.report_directory / f"{verified['content_sha256']}.json"
        if report_path.exists():
            return self._load_report_path(report_path)
        temporary = self.report_directory / f".{verified['content_sha256']}.{uuid4()}.tmp"
        temporary.write_bytes(serialized)
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        temporary.replace(report_path)
        return verified

    def _load_report_path(self, path: Path) -> dict[str, Any]:
        if path.is_symlink() or not path.is_file():
            raise FailureCorpusError("outcome report must be a regular file")
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_OUTCOME_REPORT_BYTES:
                raise FailureCorpusError("outcome report exceeds its byte limit")
            report = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FailureCorpusError("outcome report is not valid JSON") from exc
        return self._verify_report(report)

    def load_outcome_report(self, content_sha256: str) -> dict[str, Any]:
        """Load one persisted report by its content hash, rejecting tampering."""
        if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
            raise KeyError(f"unknown outcome report {content_sha256!r}")
        path = self.report_directory / f"{content_sha256}.json"
        if not path.exists():
            raise KeyError(f"unknown outcome report {content_sha256}")
        return self._load_report_path(path)


ISOLATION_LEVELS_ORDER = {name: index for index, name in enumerate(("PROCESS", "CONTAINER", "VM"), start=1)}
