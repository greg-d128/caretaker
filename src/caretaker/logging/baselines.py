from __future__ import annotations

import hashlib
import json
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping
from uuid import UUID, uuid4

from .models import (
    ApplicationLoggingBaseline,
    BaselineChange,
    BaselineComparison,
    BaselineKey,
    BaselineState,
    FunctionLoggingBaseline,
    LogEnvelope,
    MetricSummary,
    TrendFinding,
)


def _metric(values: list[float]) -> MetricSummary:
    if not values:
        return MetricSummary(0, None, None, None, None)
    return MetricSummary(len(values), min(values), max(values), statistics.fmean(values), sum(values))


class BaselineBuilder:
    def build(
        self,
        records: Iterable[LogEnvelope],
        *,
        key: BaselineKey,
        period_start: datetime,
        period_end: datetime,
        dependency_snapshot_id: UUID | None = None,
        integrity_manifest_hash: str | None = None,
    ) -> ApplicationLoggingBaseline:
        by_population: dict[tuple[str, str | None], list[LogEnvelope]] = defaultdict(list)
        all_records = list(records)
        for record in all_records:
            if not record.target_id:
                continue
            population = record.fields.get("population_designator") if isinstance(record.fields, Mapping) else None
            by_population[(record.target_id, str(population) if population is not None else None)].append(record)
        functions: list[FunctionLoggingBaseline] = []
        for (target_id, population), items in sorted(by_population.items()):
            completed = [item for item in items if item.fields.get("event") == "function.call.completed"]
            failed = [item for item in items if item.fields.get("event") == "function.call.failed"]
            call_count = len(completed) + len(failed)
            durations = [float(item.fields["elapsed_seconds"]) for item in completed + failed if item.fields.get("elapsed_seconds") is not None]
            templates = Counter(item.message_template or item.formatted_message or "" for item in items)
            exceptions = Counter(str(item.fields.get("exception_type")) for item in failed)
            functions.append(FunctionLoggingBaseline(
                target_id=target_id,
                function_version=items[-1].function_version if items else None,
                population_designator=population,
                call_count=call_count,
                success_rate=(len(completed) / call_count) if call_count else 0.0,
                exception_rate=(len(failed) / call_count) if call_count else 0.0,
                duration_summary=_metric(durations),
                log_rate_summary=_metric([len(items) / call_count] if call_count else []),
                log_template_distribution={template: count / len(items) for template, count in templates.items()} if items else {},
                exception_fingerprints={name: count / len(failed) for name, count in exceptions.items()} if failed else {},
            ))
        metrics = {
            "record_count": _metric([float(len(all_records))]),
            "target_count": _metric([float(len(by_population))]),
        }
        unsigned = {
            "key": repr(key), "period_start": period_start.isoformat(), "period_end": period_end.isoformat(),
            "functions": [asdict(item) for item in functions], "metrics": {name: asdict(value) for name, value in metrics.items()},
        }
        content_hash = hashlib.sha256(json.dumps(unsigned, sort_keys=True, default=str).encode()).hexdigest()
        return ApplicationLoggingBaseline(
            baseline_id=uuid4(), key=key, period_start=period_start, period_end=period_end,
            dependency_snapshot_id=dependency_snapshot_id,
            integrity_manifest_hash=integrity_manifest_hash,
            functions=tuple(functions), application_metrics=metrics,
            behavior_profile_id=None, state=BaselineState.GENERATED, content_hash=content_hash,
        )


class BaselineStore:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def list(self, *, state: BaselineState | None = None) -> tuple[ApplicationLoggingBaseline, ...]:
        baselines = tuple(self.load(path) for path in sorted(self.directory.glob("*.json")))
        return tuple(item for item in baselines if state is None or item.state is state)

    def load(self, baseline: UUID | str | Path) -> ApplicationLoggingBaseline:
        path = Path(baseline) if isinstance(baseline, Path) else self.directory / f"{baseline}.json"
        if isinstance(baseline, str) and baseline.endswith(".json"):
            candidate = Path(baseline)
            if candidate.exists():
                path = candidate
        return _baseline_from_json(json.loads(path.read_text(encoding="utf-8")))

    def save(self, baseline: ApplicationLoggingBaseline) -> Path:
        path = self.directory / f"{baseline.baseline_id}.json"
        path.write_text(json.dumps(_jsonable(baseline), indent=2, sort_keys=True))
        return path

    def accept(self, baseline: ApplicationLoggingBaseline | UUID | str) -> ApplicationLoggingBaseline:
        """Mark an offline logging baseline as reviewed, never runtime-authoritative.

        Historical logging evidence is intentionally separate from Guard's
        runtime baseline authority operation.  Use the authenticated Guard
        control path for a baseline that may influence runtime decisions.
        """
        current = self.load(baseline) if isinstance(baseline, (UUID, str)) else baseline
        reviewed = replace(
            current,
            state=BaselineState.OPERATOR_REVIEWED,
            accepted_at=datetime.now(timezone.utc),
        )
        self.save(reviewed)
        return reviewed


class BaselineComparator:
    def compare(
        self,
        older: ApplicationLoggingBaseline,
        newer: ApplicationLoggingBaseline,
        *,
        units_of_work_old: float | None = None,
        units_of_work_new: float | None = None,
    ) -> BaselineComparison:
        old_functions = {(item.target_id, item.population_designator): item for item in older.functions}
        new_functions = {(item.target_id, item.population_designator): item for item in newer.functions}
        changes: list[BaselineChange] = []
        new_capabilities: list[str] = []
        removed: list[str] = []
        for key in sorted(set(old_functions) | set(new_functions)):
            old = old_functions.get(key)
            new = new_functions.get(key)
            if old is None:
                new_capabilities.append(f"new function population {key}")
                continue
            if new is None:
                removed.append(f"removed function population {key}")
                continue
            for metric, old_value, new_value in (
                ("call_count", float(old.call_count), float(new.call_count)),
                ("exception_rate", old.exception_rate, new.exception_rate),
                ("duration_mean", old.duration_summary.mean or 0.0, new.duration_summary.mean or 0.0),
            ):
                absolute = new_value - old_value
                relative = absolute / old_value if old_value else None
                old_per_unit = old_value / units_of_work_old if units_of_work_old else None
                new_per_unit = new_value / units_of_work_new if units_of_work_new else None
                per_unit = (new_per_unit - old_per_unit) if old_per_unit is not None and new_per_unit is not None else None
                significance = min(100.0, abs(relative or absolute) * 100.0)
                changes.append(BaselineChange(
                    category="growth" if metric == "call_count" else "efficiency",
                    subject=f"{key[0]}[{key[1]}].{metric}", old_value=old_value, new_value=new_value,
                    absolute_change=absolute, relative_change=relative, per_unit_change=per_unit,
                    significance=significance,
                ))
        scores = [item.significance for item in changes]
        overall = statistics.fmean(scores) if scores else 0.0
        interval_days = max(1.0, (newer.period_end - older.period_end).total_seconds() / 86400)
        trends = tuple(
            TrendFinding(
                metric=item.subject,
                slope_per_day=(item.absolute_change or 0.0) / interval_days,
                relative_change=item.relative_change,
                unit_of_work_change=item.per_unit_change,
                explanation="Change separated into absolute, relative, and per-unit-of-work components",
            )
            for item in changes if item.significance >= 10
        )
        slow_drift = min(100.0, sum(abs(item.slope_per_day) for item in trends) * 10.0)
        return BaselineComparison(
            comparison_id=uuid4(), baseline_a_id=older.baseline_id, baseline_b_id=newer.baseline_id,
            significant_changes=tuple(item for item in changes if item.significance >= 10),
            gradual_trends=trends, new_capabilities=tuple(new_capabilities),
            removed_capabilities=tuple(removed), overall_change_score=overall,
            slow_drift_score=slow_drift,
        )


def _baseline_from_json(data: Mapping[str, object]) -> ApplicationLoggingBaseline:
    key = BaselineKey(**dict(data["key"]))
    functions = []
    for item in data.get("functions", []):
        item = dict(item)
        item["duration_summary"] = MetricSummary(**dict(item["duration_summary"]))
        item["log_rate_summary"] = MetricSummary(**dict(item["log_rate_summary"]))
        if item.get("behavior_profile_id"):
            item["behavior_profile_id"] = UUID(str(item["behavior_profile_id"]))
        functions.append(FunctionLoggingBaseline(**item))
    metrics = {str(name): MetricSummary(**dict(value)) for name, value in dict(data.get("application_metrics", {})).items()}
    return ApplicationLoggingBaseline(
        baseline_id=UUID(str(data["baseline_id"])),
        key=key,
        period_start=datetime.fromisoformat(str(data["period_start"])),
        period_end=datetime.fromisoformat(str(data["period_end"])),
        dependency_snapshot_id=UUID(str(data["dependency_snapshot_id"])) if data.get("dependency_snapshot_id") else None,
        integrity_manifest_hash=str(data["integrity_manifest_hash"]) if data.get("integrity_manifest_hash") else None,
        functions=tuple(functions),
        application_metrics=metrics,
        behavior_profile_id=UUID(str(data["behavior_profile_id"])) if data.get("behavior_profile_id") else None,
        state=BaselineState[str(data["state"])],
        content_hash=str(data["content_hash"]),
        created_at=datetime.fromisoformat(str(data["created_at"])),
        accepted_at=datetime.fromisoformat(str(data["accepted_at"])) if data.get("accepted_at") else None,
    )


def _jsonable(value):
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, (datetime, UUID)):
        return str(value)
    if hasattr(value, "name"):
        return value.name
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value
