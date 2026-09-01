from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .baselines import BaselineBuilder, BaselineComparator, BaselineStore
from .interrogation import InterrogationRequest, LogInterrogator, OllamaRootCauseProvider
from .ipc import control_request
from .models import BaselineKey, BaselineState
from .policy import load_operator_policy, reconcile_policy
from .segments import read_segment


def _datetime(value: str | None, *, default: datetime) -> datetime:
    if value is None:
        return default
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _record_paths(values: Iterable[str]) -> tuple[Path, ...]:
    paths: list[Path] = []
    for value in values:
        path = Path(value)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.ctlog")))
            paths.extend(sorted(path.glob("*.ctlog.gz")))
        else:
            paths.append(path)
    return tuple(dict.fromkeys(paths))


def _records(values: Iterable[str]):
    records = []
    for path in _record_paths(values):
        records.extend(read_segment(path))
    return tuple(sorted(records, key=lambda item: (item.occurred_at, item.sequence_number)))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caretaker-logging")
    sub = parser.add_subparsers(dest="command", required=True)

    policy = sub.add_parser("policy")
    policy.add_argument("action", choices=("explain", "effective"))
    policy.add_argument("--file", required=True)

    records = sub.add_parser("records")
    records.add_argument("segment")
    records.add_argument("--limit", type=int, default=50)

    control = sub.add_parser("control")
    control.add_argument("socket")
    control.add_argument("action", choices=("status", "health", "policy-effective", "mode-acquire", "mode-release"))
    control.add_argument("--mode")
    control.add_argument("--lease-id")
    control.add_argument("--reason", default="operator request")

    baseline = sub.add_parser("baseline")
    baseline_sub = baseline.add_subparsers(dest="baseline_action", required=True)
    baseline_generate = baseline_sub.add_parser("generate")
    baseline_generate.add_argument("--segments", nargs="+", required=True)
    baseline_generate.add_argument("--store", required=True)
    baseline_generate.add_argument("--application-id", required=True)
    baseline_generate.add_argument("--application-version")
    baseline_generate.add_argument("--environment-id")
    baseline_generate.add_argument("--workload-label")
    baseline_generate.add_argument("--period-start")
    baseline_generate.add_argument("--period-end")
    baseline_generate.add_argument(
        "--accept", action="store_true",
        help="mark historical logging evidence operator-reviewed (offline; not runtime-authoritative)",
    )
    baseline_list = baseline_sub.add_parser("list")
    baseline_list.add_argument("--store", required=True)
    baseline_list.add_argument("--state", choices=tuple(item.name.lower() for item in BaselineState))
    baseline_accept = baseline_sub.add_parser("accept")
    baseline_accept.add_argument("--store", required=True)
    baseline_accept.add_argument("baseline_id")
    baseline_compare = baseline_sub.add_parser("compare")
    baseline_compare.add_argument("--store", required=True)
    baseline_compare.add_argument("older")
    baseline_compare.add_argument("newer")
    baseline_compare.add_argument("--units-old", type=float)
    baseline_compare.add_argument("--units-new", type=float)

    interrogate = sub.add_parser("interrogate")
    interrogate.add_argument("--segments", nargs="+", required=True)
    interrogate.add_argument("--period-start")
    interrogate.add_argument("--period-end")
    interrogate.add_argument("--target", action="append", default=[])
    interrogate.add_argument("--objective")
    interrogate.add_argument("--ollama-model")
    interrogate.add_argument("--ollama-endpoint", default="http://127.0.0.1:11434/api/generate")

    args = parser.parse_args(argv)
    if args.command == "policy":
        loaded, snapshot = load_operator_policy(args.file)
        effective = reconcile_policy(loaded, snapshot)
        output = snapshot.human_readable_policy if args.action == "explain" else json.dumps({
            "requested_modes": [item.name for item in effective.requested_modes],
            "effective_modes": [item.name for item in effective.effective_modes],
            "generation": effective.generation,
            "overrides": [vars_like(item) for item in effective.overrides],
            "warnings": effective.warnings,
        }, indent=2, default=str)
        print(output)
        return 0
    if args.command == "records":
        for record in read_segment(args.segment)[-args.limit:]:
            print(json.dumps(vars_like(record), default=str, sort_keys=True))
        return 0
    if args.command == "control":
        request = {"command": args.action, "reason": args.reason}
        if args.mode:
            request["mode"] = args.mode
        if args.lease_id:
            request["lease_id"] = args.lease_id
        print(json.dumps(control_request(args.socket, request), indent=2, default=str))
        return 0
    if args.command == "baseline":
        store = BaselineStore(args.store)
        if args.baseline_action == "generate":
            records_in = _records(args.segments)
            if not records_in:
                raise SystemExit("No readable Caretaker records were found")
            period_start = _datetime(args.period_start, default=min(item.occurred_at for item in records_in))
            period_end = _datetime(args.period_end, default=max(item.occurred_at for item in records_in))
            key = BaselineKey(
                application_id=args.application_id,
                application_version=args.application_version,
                environment_id=args.environment_id,
                target_id=None,
                function_version=None,
                population_designator=None,
                workload_label=args.workload_label,
            )
            generated = BaselineBuilder().build(records_in, key=key, period_start=period_start, period_end=period_end)
            stored = store.accept(generated) if args.accept else generated
            path = store.save(stored)
            print(json.dumps({"baseline": vars_like(stored), "path": str(path)}, indent=2, default=str))
            return 0
        if args.baseline_action == "list":
            state = BaselineState[args.state.upper()] if args.state else None
            print(json.dumps([vars_like(item) for item in store.list(state=state)], indent=2, default=str))
            return 0
        if args.baseline_action == "accept":
            print(json.dumps(vars_like(store.accept(args.baseline_id)), indent=2, default=str))
            return 0
        older = store.load(args.older)
        newer = store.load(args.newer)
        comparison = BaselineComparator().compare(
            older, newer, units_of_work_old=args.units_old, units_of_work_new=args.units_new,
        )
        print(json.dumps(vars_like(comparison), indent=2, default=str))
        return 0
    if args.command == "interrogate":
        records_in = _records(args.segments)
        if not records_in:
            raise SystemExit("No readable Caretaker records were found")
        request = InterrogationRequest(
            period_start=_datetime(args.period_start, default=min(item.occurred_at for item in records_in)),
            period_end=_datetime(args.period_end, default=max(item.occurred_at for item in records_in)),
            target_ids=tuple(args.target),
            objective=args.objective,
        )
        interrogator = LogInterrogator()
        bundle = interrogator.build_bundle(request, records_in)
        assessment = (
            OllamaRootCauseProvider(model=args.ollama_model, endpoint=args.ollama_endpoint).assess(bundle)
            if args.ollama_model else interrogator.deterministic_assessment(bundle)
        )
        print(json.dumps({"evidence": vars_like(bundle), "assessment": vars_like(assessment)}, indent=2, default=str))
        return 0
    return 2


def vars_like(value):
    if is_dataclass(value):
        return asdict(value)
    return value


if __name__ == "__main__":
    raise SystemExit(main())
