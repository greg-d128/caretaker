"""Read-only reporting for persisted failure-corpus observations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .failure_corpus import FailureCorpusObservationStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-failure-corpus-report",
        description="Summarize bounded failure-corpus observations; never execute them.",
    )
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory",
    )
    parser.add_argument("--corpus-id", help="limit the report to one corpus")
    parser.add_argument("--environment-id", help="limit the report to one environment")
    parser.add_argument("--scenario-id", help="limit the report to one scenario")
    parser.add_argument("--limit", type=int, default=500, help="maximum observations to include")
    parser.add_argument(
        "--persist",
        action="store_true",
        help="retain the report as a content-addressed local artifact",
    )
    args = parser.parse_args(argv)

    store = FailureCorpusObservationStore(args.data_directory.expanduser().resolve())
    report = store.build_outcome_report(
        corpus_id=args.corpus_id,
        environment_id=args.environment_id,
        scenario_id=args.scenario_id,
        limit=args.limit,
    )
    if args.persist:
        report = store.persist_outcome_report(report)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
