"""Run explicitly mapped failure-corpus scenarios under a selected isolation tier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .failure_corpus import (
    FailureCorpus,
    FailureCorpusExecutionPolicy,
    FailureCorpusMultipassRunner,
    FailureCorpusObservationStore,
    FailureCorpusPodmanRunner,
    FailureCorpusProcessRunner,
)


def _environment(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise ValueError("--env values must use KEY=VALUE")
        key, value = item.split("=", 1)
        if not key:
            raise ValueError("--env keys must not be empty")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="caretaker-failure-corpus-run",
        description="Run explicitly mapped failure-corpus scenarios under policy-selected isolation.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("examples/failure_corpus/manifest.json"),
        help="metadata-only failure corpus manifest",
    )
    parser.add_argument(
        "--data-directory",
        type=Path,
        default=Path("./caretaker-data"),
        help="Caretaker data directory for observations and reports",
    )
    parser.add_argument(
        "--isolation",
        choices=("PROCESS", "CONTAINER", "VM"),
        default="PROCESS",
        help="actual runner boundary (default: PROCESS)",
    )
    parser.add_argument(
        "--minimum-isolation",
        choices=("PROCESS", "CONTAINER", "VM"),
        help="policy minimum; defaults to --isolation",
    )
    parser.add_argument("--scenario-id", action="append", help="run only this scenario; repeatable")
    parser.add_argument("--runner-command", nargs="+", help="explicit trusted command for CONTAINER or VM")
    parser.add_argument(
        "--application-laboratory",
        action="store_true",
        help="use the repository application laboratory command for PROCESS or CONTAINER",
    )
    parser.add_argument("--image", help="pre-provisioned local Podman image for CONTAINER")
    parser.add_argument("--multipass-instance", default="caretaker-validator", help="pre-provisioned VM name")
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--environment", "--env", dest="environment", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--persist-report", action="store_true", help="persist the resulting report by content hash")
    args = parser.parse_args(argv)

    manifest = args.manifest.expanduser().resolve()
    corpus = FailureCorpus.load(manifest)
    selected_ids = args.scenario_id or [scenario.scenario_id for scenario in corpus.scenarios]
    for scenario_id in selected_ids:
        corpus.get(scenario_id)
    minimum = args.minimum_isolation or args.isolation
    policy = FailureCorpusExecutionPolicy(minimum_isolation=minimum)
    environment = _environment(args.environment)
    default_laboratory = manifest.parent / "application_laboratory.py"
    if args.application_laboratory and args.runner_command:
        parser.error("--application-laboratory cannot be combined with --runner-command")
    if args.application_laboratory and args.isolation == "VM":
        parser.error(
            "--application-laboratory does not select a VM guest command; use --runner-command"
        )

    if args.isolation == "PROCESS":
        command = args.runner_command or [sys.executable, str(default_laboratory)]
        runner = FailureCorpusProcessRunner(
            corpus,
            {scenario_id: command for scenario_id in selected_ids},
            policy=policy,
            timeout_seconds=args.timeout_seconds,
            workspace_root=args.data_directory.expanduser().resolve() / "failure-corpus-workspaces",
            environment=environment,
        )
    elif args.isolation == "CONTAINER":
        if not args.image:
            parser.error("--image is required for CONTAINER isolation")
        if args.application_laboratory:
            command = ["python", "/opt/caretaker/application_laboratory.py"]
        elif not args.runner_command:
            parser.error("--runner-command is required for CONTAINER isolation")
        else:
            command = args.runner_command
        runner = FailureCorpusPodmanRunner(
            corpus,
            args.image,
            {scenario_id: command for scenario_id in selected_ids},
            policy=policy,
            timeout_seconds=args.timeout_seconds,
            environment=environment,
        )
    else:
        if not args.runner_command:
            parser.error("--runner-command is required for VM isolation")
        runner = FailureCorpusMultipassRunner(
            corpus,
            {scenario_id: args.runner_command for scenario_id in selected_ids},
            policy=policy,
            timeout_seconds=args.timeout_seconds,
            instance_name=args.multipass_instance,
        )

    store = FailureCorpusObservationStore(args.data_directory.expanduser().resolve())
    environment_id = f"failure-corpus-{args.isolation.lower()}"
    observations = []
    for scenario_id in selected_ids:
        observation = runner.run(scenario_id)
        observations.append(observation.summary())
        store.record(
            observation,
            corpus_id=corpus.corpus_id,
            environment_id=environment_id,
        )
    report = store.build_outcome_report(
        corpus_id=corpus.corpus_id,
        environment_id=environment_id,
        limit=max(1, len(selected_ids)),
    )
    if args.persist_report:
        report = store.persist_outcome_report(report)
    json.dump(
        {
            "ok": True,
            "corpus_id": corpus.corpus_id,
            "isolation": args.isolation,
            "policy": policy.summary(),
            "observations": observations,
            "report": report,
        },
        sys.stdout,
        indent=2,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
