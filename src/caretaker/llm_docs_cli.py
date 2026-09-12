"""Deterministic offline access to Caretaker's installed programmer cards."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .llm_docs import CONTRACT_LINE, DocumentationError, entry_path, load_index, read_entry


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="caretaker-docs",
        description="Read the versioned Caretaker programmer documentation bundle.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List packaged documentation entries")
    show = sub.add_parser("show", help="Print one documentation entry")
    show.add_argument("task_id")
    index = sub.add_parser("index", help="Print the machine-readable index")
    index.add_argument("--json", action="store_true", required=True)
    path = sub.add_parser("path", help="Print one entry's installed filesystem path")
    path.add_argument("task_id")
    return parser


def _list() -> int:
    index = load_index()
    print(f"Caretaker documentation (package {index['package_version']}; contract {index['contract_line']})")
    for entry in index["entries"]:
        print(f"{entry['id']:<38} {entry['kind']:<9} {entry['title']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        if args.command == "list":
            return _list()
        if args.command == "index":
            print(json.dumps(load_index(), indent=2, sort_keys=True))
            return 0
        if args.command == "show":
            entry, body = read_entry(args.task_id)
            print(f"Caretaker documentation: {entry['id']}")
            print(f"Package: {__version__} | Contract: {CONTRACT_LINE}")
            print(body, end="" if body.endswith("\n") else "\n")
            return 0
        if args.command == "path":
            with entry_path(args.task_id) as path:
                print(path)
            return 0
    except DocumentationError as exc:
        print(f"caretaker-docs: {exc}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        print(f"caretaker-docs: {exc}", file=sys.stderr)
        return 2
    parser.error("unhandled command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
