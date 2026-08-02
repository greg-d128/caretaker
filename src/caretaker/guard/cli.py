from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from ..evidence.identity import inventory_distribution
from ..evidence.store import SQLiteEvidenceStore
from .introspection import RuntimeInspector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="caretaker-guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser("inventory", help="Inventory installed distributions")
    inventory.add_argument("distributions", nargs="+")

    query = subparsers.add_parser("query", help="Run a read-only SQL query against Guard evidence")
    query.add_argument("database", type=Path)
    query.add_argument("sql")

    inspect_module = subparsers.add_parser("inspect-module", help="Inspect a loaded module")
    inspect_module.add_argument("module")
    inspect_module.add_argument("--database", type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inventory":
        records = [inventory_distribution(name) for name in args.distributions]
        print(json.dumps([_jsonable(record) for record in records], indent=2, sort_keys=True))
        return 0
    if args.command == "query":
        store = SQLiteEvidenceStore(args.database)
        rows = store.query(args.sql)
        print(json.dumps(rows, indent=2, sort_keys=True, default=str))
        return 0
    if args.command == "inspect-module":
        module = importlib.import_module(args.module)
        store = SQLiteEvidenceStore(args.database) if args.database else __import__(
            "caretaker.evidence.store", fromlist=["InMemoryEvidenceStore"]
        ).InMemoryEvidenceStore()
        inspection = RuntimeInspector(store).inspect_module(module)
        print(json.dumps(_jsonable(inspection), indent=2, sort_keys=True))
        return 0
    return 2


def _jsonable(value):
    import dataclasses
    from datetime import datetime
    from enum import Enum
    from pathlib import Path
    from uuid import UUID

    if dataclasses.is_dataclass(value):
        return {field.name: _jsonable(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, (UUID, Path)):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
