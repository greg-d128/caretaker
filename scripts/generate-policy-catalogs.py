#!/usr/bin/env python3
"""Generate machine-readable policy catalogs for a Caretaker source release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from caretaker.policy_semantics import (
    POLICY_SEMANTICS_REVIEW_GENERATION,
    RESERVED_SETTINGS,
    REVIEWED_POLICY_SURFACE_HASH,
)
from caretaker.profiles import CURRENT_POLICY_SURFACE_VERSION, capability_catalog


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("catalogs"))
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--force", action="store_true")
    return parser


def _write(path: Path, document: dict[str, object], *, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(f"Refusing to replace existing catalog: {path}; pass --force")
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    common = {
        "schema_version": 1,
        "caretaker_version": args.package_version,
        "policy_surface_version": CURRENT_POLICY_SURFACE_VERSION,
        "policy_semantics_review_generation": POLICY_SEMANTICS_REVIEW_GENERATION,
        "reviewed_policy_surface_hash": REVIEWED_POLICY_SURFACE_HASH,
    }
    capabilities = {
        **common,
        "catalog": "policy-capabilities",
        "capabilities": list(capability_catalog()),
    }
    reserved = {
        **common,
        "catalog": "reserved-policy-settings",
        "settings": dict(sorted(RESERVED_SETTINGS.items())),
    }
    version = args.package_version.replace("/", "_")
    _write(
        args.output_dir / f"caretaker-{version}-policy-capabilities.json",
        capabilities,
        force=args.force,
    )
    _write(
        args.output_dir / f"caretaker-{version}-reserved-settings.json",
        reserved,
        force=args.force,
    )
    print(f"Wrote policy catalogs for Caretaker {args.package_version} to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
