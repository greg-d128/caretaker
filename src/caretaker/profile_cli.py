from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .authority import load_policy_authority_layer, write_policy_authority_layer
from .profiles import (
    capability_catalog,
    compare_profiles,
    create_deployment_pin,
    format_comparison_text,
    load_profile,
    profile_coverage,
    profile_summary,
)


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _show_text(path: Path) -> None:
    layer = load_policy_authority_layer(path, require_canonical=True)
    summary = profile_summary(layer)
    profile = summary["profile"]
    coverage = summary["coverage"] or {}
    if profile:
        print(f"Profile:      {profile.get('name')} v{profile.get('version')}")
        print(f"Lineage:      {profile.get('lineage')}")
    else:
        print("Profile:      (ordinary authority policy; no named profile lineage)")
    print(f"Authority:    {summary['authority_id']}")
    print(f"Fingerprint:  {summary['fingerprint']}")
    if profile:
        print(f"Surface:      {coverage.get('profile_surface_version')}/{coverage.get('current_surface_version')}")
        print(f"Coverage:     {'COMPLETE' if coverage.get('complete') else 'REVIEW REQUIRED'}")
        print(f"Signer role:  {profile.get('signer_role') or '-'}")
        print(f"Min version:  {profile.get('caretaker_minimum') or '-'}")
        print(f"Tested thru:  {profile.get('caretaker_tested_through') or '-'}")
        print(f"Strict cover: {'yes' if profile.get('require_complete_surface') else 'no'}")
        print(f"Version review: {'yes' if profile.get('require_current_caretaker_version') else 'no'}")
        if profile.get("description"):
            print(f"Description:  {profile['description']}")
        if profile.get("supersedes_version"):
            print(
                "Supersedes:   "
                f"v{profile['supersedes_version']} {profile.get('supersedes_fingerprint') or ''}"
            )
    missing = coverage.get("missing_capabilities") or []
    if missing:
        print("\nNew policy-controlled capabilities not covered by this profile:")
        for item in missing:
            print(
                f"  {item['capability_id']} (Caretaker {item['introduced_in']}): "
                f"{item['title']}"
            )
            print(f"    {item['review_note']}")
    print(f"\nSettings: {len(summary['settings'])}   Constraints: {len(summary['constraints'])}")
    for item in summary["settings"]:
        target = f" target={item['target']}" if item.get("target") else ""
        print(f"  set {item['path']}{target} = {json.dumps(item['value'], default=str)}")
    for item in summary["constraints"]:
        target = f" target={item['target']}" if item.get("target") else ""
        print(
            f"  require {item['path']}{target} {item['operator']} "
            f"{json.dumps(item['value'], default=str)}"
        )


def _coverage_text(path: Path) -> int:
    layer = load_profile(path)
    report = profile_coverage(layer)
    print(
        f"Policy surface {report.profile_surface_version}/{report.current_surface_version}: "
        f"{'COMPLETE' if report.complete else 'REVIEW REQUIRED'}"
    )
    if report.future_surface:
        print("Profile was created by a newer Caretaker policy-surface definition.")
    for item in report.missing_capabilities:
        print(f"\n{item.capability_id} - {item.title}")
        print(f"  Introduced: {item.introduced_in}")
        print(f"  Meaning:    {item.description}")
        print(f"  Review:     {item.review_note}")
    return 0 if report.complete else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="caretaker-profile",
        description="Inspect, compare, pin, and edit Caretaker policy-authority profiles.",
    )
    sub = parser.add_subparsers(dest="command")

    show = sub.add_parser("show", help="Show one profile and its policy-surface coverage")
    show.add_argument("profile", type=Path)
    show.add_argument("--json", action="store_true")

    compare = sub.add_parser("compare", help="Compare two authority policies semantically")
    compare.add_argument("left", type=Path)
    compare.add_argument("right", type=Path)
    compare.add_argument("--json", action="store_true")

    coverage = sub.add_parser(
        "coverage",
        help="Report policy-controlled capabilities introduced after a profile was authored",
    )
    coverage.add_argument("profile", type=Path)
    coverage.add_argument("--json", action="store_true")
    coverage.add_argument(
        "--strict",
        action="store_true",
        help="return non-zero when the profile does not cover the current policy surface",
    )

    pin = sub.add_parser(
        "pin",
        help="Create a deployment authority layer pinned to an exact profile fingerprint",
    )
    pin.add_argument("profile", type=Path)
    pin.add_argument("--output", type=Path, required=True)
    pin.add_argument("--authority-id", default="local-profile-selection")
    pin.add_argument("--application", type=Path)
    pin.add_argument("--generation", type=int, default=1)
    pin.add_argument("--force", action="store_true")

    catalog = sub.add_parser("catalog", help="Show the current Caretaker policy-surface catalog")
    catalog.add_argument("--json", action="store_true")

    edit = sub.add_parser("edit", help="Open the Textual Profile Editor")
    edit.add_argument("profile", type=Path, nargs="?")
    edit.add_argument("--output", type=Path)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {None, "edit"}:
        from .profile_editor import run_editor

        profile = getattr(args, "profile", None)
        output = getattr(args, "output", None)
        run_editor(profile_path=profile, output_path=output)
        return 0

    if args.command == "show":
        layer = load_policy_authority_layer(args.profile, require_canonical=True)
        if args.json:
            _print_json(profile_summary(layer))
        else:
            _show_text(args.profile)
        return 0

    if args.command == "compare":
        left = load_policy_authority_layer(args.left, require_canonical=True)
        right = load_policy_authority_layer(args.right, require_canonical=True)
        result = compare_profiles(left, right)
        if args.json:
            _print_json(result.as_dict())
        else:
            print(format_comparison_text(result))
        return 0

    if args.command == "coverage":
        layer = load_profile(args.profile)
        report = profile_coverage(layer)
        if args.json:
            _print_json(report.as_dict())
        else:
            _coverage_text(args.profile)
        return 1 if args.strict and not report.complete else 0

    if args.command == "pin":
        profile = load_profile(args.profile)
        application = (
            load_policy_authority_layer(args.application, require_canonical=True)
            if args.application
            else None
        )
        if args.output.exists() and not args.force:
            parser.error(f"Refusing to overwrite {args.output}; use --force")
        layer = create_deployment_pin(
            profile,
            authority_id=args.authority_id,
            application=application,
            generation=args.generation,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_policy_authority_layer(args.output, layer)
        print(f"Wrote deployment selection pin: {args.output}")
        print(f"Pinned framework fingerprint: {profile.fingerprint}")
        return 0

    if args.command == "catalog":
        catalog_value = capability_catalog()
        if args.json:
            _print_json(catalog_value)
        else:
            for item in catalog_value:
                print(
                    f"{item['capability_id']}  surface={item['surface_version']}  "
                    f"introduced={item['introduced_in']}"
                )
                print(f"  {item['title']}: {item['description']}")
                print(f"  Review: {item['review_note']}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
