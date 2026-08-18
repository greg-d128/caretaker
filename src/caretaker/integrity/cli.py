from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .gpg import GPGUnavailableError, GPGVerifier
from .instructions import render_gpg_verification_commands
from .manifest import (
    TRANSIENT_ARTIFACT_PATTERNS,
    build_manifest,
    load_manifest,
    load_root,
    manifest_sha256,
    sha256sum_lines,
    write_manifest,
)
from .models import IntegrityClass, ManifestType, SignatureVerificationMode
from .state import IntegrityStateStore
from .verifier import IntegrityVerifier


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="caretaker-integrity",
        description="Public-key-only integrity verification for Caretaker code and manifests.",
    )
    parser.add_argument("--gpg", default="gpg", help="GnuPG executable used for verification")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate-manifest", help="Create an unsigned canonical manifest")
    generate.add_argument("--root-dir", required=True)
    generate.add_argument("--output", required=True)
    generate.add_argument("--project", default="caretaker")
    generate.add_argument("--package-version", required=True)
    generate.add_argument("--manifest-type", choices=[item.value for item in ManifestType], required=True)
    generate.add_argument("--manifest-version", type=int, required=True)
    generate.add_argument("--root-version", type=int, required=True)
    generate.add_argument("--include", action="append", default=[])
    generate.add_argument("--exclude", action="append", default=[])
    generate.add_argument("--previous-manifest-sha256")
    generate.add_argument("--minimum-caretaker-version")
    generate.add_argument("--root-policy", help="Assign protected/sealed classes from signed root metadata")

    verify = subparsers.add_parser("verify", help="Verify signatures, threshold, rollback state, and artifacts")
    _add_verification_arguments(verify)
    verify.add_argument("--state-file")
    verify.add_argument("--accept-state", action="store_true")
    verify.add_argument("--root-signature", action="append")
    verify.add_argument("--trusted-fingerprint", action="append")
    verify.add_argument("--root-threshold", type=int, default=2)
    verify.add_argument("--json", action="store_true", dest="json_output")
    verify.add_argument(
        "--verification-mode",
        choices=[item.value for item in SignatureVerificationMode],
        default=SignatureVerificationMode.FULL_PUBLICATION.value,
        help="full publication verification is the CLI default; runtime bootstrap may use randomized sampling",
    )

    root = subparsers.add_parser("verify-initial-root", help="Verify a root against external trusted fingerprints")
    root.add_argument("--root", required=True)
    root.add_argument("--signature", action="append", required=True)
    root.add_argument("--public-key", action="append", required=True)
    root.add_argument("--trusted-fingerprint", action="append", required=True)
    root.add_argument("--threshold", type=int, default=2)
    root.add_argument("--state-file")
    root.add_argument("--accept-state", action="store_true")

    transition = subparsers.add_parser("verify-root-transition", help="Verify sequential old/new 2-threshold root continuity")
    transition.add_argument("--old-root", required=True)
    transition.add_argument("--new-root", required=True)
    transition.add_argument("--signature", action="append", required=True)
    transition.add_argument("--public-key", action="append", required=True)
    transition.add_argument("--state-file")
    transition.add_argument("--accept-state", action="store_true")

    instructions = subparsers.add_parser("instructions", help="Print independent GPG verification commands")
    _add_verification_arguments(instructions)
    instructions.add_argument("--root-signature", action="append", required=True)
    instructions.add_argument("--trusted-fingerprint", action="append", required=True)
    instructions.add_argument("--root-threshold", type=int, default=2)

    export = subparsers.add_parser("export-sha256", help="Export GNU sha256sum-compatible artifact lines")
    export.add_argument("--manifest", required=True)
    export.add_argument("--output")

    inspect = subparsers.add_parser("inspect", help="Summarize root or manifest metadata")
    inspect.add_argument("path")

    return parser


def _add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--signature", action="append", required=True)
    parser.add_argument("--public-key", action="append", required=True)
    parser.add_argument("--artifact-root", required=True)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-manifest":
            return _generate_manifest(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "verify-initial-root":
            return _verify_initial_root(args)
        if args.command == "verify-root-transition":
            return _verify_root_transition(args)
        if args.command == "instructions":
            print(
                render_gpg_verification_commands(
                    root_path=args.root,
                    root_signature_paths=args.root_signature,
                    trusted_primary_fingerprints=args.trusted_fingerprint,
                    root_threshold=args.root_threshold,
                    manifest_path=args.manifest,
                    signature_paths=args.signature,
                    public_key_paths=args.public_key,
                    artifact_root=args.artifact_root,
                ),
                end="",
            )
            return 0
        if args.command == "export-sha256":
            text = sha256sum_lines(load_manifest(args.manifest))
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8")
            else:
                print(text, end="")
            return 0
        if args.command == "inspect":
            return _inspect(args)
    except (ValueError, OSError, GPGUnavailableError) as exc:
        parser.exit(2, f"caretaker-integrity: {exc}\n")
    parser.error("unhandled command")
    return 2


def _generate_manifest(args: argparse.Namespace) -> int:
    path_classes = None
    include_patterns = list(args.include)
    exclude_patterns = [*TRANSIENT_ARTIFACT_PATTERNS, *args.exclude]
    if args.root_policy:
        root_policy = load_root(args.root_policy)
        if root_policy.root_version != args.root_version:
            raise ValueError("--root-version does not match --root-policy")
        path_classes = {pattern: IntegrityClass.PROTECTED for pattern in root_policy.protected_paths}
        path_classes.update({pattern: IntegrityClass.SEALED for pattern in root_policy.sealed_paths})
        manifest_type = ManifestType(args.manifest_type)
        if manifest_type is ManifestType.RELEASE:
            exclude_patterns.extend(root_policy.protected_paths)
            exclude_patterns.extend(root_policy.sealed_paths)
        elif manifest_type is ManifestType.PROTECTED and not include_patterns:
            include_patterns.extend(
                f"{pattern}/*"
                if pattern == "**" or pattern.endswith("/**")
                else pattern
                for pattern in root_policy.protected_paths
            )
            include_patterns.extend(
                f"{pattern}/*"
                if pattern == "**" or pattern.endswith("/**")
                else pattern
                for pattern in root_policy.sealed_paths
            )
        manifest = build_manifest(
        root_dir=args.root_dir,
        project=args.project,
        package_version=args.package_version,
        manifest_type=ManifestType(args.manifest_type),
        manifest_version=args.manifest_version,
        root_version=args.root_version,
        include=tuple(include_patterns or ["**/*.py"]),
        exclude=tuple(dict.fromkeys(exclude_patterns)),
        path_classes=path_classes,
        previous_manifest_sha256=args.previous_manifest_sha256,
        minimum_caretaker_version=args.minimum_caretaker_version,
    )
    write_manifest(args.output, manifest)
    print(f"Wrote unsigned canonical manifest: {args.output}")
    print(f"Manifest SHA-256: {manifest_sha256(args.output)}")
    print("Sign this file only with the separate offline signing procedure.")
    return 0


def _verifier(args: argparse.Namespace) -> IntegrityVerifier:
    state = IntegrityStateStore(args.state_file) if getattr(args, "state_file", None) else None
    return IntegrityVerifier(gpg=GPGVerifier(args.gpg), state_store=state)


def _verify(args: argparse.Namespace) -> int:
    if args.accept_state and not args.state_file:
        raise ValueError("--accept-state requires --state-file")
    verifier = _verifier(args)
    root_trusted = False
    if args.root_signature or args.trusted_fingerprint:
        if not args.root_signature or not args.trusted_fingerprint:
            raise ValueError("--root-signature and --trusted-fingerprint must be supplied together")
        root_result = verifier.verify_initial_root(
            root_path=args.root,
            signature_paths=args.root_signature,
            public_key_paths=args.public_key,
            trusted_primary_fingerprints=args.trusted_fingerprint,
            threshold=args.root_threshold,
        )
        root_trusted = root_result.satisfied
        if root_trusted and args.accept_state:
            verifier.accept_root(args.root)
    result = verifier.verify_manifest(
        root_path=args.root,
        manifest_path=args.manifest,
        signature_paths=args.signature,
        public_key_paths=args.public_key,
        artifact_root=args.artifact_root,
        accept_state=args.accept_state,
        root_trusted=root_trusted,
        verification_mode=SignatureVerificationMode(args.verification_mode),
    )
    if args.json_output:
        print(json.dumps(_verification_json(result), indent=2, sort_keys=True))
    else:
        _print_verification(result)
    return 0 if result.trusted else 1


def _verify_initial_root(args: argparse.Namespace) -> int:
    result = IntegrityVerifier(gpg=GPGVerifier(args.gpg)).verify_initial_root(
        root_path=args.root,
        signature_paths=args.signature,
        public_key_paths=args.public_key,
        trusted_primary_fingerprints=args.trusted_fingerprint,
        threshold=args.threshold,
    )
    _print_threshold(result)
    if result.satisfied and args.accept_state:
        if not args.state_file:
            raise ValueError("--accept-state requires --state-file")
        root = load_root(args.root)
        state_store = IntegrityStateStore(args.state_file)
        state = state_store.load(root.project)
        state_store.accept(
            state=state,
            root_version=root.root_version,
            manifest_type=ManifestType.ROOT,
            manifest_version=root.root_version,
            manifest_hash=manifest_sha256(args.root),
        )
    return 0 if result.satisfied else 1


def _verify_root_transition(args: argparse.Namespace) -> int:
    old_result, new_result = IntegrityVerifier(gpg=GPGVerifier(args.gpg)).verify_root_transition(
        old_root_path=args.old_root,
        new_root_path=args.new_root,
        new_root_signature_paths=args.signature,
        public_key_paths=args.public_key,
    )
    print("Old-root authorization")
    _print_threshold(old_result)
    print("\nNew-root authorization")
    _print_threshold(new_result)
    satisfied = old_result.satisfied and new_result.satisfied
    if satisfied and args.accept_state:
        if not args.state_file:
            raise ValueError("--accept-state requires --state-file")
        new_root = load_root(args.new_root)
        state_store = IntegrityStateStore(args.state_file)
        state = state_store.load(new_root.project)
        state_store.accept(
            state=state,
            root_version=new_root.root_version,
            manifest_type=ManifestType.ROOT,
            manifest_version=new_root.root_version,
            manifest_hash=manifest_sha256(args.new_root),
        )
    return 0 if satisfied else 1


def _inspect(args: argparse.Namespace) -> int:
    path = Path(args.path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if "roles" in value:
        root = load_root(path)
        print(f"Project: {root.project}")
        print(f"Root version: {root.root_version}")
        for name, role in sorted(root.roles.items()):
            print(
                f"Role {name}: authorization {role.threshold}, publication "
                f"{role.publication_threshold}, runtime sample {role.runtime_sample_size} "
                f"of {len(role.authorized_primary_fingerprints)}"
            )
            for fingerprint in role.authorized_primary_fingerprints:
                print(f"  {fingerprint}")
        if root.key_slots:
            print("Key slots:")
            for slot, fingerprint in sorted(root.key_slots.items()):
                print(f"  {slot}: {fingerprint}")
        rotation = root.rotation_status()
        if rotation is not None:
            print(f"Next rotation slot: {rotation.next_slot}")
            print(f"Next rotation due:  {rotation.next_due_at.isoformat()}")
            print(f"Full cycle days:    {rotation.full_cycle_days}")
    else:
        manifest = load_manifest(path)
        print(f"Project: {manifest.project}")
        print(f"Type: {manifest.manifest_type.value}")
        print(f"Version: {manifest.manifest_version}")
        print(f"Root version: {manifest.root_version}")
        print(f"Artifacts: {len(manifest.artifacts)}")
        print(f"SHA-256: {manifest_sha256(path)}")
    return 0


def _print_verification(result: object) -> None:
    print("Caretaker integrity verification")
    print("================================")
    print(f"Project:             {result.project}")
    print(f"Manifest type:       {result.manifest_type.value}")
    print(f"Root version:        {result.root_version}")
    print(f"Manifest version:    {result.manifest_version}")
    print(f"Manifest SHA-256:    {result.manifest_sha256}")
    print(f"Root anchored:       {'yes' if result.root_anchored else 'no'}")
    print(f"Verification mode:   {result.signature_verification.verification_mode.value}")
    _print_threshold(result.signature_verification)
    valid_files = sum(1 for item in result.artifact_results if item.valid)
    invalid_files = len(result.artifact_results) - valid_files
    print(f"Artifacts valid:     {valid_files}")
    print(f"Artifacts invalid:   {invalid_files}")
    for item in result.artifact_results:
        if not item.valid:
            print(f"  INVALID {item.path}: {item.error}")
    for warning in result.warnings:
        print(f"  WARNING: {warning}")
    for error in result.errors:
        print(f"  ERROR: {error}")
    print(f"Result:              {'TRUSTED' if result.trusted else 'UNTRUSTED'}")


def _print_threshold(result: object) -> None:
    print(f"Signature role:      {result.role_name}")
    print(f"Required threshold:  {result.required_threshold}")
    print(f"Valid distinct keys: {len(result.valid_primary_fingerprints)}")
    print(f"Verification mode:   {result.verification_mode.value}")
    if result.selected_primary_fingerprints:
        print("Selected identities:")
        for fingerprint in result.selected_primary_fingerprints:
            print(f"  {fingerprint}")
    for fingerprint in result.valid_primary_fingerprints:
        print(f"  {fingerprint}")
    for error in result.errors:
        print(f"  ERROR: {error}")


def _verification_json(result: object) -> dict[str, object]:
    return {
        "project": result.project,
        "root_version": result.root_version,
        "manifest_version": result.manifest_version,
        "manifest_type": result.manifest_type.value,
        "manifest_sha256": result.manifest_sha256,
        "root_anchored": result.root_anchored,
        "trusted": result.trusted,
        "valid_primary_fingerprints": list(result.signature_verification.valid_primary_fingerprints),
        "required_threshold": result.signature_verification.required_threshold,
        "verification_mode": result.signature_verification.verification_mode.value,
        "selected_primary_fingerprints": list(
            result.signature_verification.selected_primary_fingerprints
        ),
        "artifacts": [
            {
                "path": item.path,
                "valid": item.valid,
                "expected_sha256": item.expected_sha256,
                "observed_sha256": item.observed_sha256,
                "error": item.error,
            }
            for item in result.artifact_results
        ],
        "warnings": list(result.warnings),
        "errors": list(result.errors) + list(result.signature_verification.errors),
    }


if __name__ == "__main__":
    raise SystemExit(main())
