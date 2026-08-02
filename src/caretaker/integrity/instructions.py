from __future__ import annotations

import shlex
from pathlib import Path
from typing import Sequence

from .manifest import load_manifest, load_root
from .models import normalize_fingerprint


def render_gpg_verification_commands(
    *,
    root_path: str | Path,
    root_signature_paths: Sequence[str | Path],
    trusted_primary_fingerprints: Sequence[str],
    manifest_path: str | Path,
    signature_paths: Sequence[str | Path],
    public_key_paths: Sequence[str | Path],
    artifact_root: str | Path = ".",
    root_threshold: int = 2,
) -> str:
    """Render an inspectable shell procedure using GnuPG and sha256sum.

    The generated script verifies the root threshold against independently
    published fingerprints, verifies the complete publication signature set for
    the manifest, deduplicates primary signer identities, and then verifies every
    signed file digest. Runtime randomized sampling is intentionally not used by
    this independent full-verification procedure.
    """

    root = load_root(root_path)
    manifest = load_manifest(manifest_path)
    role_name = manifest.manifest_type.value
    role = root.role(role_name)
    trusted = tuple(normalize_fingerprint(item) for item in trusted_primary_fingerprints)
    if root_threshold < 1 or root_threshold > len(trusted):
        raise ValueError("Invalid external root threshold")
    if not root_signature_paths:
        raise ValueError("At least one root signature is required")

    quote = shlex.quote
    key_paths = [Path(item) for item in public_key_paths]
    root_signatures = [Path(item) for item in root_signature_paths]
    manifest_signatures = [Path(item) for item in signature_paths]

    lines = [
        "#!/bin/sh",
        "# Independent Caretaker OpenPGP and SHA-256 verification.",
        "set -eu",
        'GNUPGHOME="$(mktemp -d)"',
        'chmod 700 "$GNUPGHOME"',
        "cleanup() { rm -rf -- \"$GNUPGHOME\"; }",
        "trap cleanup EXIT HUP INT TERM",
        "",
        "# Import public certificates acquired independently of the source archive.",
        "gpg --homedir \"$GNUPGHOME\" --batch --no-auto-key-retrieve --import \\",
    ]
    for index, path in enumerate(key_paths):
        suffix = " \\" if index < len(key_paths) - 1 else ""
        lines.append(f"  {quote(str(path))}{suffix}")

    lines.extend(
        [
            "",
            "# Display full fingerprints for manual comparison with independent publications.",
            'gpg --homedir "$GNUPGHOME" --with-colons --fingerprint --list-keys',
            "",
            "verify_threshold() {",
            "  signed_file=$1",
            "  required=$2",
            "  authorized=$3",
            "  shift 3",
            "  count=0",
            "  seen=' '",
            "  for signature_file in \"$@\"; do",
            "    status=$(gpg --homedir \"$GNUPGHOME\" --batch --no-auto-key-retrieve \\",
            "      --no-auto-key-import --status-fd=1 --verify \\",
            "      \"$signature_file\" \"$signed_file\" 2>&1) || {",
            "        printf '%s\\n' \"$status\" >&2",
            "        return 1",
            "      }",
            "    printf '%s\\n' \"$status\"",
            "    primary=$(printf '%s\\n' \"$status\" | awk '",
            "      /^\\[GNUPG:\\] VALIDSIG / { value=$NF } END { print value }')",
            "    [ -n \"$primary\" ] || { echo 'No VALIDSIG primary fingerprint' >&2; return 1; }",
            "    case \" $authorized \" in",
            "      *\" $primary \"*) ;;",
            "      *) echo \"Unauthorized signer: $primary\" >&2; return 1 ;;",
            "    esac",
            "    case \"$seen\" in",
            "      *\" $primary \"*) ;;",
            "      *) seen=\"$seen$primary \"; count=$((count + 1)) ;;",
            "    esac",
            "  done",
            "  [ \"$count\" -ge \"$required\" ] || {",
            "    echo \"Threshold not met: $count of $required\" >&2",
            "    return 1",
            "  }",
            "}",
            "",
            "# Verify the signed root against fingerprints obtained independently.",
            "verify_threshold \\",
            f"  {quote(str(Path(root_path)))} \\",
            f"  {root_threshold} \\",
            f"  {quote(' '.join(trusted))} \\",
        ]
    )
    for index, signature in enumerate(root_signatures):
        suffix = " \\" if index < len(root_signatures) - 1 else ""
        lines.append(f"  {quote(str(signature))}{suffix}")

    lines.extend(
        [
            "",
            f"# Verify all published {role_name} signatures required by the authenticated root.",
            "verify_threshold \\",
            f"  {quote(str(Path(manifest_path)))} \\",
            f"  {role.publication_threshold} \\",
            f"  {quote(' '.join(role.authorized_primary_fingerprints))} \\",
        ]
    )
    for index, signature in enumerate(manifest_signatures):
        suffix = " \\" if index < len(manifest_signatures) - 1 else ""
        lines.append(f"  {quote(str(signature))}{suffix}")

    lines.extend(
        [
            "",
            "# After authenticating the root and manifest, independently check",
            "# project identity, path classifications, signed coverage, sizes, and hashes.",
            f"cd {quote(str(Path(artifact_root)))}",
            f"python3 - {quote(str(Path(root_path).resolve()))} {quote(str(Path(manifest_path).resolve()))} <<'PY'",
            "import fnmatch, hashlib, json, pathlib, sys",
            "root_path = pathlib.Path(sys.argv[1])",
            "manifest_path = pathlib.Path(sys.argv[2])",
            "root = json.loads(root_path.read_text(encoding='utf-8'))",
            "manifest = json.loads(manifest_path.read_text(encoding='utf-8'))",
            "if manifest['project'] != root['project']:",
            "    raise SystemExit('project identity mismatch')",
            "if manifest['root_version'] != root['root_version']:",
            "    raise SystemExit('root version mismatch')",
            "base = pathlib.Path.cwd().resolve()",
            "listed = set()",
            "def classify(path):",
            "    result = 'ordinary'",
            "    if any(fnmatch.fnmatch(path, pattern) for pattern in root.get('protected_paths', [])):",
            "        result = 'protected'",
            "    if any(fnmatch.fnmatch(path, pattern) for pattern in root.get('sealed_paths', [])):",
            "        result = 'sealed'",
            "    return result",
            "for item in manifest['artifacts']:",
            "    name = item['path']",
            "    relative = pathlib.PurePosixPath(name)",
            "    if (not name or relative.is_absolute() or '..' in relative.parts",
            "            or '\\\\' in name or any(ord(ch) < 32 for ch in name)):",
            "        raise SystemExit(f'unsafe artifact path: {name!r}')",
            "    resolved = (base / pathlib.Path(*relative.parts)).resolve()",
            "    try:",
            "        resolved.relative_to(base)",
            "    except ValueError:",
            "        raise SystemExit(f'artifact escapes verification root: {name}')",
            "    expected_class = classify(name)",
            "    if item.get('integrity_class', 'ordinary') != expected_class:",
            "        raise SystemExit(f'integrity class mismatch: {name}')",
            "    if manifest['manifest_type'] == 'release' and expected_class != 'ordinary':",
            "        raise SystemExit(f'release manifest contains protected path: {name}')",
            "    if manifest['manifest_type'] == 'protected' and expected_class == 'ordinary':",
            "        raise SystemExit(f'protected manifest contains ordinary path: {name}')",
            "    if not resolved.is_file() or resolved.stat().st_size != item['size_bytes']:",
            "        raise SystemExit(f'missing or size-mismatched artifact: {name}')",
            "    observed = hashlib.sha256(resolved.read_bytes()).hexdigest()",
            "    if observed != item['sha256']:",
            "        raise SystemExit(f'SHA-256 mismatch: {name}')",
            "    listed.add(name)",
            "coverage = set()",
            "for pattern in manifest.get('coverage_patterns', []):",
            "    for candidate in base.glob(pattern):",
            "        if not candidate.is_file():",
            "            continue",
            "        resolved = candidate.resolve()",
            "        try:",
            "            name = resolved.relative_to(base).as_posix()",
            "        except ValueError:",
            "            raise SystemExit(f'covered path escapes verification root: {candidate}')",
            "        if any(fnmatch.fnmatch(name, p) for p in manifest.get('excluded_patterns', [])):",
            "            continue",
            "        coverage.add(name)",
            "missing = sorted(coverage - listed)",
            "if missing:",
            "    raise SystemExit('manifest omits covered artifacts: ' + ', '.join(missing))",
            "if manifest['manifest_type'] == 'protected':",
            "    required = set()",
            "    for pattern in root.get('protected_paths', []) + root.get('sealed_paths', []):",
            "        for candidate in base.glob(pattern):",
            "            if candidate.is_file():",
            "                required.add(candidate.resolve().relative_to(base).as_posix())",
            "    missing = sorted(required - listed)",
            "    if missing:",
            "        raise SystemExit('protected manifest omits: ' + ', '.join(missing))",
            "print(f\"Verified {len(listed)} signed artifacts.\")",
            "PY",
            "",
            "# Repeat the digest check with GNU sha256sum for a second independent implementation.",
            f"python3 - {quote(str(Path(manifest_path).resolve()))} <<'PY' | sha256sum --check -",
            "import json, pathlib, sys",
            "manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))",
            "for item in manifest['artifacts']:",
            "    print(f\"{item['sha256']}  {item['path']}\")",
            "PY",
            "",
            "echo 'Caretaker signature thresholds and artifact integrity verified.'",
        ]
    )
    return "\n".join(lines) + "\n"
