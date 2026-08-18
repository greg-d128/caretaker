#!/usr/bin/env python3
"""Check canonical framework-policy bytes and their configured signing role."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from caretaker.authority import AuthorityKind, load_policy_authority_layer


def fail(message: str) -> None:
    print(f"framework-policy-check: {message}", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    if len(sys.argv) != 4:
        fail("usage: check-framework-policy.py POLICY ROOT ROLE")
    policy_path, root_path, role_name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    try:
        layer = load_policy_authority_layer(policy_path, require_canonical=True)
        root = json.loads(root_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError) as exc:
        fail(str(exc))
    if layer.kind is not AuthorityKind.FRAMEWORK:
        fail(f"{policy_path} declares kind {layer.kind.value!r}, not 'framework'")
    if role_name not in root.get("roles", {}):
        fail(f"root does not authorize role {role_name!r}")
    print(
        f"Framework policy valid: {policy_path} "
        f"(authority={layer.authority_id}, generation={layer.generation}, role={role_name})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
