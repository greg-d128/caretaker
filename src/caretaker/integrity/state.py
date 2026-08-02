from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path

from .models import ManifestType, TrustedVersionState


class IntegrityRollbackError(RuntimeError):
    pass


class IntegrityStateStore:
    """Persist the highest trusted root and manifest versions atomically."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self, project: str) -> TrustedVersionState:
        if not self.path.exists():
            return TrustedVersionState(project=project)
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if value.get("project") != project:
            raise ValueError(
                f"Trusted-state project {value.get('project')!r} does not match {project!r}"
            )
        return TrustedVersionState(
            project=project,
            highest_root_version=int(value.get("highest_root_version", 0)),
            highest_release_manifest_version=int(value.get("highest_release_manifest_version", 0)),
            highest_protected_manifest_version=int(value.get("highest_protected_manifest_version", 0)),
            accepted_manifest_hashes=dict(value.get("accepted_manifest_hashes", {})),
            updated_at=value.get("updated_at"),
        )

    def assert_not_rollback(
        self,
        *,
        state: TrustedVersionState,
        root_version: int,
        manifest_type: ManifestType,
        manifest_version: int,
    ) -> None:
        if root_version < state.highest_root_version:
            raise IntegrityRollbackError(
                f"Root version {root_version} is older than trusted version {state.highest_root_version}"
            )
        highest = (
            state.highest_protected_manifest_version
            if manifest_type is ManifestType.PROTECTED
            else state.highest_release_manifest_version
        )
        if manifest_type is not ManifestType.ROOT and manifest_version < highest:
            raise IntegrityRollbackError(
                f"{manifest_type.value} manifest version {manifest_version} is older than trusted version {highest}"
            )

    def accept(
        self,
        *,
        state: TrustedVersionState,
        root_version: int,
        manifest_type: ManifestType,
        manifest_version: int,
        manifest_hash: str,
    ) -> TrustedVersionState:
        release_version = state.highest_release_manifest_version
        protected_version = state.highest_protected_manifest_version
        if manifest_type is ManifestType.RELEASE:
            release_version = max(release_version, manifest_version)
        elif manifest_type is ManifestType.PROTECTED:
            protected_version = max(protected_version, manifest_version)

        hashes = dict(state.accepted_manifest_hashes)
        hashes[manifest_type.value] = manifest_hash
        updated = TrustedVersionState(
            project=state.project,
            highest_root_version=max(state.highest_root_version, root_version),
            highest_release_manifest_version=release_version,
            highest_protected_manifest_version=protected_version,
            accepted_manifest_hashes=hashes,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        self._write(updated)
        return updated

    def _write(self, state: TrustedVersionState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(asdict(state), sort_keys=True, indent=2) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as destination:
                destination.write(payload)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
