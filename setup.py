from __future__ import annotations

import os
import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


ROOT = Path(__file__).resolve().parent
SLOTS = ("a", "b", "c")
PROFILES = (
    "caretaker-observe-only-v1.json",
    "caretaker-balanced-v1.json",
    "caretaker-high-assurance-v1.json",
)


class build_py(_build_py):
    """Place reviewed external publication data into the built package only."""

    def run(self) -> None:
        super().run()
        package = Path(self.build_lib) / "caretaker"
        profiles = package / "profiles"
        publication = package / "_publication"
        shutil.copytree(ROOT / "profiles", profiles, dirs_exist_ok=True)
        if os.environ.get("CARETAKER_RELEASE_SIGNING") == "disabled":
            # Development candidates deliberately have no installed
            # publication bundle. They remain unsigned development artifacts
            # and must not pass installed release-integrity verification.
            return
        required = [
            ROOT / "root.json",
            *(ROOT / f"root.json.key-{slot}.asc" for slot in SLOTS),
            *(ROOT / "release-keys" / f"caretaker-key-{slot}.asc" for slot in SLOTS),
        ]
        for manifest in ("wheel-release-manifest.json", "wheel-protected-manifest.json"):
            required.append(ROOT / manifest)
            required.extend(ROOT / f"{manifest}.key-{slot}.asc" for slot in SLOTS)
        for profile in PROFILES:
            required.extend(ROOT / "profiles" / f"{profile}.key-{slot}.asc" for slot in SLOTS)
        missing = [str(path.relative_to(ROOT)) for path in required if not path.is_file()]
        if missing:
            raise RuntimeError(
                "signed wheel publication is incomplete; missing: " + ", ".join(missing)
            )
        publication.mkdir(parents=True, exist_ok=True)
        (publication / "release-keys").mkdir(parents=True, exist_ok=True)
        for path in required:
            if path.parent == ROOT / "profiles":
                continue
            destination = (
                publication / "release-keys" / path.name
                if path.parent == ROOT / "release-keys"
                else publication / path.name
            )
            shutil.copy2(path, destination)


setup(cmdclass={"build_py": build_py})
