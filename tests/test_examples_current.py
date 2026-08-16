from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from caretaker.integrity import load_root
from caretaker.logging.policy import load_operator_policy


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.repository
def test_example_policy_modules_construct_against_current_policy_surface(tmp_path: Path) -> None:
    modules = (
        "examples.caretaker_full_demo",
        "examples.guard_demo",
        "examples.self_heal_demo",
        "examples.interactive_caretaker_lab",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
    result = subprocess.run(
        [sys.executable, "-c", "; ".join(f"import {module}" for module in modules)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.repository
def test_structured_examples_load_against_current_schemas() -> None:
    load_operator_policy(ROOT / "examples" / "logging_policy.toml")
    root = load_root(ROOT / "examples" / "integrity" / "root.template.json")
    assert root.schema_version == 2
    assert set(root.key_slots) == {"A", "B", "C"}


@pytest.mark.repository
@pytest.mark.parametrize(
    "module",
    (
        "examples.logging_demo",
        "examples.guard_demo",
        "examples.module_routing_demo",
        "examples.self_heal_demo",
        "examples.caretaker_full_demo",
        "examples.demo_target",
    ),
)
def test_noninteractive_python_example_runs(module: str, tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(ROOT)))
    result = subprocess.run(
        [sys.executable, "-m", module],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
