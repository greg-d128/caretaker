from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from caretaker.logging.ipc import control_request


ROOT = Path(__file__).resolve().parents[1]


def _start_run(
    tmp_path: Path,
    module_name: str,
    *,
    policy_path: Path | None = None,
) -> tuple[subprocess.Popen[str], Path]:
    data_directory = tmp_path / "caretaker-data"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(tmp_path), str(ROOT)))
    policy_arguments = (
        ["--policy", str(policy_path)]
        if policy_path is not None
        else ["--data-directory", str(data_directory)]
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "caretaker.run",
            *policy_arguments,
            module_name,
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return process, data_directory


def _wait_for_status(process: subprocess.Popen[str], socket_path: Path) -> dict[str, object]:
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else ""
            raise AssertionError(f"caretaker-run exited before readiness: {stderr}")
        if socket_path.exists():
            try:
                response = control_request(socket_path, {"command": "status"}, timeout=0.5)
            except OSError:
                response = {}
            if response.get("ok") and len(response.get("workers") or ()) >= 4:
                return response
        time.sleep(0.05)
    raise AssertionError("timed out waiting for the real caretaker-run supervisor")


@pytest.mark.repository
def test_real_run_entrypoint_reaches_supervisor_readiness_and_cleans_endpoints(tmp_path: Path) -> None:
    module = tmp_path / "entrypoint_probe.py"
    marker = tmp_path / "policy-marker.txt"
    module.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "import time\n"
        "Path(os.environ['CARETAKER_ENTRYPOINT_MARKER']).write_text(\n"
        "    os.environ['CARETAKER_APPLICATION_ID'], encoding='utf-8'\n"
        ")\n"
        "time.sleep(0.75)\n",
        encoding="utf-8",
    )
    policy = tmp_path / "logging-policy.toml"
    policy.write_text(
        "[logging]\n"
        "application_id = 'entrypoint-configured'\n"
        f"directory = '{tmp_path / 'configured-data'}'\n",
        encoding="utf-8",
    )
    environment_marker = dict(os.environ)
    environment_marker["CARETAKER_ENTRYPOINT_MARKER"] = str(marker)
    environment_marker["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(tmp_path), str(ROOT)))
    process = subprocess.Popen(
        [sys.executable, "-m", "caretaker.run", "--policy", str(policy), "entrypoint_probe"],
        cwd=ROOT,
        env=environment_marker,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    data_directory = tmp_path / "configured-data"
    control_socket = data_directory / "run" / "control.sock"
    try:
        status = _wait_for_status(process, control_socket)
        worker_kinds = {
            str(item["worker_kind"]).rsplit(".", 1)[-1]
            for item in status["workers"]
        }
        assert {"SUPERVISOR", "WRITER", "EVENT_SERVER", "CONTROL_SERVER"} <= worker_kinds
        assert status["application_running"] is True
        assert process.wait(timeout=10) == 0
        assert status["application_pid"] != process.pid
        assert marker.read_text(encoding="utf-8") == "entrypoint-configured"
    finally:
        if process.poll() is None:
            try:
                current = control_request(control_socket, {"command": "status"}, timeout=0.5)
                child_pid = current.get("application_pid")
                if isinstance(child_pid, int):
                    os.kill(child_pid, signal.SIGTERM)
            except (OSError, ValueError):
                process.terminate()
            process.wait(timeout=10)
    assert not (data_directory / "run" / "events.sock").exists()
    assert not control_socket.exists()
    assert not (data_directory / "run" / "runtime.sock").exists()


@pytest.mark.repository
def test_real_run_entrypoint_cleans_endpoints_after_application_startup_failure(tmp_path: Path) -> None:
    process, data_directory = _start_run(tmp_path, "module_that_does_not_exist")

    _, stderr = process.communicate(timeout=10)
    assert process.returncode == 1
    assert "ImportError: No module named module_that_does_not_exist" in stderr
    assert not (data_directory / "run" / "events.sock").exists()
    assert not (data_directory / "run" / "control.sock").exists()
    assert not (data_directory / "run" / "runtime.sock").exists()
