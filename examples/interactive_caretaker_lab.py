"""Interactive Textual Caretaker behavior laboratory.

See ``examples/interactive_caretaker_lab.md`` for the guided walkthrough.

Run the lab under ``caretaker-run`` and attach the standard ``caretaker-console``
from a second terminal. The application UI drives inputs and controlled behavior
changes; Guard/Repair inspection and operator approval live in Caretaker's own
console.

Most contained ``malicious`` variants operate only on synthetic lab-owned data,
loopback endpoints, and a fixed harmless subprocess.  The dedicated behavior-change
probe is the deliberate exception: its highest-change mode enumerates home-directory
metadata and attempts an HTTPS request to www.google.com without transmitting local
file contents. Do not enter real secrets because argument/result evidence is
intentionally enabled for this example.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import time
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlsplit
import urllib.request
from uuid import uuid4

from caretaker import (
    CandidateGuardPolicy,
    CandidateProposal,
    ExceptionTrigger,
    GuardBinding,
    GuardEngine,
    GuardPolicy,
    LoggingBinding,
    ObservationPolicy,
    OllamaBehaviorAssessmentProvider,
    OutputValidationTrigger,
    RegisteredCase,
    RepairAuthority,
    RepairEngine,
    RepairLimits,
    RepairMode,
    RepairPolicy,
    ReplaySafety,
    RetryPolicy,
    StatePolicy,
    TimeoutTrigger,
    ValidationPolicy,
    caretaker,
)
from caretaker.guard.models import GuardDeviationAction
from caretaker.guard.policy import LLMReviewPolicy
from caretaker.logging import (
    OperatorLoggingPolicy,
    configure as configure_logging,
    get_runtime as get_logging_runtime,
)
from caretaker.provider import CandidateBatch, RepairRequest
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Footer, Header, Input, Label, RichLog, Static


LOGGER = logging.getLogger("caretaker.interactive_lab")

DEFAULT_LAB_ROOT = Path(__file__).resolve().parent / ".caretaker-interactive-lab"
LAB_ROOT = Path(
    os.environ.get("CARETAKER_LAB_ROOT", str(DEFAULT_LAB_ROOT))
).expanduser().resolve()
WORKSPACE = LAB_ROOT / "workspace"
LOCAL_LOG_DIRECTORY = LAB_ROOT / "caretaker-data"
SYNTHETIC_SECRET = WORKSPACE / "demo-secret.txt"
COLLECTOR_EVENTS: list[dict[str, str]] = []

SEARCH_FILE_LIMIT = 2_000
BEHAVIOR_HOME_SCAN_LIMIT = 500
BEHAVIOR_HOME_SCAN_DEPTH = 2
HTTP_TIMEOUT_SECONDS = 4.0


# ---------------------------------------------------------------------------
# Local HTTP laboratory
# ---------------------------------------------------------------------------


class _LabHTTPHandler(BaseHTTPRequestHandler):
    server_version = "CaretakerLabHTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:
        LOGGER.info("lab HTTP: " + format, *args)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        kind = getattr(self.server, "lab_kind", "application")
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)

        if kind == "collector":
            if parsed.path != "/collect":
                self._send_json(404, {"error": "collector endpoint not found"})
                return
            record = {
                "target": query.get("target", [""])[0],
                "digest": query.get("digest", [""])[0],
                "note": query.get("note", [""])[0],
            }
            COLLECTOR_EVENTS.append(record)
            self._send_json(200, {"stored": True, "record": record})
            return

        if parsed.path == "/page":
            body = (
                "<html><body><h1>Caretaker lab page</h1>"
                "<p>This response came from the loopback demo server.</p>"
                "</body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api/status":
            value = query.get("value", ["example"])[0]
            self._send_json(
                200,
                {
                    "ok": True,
                    "value": value,
                    "message": "local Caretaker lab API",
                },
            )
            return

        if parsed.path == "/api/echo":
            self._send_json(200, {"query": query})
            return

        self._send_json(
            404,
            {
                "error": "not found",
                "hint": "Try /page, /api/status, or /api/echo",
            },
        )

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LabServers:
    def __init__(self) -> None:
        self.application = ThreadingHTTPServer(("127.0.0.1", 0), _LabHTTPHandler)
        self.collector = ThreadingHTTPServer(("127.0.0.1", 0), _LabHTTPHandler)
        self.application.lab_kind = "application"  # type: ignore[attr-defined]
        self.collector.lab_kind = "collector"  # type: ignore[attr-defined]
        self._threads = (
            threading.Thread(
                target=self.application.serve_forever,
                name="caretaker-lab-http",
                daemon=True,
            ),
            threading.Thread(
                target=self.collector.serve_forever,
                name="caretaker-lab-collector",
                daemon=True,
            ),
        )

    @property
    def application_base(self) -> str:
        host, port = self.application.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def collector_base(self) -> str:
        host, port = self.collector.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def close(self) -> None:
        for server in (self.application, self.collector):
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2.0)


SERVERS: LabServers | None = None


# ---------------------------------------------------------------------------
# Safe synthetic suspicious behavior
# ---------------------------------------------------------------------------


def _workspace_file(name: str) -> Path:
    """Resolve a lab-owned relative path and reject traversal."""
    candidate = (WORKSPACE / name).resolve()
    try:
        candidate.relative_to(WORKSPACE)
    except ValueError as exc:
        raise ValueError(
            f"Lab write paths must stay under {WORKSPACE}; received {name!r}"
        ) from exc
    return candidate


def _malicious_demo_side_effect(target_name: str) -> None:
    """Perform contained activity that should look suspicious to Guard.

    This is deliberately non-destructive.  The function reads only a synthetic
    secret generated by this example, writes only under the lab workspace,
    launches a fixed harmless child process without ``shell=True``, and sends
    only a SHA-256 digest to a second loopback-only HTTP server.
    """
    secret = SYNTHETIC_SECRET.read_text(encoding="utf-8")
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()

    marker = _workspace_file(f".unexpected-{target_name}.txt")
    marker.write_text(
        f"Synthetic suspicious side effect for {target_name}\n"
        f"secret_sha256={digest}\n",
        encoding="utf-8",
    )

    subprocess.run(
        [
            sys.executable,
            "-c",
            "print('Caretaker lab child process: harmless synthetic activity')",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=3.0,
    )

    if SERVERS is not None:
        url = (
            f"{SERVERS.collector_base}/collect?"
            + urlencode(
                {
                    "target": target_name,
                    "digest": digest,
                    "note": "synthetic-loopback-only",
                }
            )
        )
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS) as response:
            response.read()


# ---------------------------------------------------------------------------
# Function variants
# ---------------------------------------------------------------------------


def divide_benign(left, right):
    return float(left) / float(right)


def divide_bad(left, right):
    # Plausible logic defect: returns a string instead of a numeric result.
    float(left)
    float(right)
    return "bad-result"


def divide_malicious(left, right):
    _malicious_demo_side_effect("divide")
    return float(left) / float(right)


def list_directory_benign(path):
    directory = Path(path).expanduser()
    return sorted(item.name for item in directory.iterdir())


def list_directory_bad(path):
    # Plausible path-construction defect.
    directory = Path(path).expanduser() / "misspelled-subdirectory"
    return sorted(item.name for item in directory.iterdir())


def list_directory_malicious(path):
    _malicious_demo_side_effect("list-directory")
    return list_directory_benign(path)


def load_webpage_benign(url):
    with urllib.request.urlopen(str(url), timeout=HTTP_TIMEOUT_SECONDS) as response:
        body = response.read()
        return {
            "status": getattr(response, "status", None),
            "url": response.geturl(),
            "bytes": len(body),
            "preview": body.decode("utf-8", errors="replace")[:240],
        }


def load_webpage_bad(url):
    # Plausible endpoint typo introduced by an application defect.
    return load_webpage_benign(str(url).rstrip("/") + "/typo")


def load_webpage_malicious(url):
    result = load_webpage_benign(url)
    _malicious_demo_side_effect("load-webpage")
    return result


def search_files_benign(directory, word):
    root = Path(directory).expanduser()
    needle = str(word).casefold()
    matches: list[str] = []
    examined = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        examined += 1
        if examined > SEARCH_FILE_LIMIT:
            break
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if needle in line.casefold():
                        matches.append(f"{path}:{line_number}")
                        break
        except OSError:
            continue
    return {
        "examined_files": min(examined, SEARCH_FILE_LIMIT),
        "limit_reached": examined > SEARCH_FILE_LIMIT,
        "matches": matches,
    }


def search_files_bad(directory, word):
    # Plausible implementation bug: searches filenames rather than contents.
    root = Path(directory).expanduser()
    needle = str(word).casefold()
    matches = [
        str(path)
        for path in root.rglob("*")
        if path.is_file() and needle in path.name.casefold()
    ]
    return {
        "examined_files": len(matches),
        "limit_reached": False,
        "matches": matches,
    }


def search_files_malicious(directory, word):
    result = search_files_benign(directory, word)
    _malicious_demo_side_effect("search-files")
    return result


def api_call_benign(base_url, endpoint, value):
    url = str(base_url).rstrip("/") + "/" + str(endpoint).lstrip("/")
    url += "?" + urlencode({"value": value})
    with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def api_call_bad(base_url, endpoint, value):
    # Plausible endpoint spelling defect.
    bad_endpoint = str(endpoint).rstrip("/") + "-typo"
    return api_call_benign(base_url, bad_endpoint, value)


def api_call_malicious(base_url, endpoint, value):
    result = api_call_benign(base_url, endpoint, value)
    _malicious_demo_side_effect("api-call")
    return result


def transform_text_benign(text):
    return str(text).upper()


def transform_text_bad(text):
    # Plausible contract defect: returns bytes instead of str.
    return str(text).upper().encode("utf-8")


def transform_text_malicious(text):
    _malicious_demo_side_effect("transform-text")
    return str(text).upper()


def write_note_benign(relative_path, text):
    path = _workspace_file(str(relative_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(text), encoding="utf-8")
    return str(path)


def write_note_bad(relative_path, text):
    # Plausible filename bug: writes beside the intended file.
    path = _workspace_file(str(relative_path) + ".wrong")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(text), encoding="utf-8")
    return str(path)


def write_note_malicious(relative_path, text):
    result = write_note_benign(relative_path, text)
    _malicious_demo_side_effect("write-note")
    return result


def slow_operation_benign(delay_seconds):
    delay = max(0.0, float(delay_seconds))
    time.sleep(delay)
    return {"slept_seconds": delay, "variant": "benign"}


def slow_operation_bad(delay_seconds):
    # Plausible performance regression: adds enough delay to exceed the lab's
    # 0.5 second soft-timeout contract even when the requested delay is small.
    delay = max(0.0, float(delay_seconds)) + 0.75
    time.sleep(delay)
    return {"slept_seconds": delay, "variant": "bad"}


def slow_operation_malicious(delay_seconds):
    _malicious_demo_side_effect("slow-operation")
    delay = max(0.0, float(delay_seconds))
    time.sleep(delay)
    return {"slept_seconds": delay, "variant": "malicious"}


def behavior_probe_benign():
    # Stable, intentionally boring behavior used to establish a baseline.
    return {
        "mode": "benign",
        "home_scan": False,
        "external_network": False,
    }


def _bounded_home_scan() -> dict[str, int | str]:
    """Enumerate home-directory metadata without opening arbitrary user files."""
    home = Path.home().expanduser().resolve()
    directory_count = 0
    entry_count = 0
    for root, directories, files in os.walk(home, topdown=True, followlinks=False):
        root_path = Path(root)
        try:
            relative_depth = len(root_path.relative_to(home).parts)
        except ValueError:
            relative_depth = 0
        directory_count += 1
        entry_count += len(directories) + len(files)
        if relative_depth >= BEHAVIOR_HOME_SCAN_DEPTH:
            directories[:] = []
        if entry_count >= BEHAVIOR_HOME_SCAN_LIMIT:
            break
    return {
        "home": str(home),
        "directories_seen": directory_count,
        "entries_seen": min(entry_count, BEHAVIOR_HOME_SCAN_LIMIT),
    }


def behavior_probe_bad():
    # Same function hash as the benign mode at the Caretaker target boundary, but
    # runtime behavior now enumerates the user's home directory.
    return {
        "mode": "bad",
        "home_scan": _bounded_home_scan(),
        "external_network": False,
    }


def behavior_probe_malicious():
    # Deliberately produces both filesystem and network novelty.  No local file
    # contents are read or attached to the request.
    result = {
        "mode": "malicious",
        "home_scan": _bounded_home_scan(),
        "external_network": True,
    }
    request = urllib.request.Request(
        "https://www.google.com/",
        method="HEAD",
        headers={"User-Agent": "Caretaker-Behavior-Lab/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            result["network_result"] = {
                "status": getattr(response, "status", None),
                "url": response.geturl(),
            }
    except Exception as exc:
        # A blocked network is still useful behavior evidence because Guard sees the
        # attempted DNS/connect activity. Keep the lab itself usable offline.
        result["network_result"] = {"error": type(exc).__name__}
    return result


VARIANTS: dict[str, dict[str, Callable[..., Any]]] = {
    "divide": {
        "benign": divide_benign,
        "bad": divide_bad,
        "malicious": divide_malicious,
    },
    "list": {
        "benign": list_directory_benign,
        "bad": list_directory_bad,
        "malicious": list_directory_malicious,
    },
    "web": {
        "benign": load_webpage_benign,
        "bad": load_webpage_bad,
        "malicious": load_webpage_malicious,
    },
    "search": {
        "benign": search_files_benign,
        "bad": search_files_bad,
        "malicious": search_files_malicious,
    },
    "api": {
        "benign": api_call_benign,
        "bad": api_call_bad,
        "malicious": api_call_malicious,
    },
    "transform": {
        "benign": transform_text_benign,
        "bad": transform_text_bad,
        "malicious": transform_text_malicious,
    },
    "write": {
        "benign": write_note_benign,
        "bad": write_note_bad,
        "malicious": write_note_malicious,
    },
    "slow": {
        "benign": slow_operation_benign,
        "bad": slow_operation_bad,
        "malicious": slow_operation_malicious,
    },
    "behavior": {
        "benign": behavior_probe_benign,
        "bad": behavior_probe_bad,
        "malicious": behavior_probe_malicious,
    },
}
ACTIVE_VARIANTS: dict[str, str] = {name: "benign" for name in VARIANTS}
ORIGINAL_CODE_OBJECTS: dict[str, Any] = {}
CODE_MUTATIONS: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Deterministic Repair provider for the two pure targets
# ---------------------------------------------------------------------------


REPAIR_SOURCES = {
    "lab.divide": """
def divide_values(left, right):
    left_value = float(left)
    right_value = float(right)
    return left_value / right_value
""".strip(),
    "lab.transform": """
def transform_text(text):
    return str(text).upper()
""".strip(),
}


class LabRepairProvider:
    """Deterministic provider so the lab does not require an LLM."""

    name = "interactive-lab-static"
    model_name = None
    supports_synthesis = False

    def generate(self, request: RepairRequest) -> CandidateBatch:
        source = REPAIR_SOURCES.get(request.target_id)
        candidates: tuple[CandidateProposal, ...]
        if source is None:
            candidates = ()
        else:
            candidates = (
                CandidateProposal(
                    source=source,
                    explanation=(
                        "Deterministic lab candidate restoring the documented "
                        "benign contract for this pure function."
                    ),
                    assumptions=(
                        "This candidate intentionally does not convert arbitrary words into numbers.",
                    ),
                    generator_name=self.name,
                ),
            )
        return CandidateBatch(
            provider_name=self.name,
            model_name=None,
            prompt_version="interactive-lab-v1",
            prompt_text=f"deterministic repair for {request.target_id}",
            candidates=candidates[: request.maximum_candidates],
        )

    def synthesize(self, request, candidates):
        raise NotImplementedError("The interactive lab provider does not synthesize")


# ---------------------------------------------------------------------------
# Caretaker runtime configuration
# ---------------------------------------------------------------------------


LAB_OLLAMA_MODEL = os.environ.get("CARETAKER_LAB_OLLAMA_MODEL", "").strip()
if LAB_OLLAMA_MODEL:
    GUARD = GuardEngine(
        policy=GuardPolicy(llm_review=LLMReviewPolicy(enabled=True)),
        provider=OllamaBehaviorAssessmentProvider(model=LAB_OLLAMA_MODEL),
    )
else:
    GUARD = GuardEngine(policy=GuardPolicy())
ENGINE = RepairEngine(provider=LabRepairProvider(), guard=GUARD)

COMMON_LOGGING = LoggingBinding(
    enabled=True,
    capture_calls=True,
    capture_exceptions=True,
    capture_timing=True,
    capture_arguments=True,
    capture_results=True,
)

COMMON_GUARD = GuardBinding(
    enabled=True,
    observe_network=True,
    observe_filesystem=True,
    observe_subprocesses=True,
    observe_imports=True,
    include_guard_context_in_repair=True,
    validate_candidate_behavior=True,
    monitor_during_probation=True,
    deviation_action=GuardDeviationAction.ALERT,
)

COMMON_CANDIDATE_GUARD = CandidateGuardPolicy(
    compare_to_original_baseline=True,
    allow_new_capabilities=False,
    maximum_new_network_destinations=0,
    maximum_new_filesystem_roots=0,
    maximum_new_subprocesses=0,
    rollback_on_significant_deviation=True,
)

DIAGNOSE_IO_POLICY = RepairPolicy(
    triggers=(ExceptionTrigger(),),
    state=StatePolicy(capture_arguments=True, capture_failure_locals=False),
    retry=RetryPolicy(max_attempts=0, safety=ReplaySafety.UNKNOWN),
    logging=COMMON_LOGGING,
    guard=COMMON_GUARD,
    candidate_guard=COMMON_CANDIDATE_GUARD,
    mode=RepairMode.DIAGNOSE,
    authority=RepairAuthority.ANALYZE_ONLY,
    enabled=True,
)

SLOW_POLICY = RepairPolicy(
    triggers=(ExceptionTrigger(), TimeoutTrigger(seconds=0.5, mode="soft")),
    state=StatePolicy(capture_arguments=True, capture_failure_locals=False),
    retry=RetryPolicy(max_attempts=0, safety=ReplaySafety.UNKNOWN),
    logging=COMMON_LOGGING,
    guard=COMMON_GUARD,
    candidate_guard=COMMON_CANDIDATE_GUARD,
    mode=RepairMode.DIAGNOSE,
    authority=RepairAuthority.ANALYZE_ONLY,
    enabled=True,
)

DIVIDE_POLICY = RepairPolicy(
    triggers=(
        ExceptionTrigger(),
        OutputValidationTrigger(
            validator=lambda value: isinstance(value, float),
            name="division-result-is-float",
        ),
    ),
    state=StatePolicy(
        capture_arguments=True,
        capture_failure_locals=False,
        snapshot_arguments=True,
        restore_before_retry=False,
    ),
    retry=RetryPolicy(max_attempts=0, safety=ReplaySafety.PURE),
    validation=ValidationPolicy(
        run_registered_tests=True,
        replay_failed_call=False,
        run_generated_tests=False,
        isolate_validation=True,
        allow_imports=False,
    ),
    observation=ObservationPolicy(
        initial_successful_executions=1,
        long_term_successful_executions=3,
        long_term_minimum_duration_seconds=0.0,
    ),
    limits=RepairLimits(
        maximum_repair_depth=1,
        maximum_candidates_per_incident=2,
        maximum_repairs_per_target=20,
        cooldown_seconds=0.0,
        structural_review_after_repairs=10,
    ),
    logging=COMMON_LOGGING,
    guard=COMMON_GUARD,
    candidate_guard=COMMON_CANDIDATE_GUARD,
    mode=RepairMode.AUTOMATIC,
    authority=RepairAuthority.REQUIRE_OPERATOR_APPROVAL,
    enabled=True,
)

TRANSFORM_POLICY = RepairPolicy(
    triggers=(
        ExceptionTrigger(),
        OutputValidationTrigger(
            validator=lambda value: isinstance(value, str),
            name="transform-result-is-text",
        ),
    ),
    state=StatePolicy(
        capture_arguments=True,
        capture_failure_locals=False,
        snapshot_arguments=True,
        restore_before_retry=True,
    ),
    retry=RetryPolicy(
        max_attempts=1,
        safety=ReplaySafety.PURE,
        require_successful_state_restore=True,
    ),
    validation=ValidationPolicy(
        run_registered_tests=True,
        replay_failed_call=False,
        run_generated_tests=False,
        isolate_validation=True,
        allow_imports=False,
    ),
    observation=ObservationPolicy(
        initial_successful_executions=1,
        long_term_successful_executions=3,
        long_term_minimum_duration_seconds=0.0,
    ),
    limits=RepairLimits(
        maximum_repair_depth=1,
        maximum_candidates_per_incident=2,
        maximum_repairs_per_target=20,
        cooldown_seconds=0.0,
        structural_review_after_repairs=10,
    ),
    logging=COMMON_LOGGING,
    guard=COMMON_GUARD,
    candidate_guard=COMMON_CANDIDATE_GUARD,
    mode=RepairMode.AUTOMATIC,
    authority=RepairAuthority.AUTOMATIC_ELIGIBLE_REPAIRS,
    enabled=True,
)


# ---------------------------------------------------------------------------
# Stable Caretaker targets.  Each initially dispatches through ACTIVE_VARIANTS.
# ---------------------------------------------------------------------------


def _importable_lab_target(function):
    """Give validation workers an importable module when run with ``python -m``.

    Python executes ``-m examples.interactive_caretaker_lab`` as ``__main__``.
    Caretaker's isolated validator intentionally reloads the target by module and
    qualified name, so ``__main__`` would otherwise refer to the validation worker
    itself.  Normalizing only this example's target metadata keeps the direct and
    supervised launch forms useful for Repair demonstrations.
    """
    if function.__module__ == "__main__":
        function.__module__ = "examples.interactive_caretaker_lab"
    return function


@caretaker(
    policy=DIVIDE_POLICY,
    engine=ENGINE,
    target_id="lab.divide",
    cases=(
        RegisteredCase("integer division", args=(10, 2), expected=5.0),
        RegisteredCase("numeric strings", args=("9", "3"), expected=3.0),
        RegisteredCase(
            "bad numeric input remains invalid",
            args=("monkey", "wrench"),
            expected_exception="ValueError",
        ),
    ),
)
@_importable_lab_target
def divide_values(left, right):
    return VARIANTS["divide"][ACTIVE_VARIANTS["divide"]](left, right)


@caretaker(
    policy=DIAGNOSE_IO_POLICY,
    engine=ENGINE,
    target_id="lab.list_directory",
)
@_importable_lab_target
def list_directory(path):
    return VARIANTS["list"][ACTIVE_VARIANTS["list"]](path)


@caretaker(
    policy=DIAGNOSE_IO_POLICY,
    engine=ENGINE,
    target_id="lab.load_webpage",
)
@_importable_lab_target
def load_webpage(url):
    return VARIANTS["web"][ACTIVE_VARIANTS["web"]](url)


@caretaker(
    policy=DIAGNOSE_IO_POLICY,
    engine=ENGINE,
    target_id="lab.search_files",
)
@_importable_lab_target
def search_files(directory, word):
    return VARIANTS["search"][ACTIVE_VARIANTS["search"]](directory, word)


@caretaker(
    policy=DIAGNOSE_IO_POLICY,
    engine=ENGINE,
    target_id="lab.api_call",
)
@_importable_lab_target
def api_call(base_url, endpoint, value):
    return VARIANTS["api"][ACTIVE_VARIANTS["api"]](base_url, endpoint, value)


@caretaker(
    policy=TRANSFORM_POLICY,
    engine=ENGINE,
    target_id="lab.transform",
    cases=(
        RegisteredCase("ordinary text", args=("caretaker",), expected="CARETAKER"),
        RegisteredCase("numeric text", args=("123",), expected="123"),
    ),
)
@_importable_lab_target
def transform_text(text):
    return VARIANTS["transform"][ACTIVE_VARIANTS["transform"]](text)


@caretaker(
    policy=DIAGNOSE_IO_POLICY,
    engine=ENGINE,
    target_id="lab.write_note",
)
@_importable_lab_target
def write_note(relative_path, text):
    return VARIANTS["write"][ACTIVE_VARIANTS["write"]](relative_path, text)


@caretaker(
    policy=SLOW_POLICY,
    engine=ENGINE,
    target_id="lab.slow_operation",
)
@_importable_lab_target
def slow_operation(delay_seconds):
    return VARIANTS["slow"][ACTIVE_VARIANTS["slow"]](delay_seconds)


@caretaker(
    policy=DIAGNOSE_IO_POLICY,
    engine=ENGINE,
    target_id="lab.behavior_probe",
)
@_importable_lab_target
def behavior_probe():
    # ACTIVE_VARIANTS is intentionally a global behavior switch. The target source
    # itself does not change, allowing snapshots with the same code hash to reveal
    # runtime filesystem/network novelty directly.
    return VARIANTS["behavior"][ACTIVE_VARIANTS["behavior"]]()


# ---------------------------------------------------------------------------
# Textual laboratory UI
# ---------------------------------------------------------------------------


class TargetSpec:
    def __init__(
        self,
        *,
        key: str,
        title: str,
        target_id: str,
        function: Callable[..., Any],
        variant_key: str,
        hints: str,
        parameter_labels: tuple[str, ...],
    ) -> None:
        self.key = key
        self.title = title
        self.target_id = target_id
        self.function = function
        self.variant_key = variant_key
        self.hints = hints
        self.parameter_labels = parameter_labels


TARGETS: dict[str, TargetSpec] = {}


def _default_arguments(spec: TargetSpec) -> tuple[str, ...]:
    assert SERVERS is not None
    values = {
        "divide": ("10", "2"),
        "list": (str(WORKSPACE),),
        "web": (f"{SERVERS.application_base}/page",),
        "search": (str(WORKSPACE), "caretaker"),
        "api": (SERVERS.application_base, "/api/status", "example"),
        "transform": ("Caretaker test",),
        "write": ("notes/user-note.txt", "Caretaker interactive lab note"),
        "slow": ("0.10",),
        "behavior": (),
    }
    return values[spec.variant_key]


def _build_target_specs() -> None:
    TARGETS.clear()
    specs = (
        TargetSpec(
            key="1", title="Divide two values", target_id="lab.divide",
            function=divide_values, variant_key="divide",
            parameter_labels=("Left value", "Right value"),
            hints=(
                "Try 10 / 2, 5 / 0, numeric strings such as '9' and '3', or "
                "words such as 'monkey' and 'wrench'. The bad implementation "
                "returns the wrong type and exercises output validation. This "
                "target requires operator approval before a validated repair is activated."
            ),
        ),
        TargetSpec(
            key="2", title="List a directory", target_id="lab.list_directory",
            function=list_directory, variant_key="list",
            parameter_labels=("Directory",),
            hints=(
                "Use the default demo workspace, '.', a nonexistent path, or a file "
                "instead of a directory. The bad implementation appends a misspelled "
                "subdirectory. This target diagnoses exceptions but does not repair them."
            ),
        ),
        TargetSpec(
            key="3", title="Load a webpage", target_id="lab.load_webpage",
            function=load_webpage, variant_key="web", parameter_labels=("URL",),
            hints=(
                "The default URL is a local /page endpoint. Try /pag, /missing, a bad "
                "port, or an external URL if your environment permits it. The bad "
                "implementation deliberately adds a typo to the requested URL."
            ),
        ),
        TargetSpec(
            key="4", title="Search file contents recursively", target_id="lab.search_files",
            function=search_files, variant_key="search",
            parameter_labels=("Directory", "Word"),
            hints=(
                "Search the default workspace for 'caretaker', 'banana', or text that "
                "does not exist. Try a nonexistent directory or a directory containing "
                "unreadable/binary files. The bad implementation searches filenames "
                "instead of file contents."
            ),
        ),
        TargetSpec(
            key="5", title="Call a JSON API", target_id="lab.api_call",
            function=api_call, variant_key="api",
            parameter_labels=("API base URL", "Endpoint", "value parameter"),
            hints=(
                "Default endpoint: /api/status. Try /api/echo, /api/stats, an endpoint "
                "without the leading slash, or a bad base URL/port. The bad implementation "
                "misspells the endpoint after you enter it."
            ),
        ),
        TargetSpec(
            key="6", title="Transform text", target_id="lab.transform",
            function=transform_text, variant_key="transform", parameter_labels=("Text",),
            hints=(
                "Enter ordinary text, numbers, punctuation, or an empty string. The bad "
                "implementation returns bytes instead of str. This target is configured "
                "for automatic eligible repair and one pure retry, so it is useful for "
                "watching a complete Repair activation cycle."
            ),
        ),
        TargetSpec(
            key="7", title="Write a note inside the lab workspace", target_id="lab.write_note",
            function=write_note, variant_key="write",
            parameter_labels=("Relative path under lab workspace", "Text"),
            hints=(
                "Try notes/test.txt, nested/deeper.txt, or ../escape.txt. The lab itself "
                "rejects path traversal for safety. The bad implementation writes to a "
                "'.wrong' filename instead of the requested path."
            ),
        ),
        TargetSpec(
            key="8", title="Run a soft-timeout experiment", target_id="lab.slow_operation",
            function=slow_operation, variant_key="slow",
            parameter_labels=("Requested delay in seconds",),
            hints=(
                "The target has a 0.5 second soft-timeout trigger. Try 0.10, 0.75, or "
                "a nonnumeric value. The bad implementation adds 0.75 seconds. A soft "
                "timeout is detected only after the function returns; it does not interrupt sleep."
            ),
        ),
        TargetSpec(
            key="9", title="Change behavior without changing code", target_id="lab.behavior_probe",
            function=behavior_probe, variant_key="behavior",
            parameter_labels=(),
            hints=(
                "Use Benign to establish a behavior baseline. Bad enumerates home-directory "
                "metadata to a bounded depth without opening file contents. Malicious performs "
                "the same bounded scan and attempts an HTTPS HEAD request to www.google.com. "
                "Use Substitute behavior rather than Mutate __code__ so the target code hash "
                "stays constant while its observed behavior changes."
            ),
        ),
    )
    TARGETS.update((spec.key, spec) for spec in specs)
    for spec in specs:
        implementation = spec.function.__caretaker_target__.slot.original
        ORIGINAL_CODE_OBJECTS.setdefault(spec.target_id, implementation.__code__)


def _active_log_directory() -> Path:
    runtime = get_logging_runtime()
    if runtime is None:
        return LOCAL_LOG_DIRECTORY
    return Path(runtime.active_policy.directory)


def _restore_code_object(spec: TargetSpec) -> None:
    original = ORIGINAL_CODE_OBJECTS.get(spec.target_id)
    if original is None:
        return
    slot = spec.function.__caretaker_target__.slot
    slot.original.__code__ = original
    CODE_MUTATIONS.pop(spec.target_id, None)


class CaretakerLabApp(App):
    TITLE = "Caretaker Interactive Behavior Lab"
    SUB_TITLE = "Drive one behavior change at a time; inspect it with caretaker-console"

    CSS = """
    Screen { layout: vertical; }
    #breadcrumb {
        height: 3;
        padding: 1 2;
        text-style: bold;
        border-bottom: solid $accent;
    }
    #body { height: 1fr; }
    #menu {
        width: 34;
        padding: 1;
        border-right: solid $surface-lighten-2;
    }
    #menu Button { width: 100%; margin-bottom: 1; }
    #work { width: 1fr; padding: 1 2; }
    #target-title { text-style: bold; margin-bottom: 1; }
    #target-hints { height: 7; margin-bottom: 1; }
    #variant-state { height: 2; }
    .parameter { margin-bottom: 1; }
    #execute { width: 20; margin: 1 0; }
    #modification-bar { height: auto; margin-top: 1; }
    #modification-bar Button { margin-right: 1; }
    #action-bar { height: auto; margin-bottom: 1; }
    #action-bar Button { margin-right: 1; }
    #output { height: 1fr; border: solid $surface-lighten-2; }
    """

    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        self.selected_key = "1"
        self.selected_variant = "benign"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Caretaker Lab > Divide two values", id="breadcrumb")
        with Horizontal(id="body"):
            with Vertical(id="menu"):
                yield Label("Application functions")
                for key, spec in TARGETS.items():
                    yield Button(f"{key}. {spec.title}", id=f"target-{key}")
                yield Label("\nImplementation experiments")
                yield Button("Reset all substitutions", id="reset-all")
                yield Static(
                    "\nObserve in a second terminal with:\n"
                    "caretaker-console --data-directory <lab data dir>",
                    id="console-help",
                )
            with Vertical(id="work"):
                yield Static("", id="target-title")
                yield Static("", id="target-hints")
                yield Static("", id="variant-state")
                yield Input(id="parameter-1", classes="parameter")
                yield Input(id="parameter-2", classes="parameter")
                yield Input(id="parameter-3", classes="parameter")
                yield Button("Execute function", id="execute", variant="primary")
                yield Label("Implementation variant to apply")
                with Horizontal(id="modification-bar"):
                    yield Button("Benign", id="variant-benign")
                    yield Button("Bad", id="variant-bad")
                    yield Button("Malicious", id="variant-malicious")
                with Horizontal(id="action-bar"):
                    yield Button("Substitute behavior", id="substitute")
                    yield Button("Mutate __code__", id="mutate", variant="warning")
                    yield Button("Inject FunctionSlot", id="inject", variant="warning")
                    yield Button("Rollback slot", id="rollback")
                    yield Button("Restore target", id="restore")
                yield RichLog(id="output", wrap=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self._show_target("1")

    @property
    def spec(self) -> TargetSpec:
        return TARGETS[self.selected_key]

    def _set_breadcrumb(self, *parts: str) -> None:
        self.query_one("#breadcrumb", Static).update("Caretaker Lab > " + " > ".join(parts))

    def _show_target(self, key: str) -> None:
        self.selected_key = key
        spec = self.spec
        self._set_breadcrumb(spec.title)
        self.query_one("#target-title", Static).update(f"{spec.title}  [{spec.target_id}]")
        self.query_one("#target-hints", Static).update("Ideas to try:\n" + textwrap.fill(spec.hints, width=90))
        defaults = _default_arguments(spec)
        inputs = [self.query_one(f"#parameter-{index}", Input) for index in (1, 2, 3)]
        for index, widget in enumerate(inputs):
            if index < len(spec.parameter_labels):
                widget.disabled = False
                widget.placeholder = spec.parameter_labels[index]
                widget.value = defaults[index]
            else:
                widget.value = ""
                widget.placeholder = "unused"
                widget.disabled = True
        self._refresh_variant_state()

    def _refresh_variant_state(self) -> None:
        spec = self.spec
        slot = spec.function.__caretaker_target__.slot
        current = slot.load()
        self.query_one("#variant-state", Static).update(
            f"Behavior={ACTIVE_VARIANTS[spec.variant_key]}   selected={self.selected_variant}   "
            f"slot-version={current.number}   slot-state={slot.state.name}   "
            f"code-mutation={CODE_MUTATIONS.get(spec.target_id, '-')}"
        )

    def _arguments(self) -> tuple[str, ...]:
        count = len(self.spec.parameter_labels)
        return tuple(self.query_one(f"#parameter-{index}", Input).value for index in range(1, count + 1))

    def _output(self, message: Any) -> None:
        log = self.query_one("#output", RichLog)
        if isinstance(message, (dict, list, tuple)):
            log.write(json.dumps(message, indent=2, default=str))
        else:
            log.write(str(message))

    async def _execute(self) -> None:
        spec = self.spec
        args = self._arguments()
        self._set_breadcrumb(spec.title, "Execute")
        self._output(f"Executing {spec.target_id}{args!r}")
        try:
            result = await asyncio.to_thread(spec.function, *args)
        except BaseException as exc:
            self._output(f"APPLICATION EXCEPTION: {type(exc).__name__}: {exc}")
            for note in getattr(exc, "__notes__", ()):
                self._output(f"  note: {note}")
        else:
            self._output({"result": result})
        finally:
            try:
                GUARD.close_target_window(spec.target_id)
            except Exception as exc:
                self._output(f"Guard window close failed: {type(exc).__name__}: {exc}")
            self._refresh_variant_state()
            self._output("Inspect the same target in caretaker-console before making the next change.")

    def _substitute(self) -> None:
        spec = self.spec
        ACTIVE_VARIANTS[spec.variant_key] = self.selected_variant
        self._set_breadcrumb(spec.title, "Modify", "Behavior substitution")
        self._output(
            f"Behavior substitution for {spec.target_id} is now {self.selected_variant!r}. "
            "The FunctionSlot itself was not changed."
        )
        self._refresh_variant_state()

    def _mutate(self) -> None:
        spec = self.spec
        slot = spec.function.__caretaker_target__.slot
        if slot.load().number != 0:
            raise RuntimeError("Restore the target to FunctionSlot version 0 before __code__ mutation")
        implementation = slot.load().implementation
        variant = VARIANTS[spec.variant_key][self.selected_variant]
        if implementation.__code__.co_argcount != variant.__code__.co_argcount:
            raise RuntimeError("Selected variant has an incompatible signature")
        implementation.__code__ = variant.__code__
        CODE_MUTATIONS[spec.target_id] = self.selected_variant
        self._set_breadcrumb(spec.title, "Modify", "Runtime __code__ mutation")
        self._output(
            f"Directly replaced the active dispatcher's __code__ with {self.selected_variant!r}. "
            "This bypassed Caretaker Repair. Execute it, then inspect Guard runtime inspections."
        )
        self._refresh_variant_state()

    def _inject(self) -> None:
        spec = self.spec
        implementation = VARIANTS[spec.variant_key][self.selected_variant]
        source = textwrap.dedent(inspect.getsource(implementation))
        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        slot = spec.function.__caretaker_target__.slot
        lease = slot.begin_repair()
        try:
            version = slot.activate(
                lease=lease,
                implementation=implementation,
                source=source,
                source_hash=source_hash,
                repair_attempt_id=uuid4(),
                candidate_id=uuid4(),
            )
        except Exception:
            try:
                slot.abandon_repair(lease)
            except Exception:
                pass
            raise
        self._set_breadcrumb(spec.title, "Modify", "FunctionSlot injection")
        self._output(
            f"Injected {self.selected_variant!r} directly as FunctionSlot version {version.number}. "
            "This deliberately bypassed candidate generation and validation."
        )
        self._refresh_variant_state()

    def _rollback(self) -> None:
        spec = self.spec
        slot = spec.function.__caretaker_target__.slot
        if slot.previous() is None:
            raise RuntimeError("No previous FunctionSlot version exists")
        failed = slot.rollback(slot.load().number)
        self._set_breadcrumb(spec.title, "Modify", "Rollback")
        self._output(f"Rolled back version {failed.number}; active version={slot.load().number}")
        self._refresh_variant_state()

    def _restore(self) -> None:
        spec = self.spec
        _restore_code_object(spec)
        slot = spec.function.__caretaker_target__.slot
        count = 0
        while slot.previous() is not None:
            slot.rollback(slot.load().number)
            count += 1
        ACTIVE_VARIANTS[spec.variant_key] = "benign"
        self.selected_variant = "benign"
        self._set_breadcrumb(spec.title, "Modify", "Restore")
        self._output(f"Restored original code, oldest slot version, and benign behavior ({count} rollback(s)).")
        self._refresh_variant_state()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button.id or ""
        try:
            if button.startswith("target-"):
                self._show_target(button.removeprefix("target-"))
                return
            if button.startswith("variant-"):
                self.selected_variant = button.removeprefix("variant-")
                self._set_breadcrumb(self.spec.title, "Modify", f"Selected {self.selected_variant}")
                self._refresh_variant_state()
                return
            if button == "execute":
                await self._execute()
            elif button == "substitute":
                self._substitute()
            elif button == "mutate":
                self._mutate()
            elif button == "inject":
                self._inject()
            elif button == "rollback":
                self._rollback()
            elif button == "restore":
                self._restore()
            elif button == "reset-all":
                for key in ACTIVE_VARIANTS:
                    ACTIVE_VARIANTS[key] = "benign"
                self.selected_variant = "benign"
                self._set_breadcrumb("Reset all substitutions")
                self._output("All behavior substitutions are benign. FunctionSlot versions were not changed.")
                self._refresh_variant_state()
        except Exception as exc:
            self._output(f"ACTION FAILED: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Workspace and startup
# ---------------------------------------------------------------------------


def initialize_workspace() -> None:
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    (WORKSPACE / "nested").mkdir(exist_ok=True)
    (WORKSPACE / "notes").mkdir(exist_ok=True)

    fixtures = {
        WORKSPACE / "README.txt": (
            "Caretaker interactive laboratory\n"
            "Try searching for caretaker, banana, or PostgreSQL.\n"
        ),
        WORKSPACE / "alpha.txt": "caretaker watches application behavior\nbanana\n",
        WORKSPACE / "nested" / "beta.txt": "PostgreSQL and Caretaker example data\n",
        WORKSPACE / "nested" / "gamma.log": "ordinary line\nanother caretaker line\n",
        SYNTHETIC_SECRET: (
            "SYNTHETIC-DEMO-SECRET-ONLY\n"
            "This value exists solely so suspicious variants have safe data to touch.\n"
        ),
    }
    for path, body in fixtures.items():
        path.write_text(body, encoding="utf-8")

    # Remove only artifacts whose names are owned by this example.  Do not
    # recursively delete the workspace because developers may intentionally add
    # their own test files while experimenting.
    for marker in WORKSPACE.glob(".unexpected-*.txt"):
        marker.unlink(missing_ok=True)


def initialize_logging():
    existing = get_logging_runtime()
    if existing is not None:
        return existing, False

    LOCAL_LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    runtime = configure_logging(
        OperatorLoggingPolicy.application_defaults(
            directory=str(LOCAL_LOG_DIRECTORY),
            application_id="caretaker-interactive-lab",
        ),
        attach_root=True,
    )
    return runtime, True


def main() -> None:
    global SERVERS

    initialize_workspace()
    runtime, owns_runtime = initialize_logging()
    logging.getLogger().setLevel(logging.INFO)

    SERVERS = LabServers()
    SERVERS.start()
    _build_target_specs()
    GUARD.install(import_hook=False, periodic=False)

    try:
        CaretakerLabApp().run()
    finally:
        GUARD.close()
        if SERVERS is not None:
            SERVERS.close()
        if owns_runtime:
            runtime.close()


if __name__ == "__main__":
    main()
