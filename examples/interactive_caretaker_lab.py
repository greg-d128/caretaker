"""Interactive Caretaker behavior laboratory.

See ``examples/interactive_caretaker_lab.md`` for a guided walkthrough.

This example is intentionally driven from a terminal menu.  It is meant to be
run by a developer who wants to make one controlled change at a time and then
inspect Caretaker's evidence, Guard observations, Repair state, and logs from a
second-terminal lab console.

The lab provides eight application functions:

* division;
* directory listing;
* webpage loading;
* recursive content search;
* JSON API calls;
* text transformation;
* note writing;
* a deliberately slow operation for soft-timeout experiments.

Each target has three application-level implementations:

``benign``
    Expected implementation.
``bad``
    Plausible implementation defect: exception, incorrect result, wrong path,
    or misspelled endpoint.
``malicious``
    A *contained simulation* of suspicious behavior.  It still returns the
    expected result when possible, but also performs unrelated filesystem,
    subprocess, and loopback-network activity.  It never deletes user data,
    never transmits real file contents, and never sends data off-host.  The only
    synthetic secret it reads is created inside this lab's private workspace.

Three modification mechanisms are available:

1. behavior substitution changes the function selected by the original stable
   dispatcher while leaving the Caretaker FunctionSlot implementation alone;
2. code-object mutation replaces the active dispatcher's ``__code__`` object
   without going through Caretaker, simulating unauthorized runtime tampering;
3. slot injection deliberately replaces the active FunctionSlot implementation
   and therefore simulates an out-of-band candidate activation.

The mutation/injection mechanisms intentionally bypass the Repair provider and
validation pipeline.  They exist only so a developer can observe Guard runtime
inspection and candidate/probation behavior.

The example uses only the Python standard library and Caretaker itself.  It
starts two loopback-only HTTP servers so network behavior can be tested without
requiring Internet access.

Direct execution from the repository root::

    PYTHONPATH=src:. python -m examples.interactive_caretaker_lab

Supervised execution, which also exposes Caretaker's standard supervisor control socket::

    PYTHONPATH=src:. python -m caretaker.run \
      --data-directory ./caretaker-interactive-lab/caretaker-data \
      examples.interactive_caretaker_lab

Attach the example-specific observation console from a second terminal::

    PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console

The lab deliberately enables argument and result evidence.  Do not enter real
secrets while experimenting.
"""

from __future__ import annotations

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
from caretaker.logging import (
    OperatorLoggingPolicy,
    configure as configure_logging,
    get_runtime as get_logging_runtime,
    read_segment,
)
from caretaker.logging.ipc import ControlSocketServer
from caretaker.provider import CandidateBatch, RepairRequest


LOGGER = logging.getLogger("caretaker.interactive_lab")

LAB_ROOT = Path(
    os.environ.get("CARETAKER_LAB_ROOT", "./caretaker-interactive-lab")
).resolve()
WORKSPACE = LAB_ROOT / "workspace"
LOCAL_LOG_DIRECTORY = LAB_ROOT / "caretaker-data"
SYNTHETIC_SECRET = WORKSPACE / "demo-secret.txt"
COLLECTOR_EVENTS: list[dict[str, str]] = []
LAB_CONSOLE_SERVER: ControlSocketServer | None = None
LAB_CONSOLE_THREAD: threading.Thread | None = None

SEARCH_FILE_LIMIT = 2_000
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


# ---------------------------------------------------------------------------
# Menu metadata and helpers
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
        prompt: Callable[[], tuple[Any, ...]],
    ) -> None:
        self.key = key
        self.title = title
        self.target_id = target_id
        self.function = function
        self.variant_key = variant_key
        self.hints = hints
        self.prompt = prompt


TARGETS: dict[str, TargetSpec] = {}


def _input_with_default(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value if value else default


def _prompt_divide() -> tuple[Any, ...]:
    left = _input_with_default("Left value", "10")
    right = _input_with_default("Right value", "2")
    return left, right


def _prompt_list() -> tuple[Any, ...]:
    return (_input_with_default("Directory", str(WORKSPACE)),)


def _prompt_web() -> tuple[Any, ...]:
    assert SERVERS is not None
    return (_input_with_default("URL", f"{SERVERS.application_base}/page"),)


def _prompt_search() -> tuple[Any, ...]:
    directory = _input_with_default("Directory", str(WORKSPACE))
    word = _input_with_default("Word", "caretaker")
    return directory, word


def _prompt_api() -> tuple[Any, ...]:
    assert SERVERS is not None
    base = _input_with_default("API base URL", SERVERS.application_base)
    endpoint = _input_with_default("Endpoint", "/api/status")
    value = _input_with_default("value parameter", "example")
    return base, endpoint, value


def _prompt_transform() -> tuple[Any, ...]:
    return (_input_with_default("Text", "Caretaker test"),)


def _prompt_write() -> tuple[Any, ...]:
    relative = _input_with_default("Relative path under lab workspace", "notes/user-note.txt")
    text = _input_with_default("Text", "Caretaker interactive lab note")
    return relative, text


def _prompt_slow() -> tuple[Any, ...]:
    return (_input_with_default("Requested delay in seconds", "0.10"),)


def _build_target_specs() -> None:
    TARGETS.clear()
    specs = (
        TargetSpec(
            key="1",
            title="Divide two values",
            target_id="lab.divide",
            function=divide_values,
            variant_key="divide",
            hints=(
                "Try 10 / 2, 5 / 0, numeric strings such as '9' and '3', or "
                "words such as 'monkey' and 'wrench'. The bad implementation "
                "returns the wrong type and exercises output validation. This "
                "target requires operator approval before a validated repair is activated."
            ),
            prompt=_prompt_divide,
        ),
        TargetSpec(
            key="2",
            title="List a directory",
            target_id="lab.list_directory",
            function=list_directory,
            variant_key="list",
            hints=(
                "Use the default demo workspace, '.', a nonexistent path, or a file "
                "instead of a directory. The bad implementation appends a misspelled "
                "subdirectory. This target diagnoses exceptions but does not repair them."
            ),
            prompt=_prompt_list,
        ),
        TargetSpec(
            key="3",
            title="Load a webpage",
            target_id="lab.load_webpage",
            function=load_webpage,
            variant_key="web",
            hints=(
                "The default URL is a local /page endpoint. Try /pag, /missing, a bad "
                "port, or an external URL if your environment permits it. The bad "
                "implementation deliberately adds a typo to the requested URL."
            ),
            prompt=_prompt_web,
        ),
        TargetSpec(
            key="4",
            title="Search file contents recursively",
            target_id="lab.search_files",
            function=search_files,
            variant_key="search",
            hints=(
                "Search the default workspace for 'caretaker', 'banana', or text that "
                "does not exist. Try a nonexistent directory or a directory containing "
                "unreadable/binary files. The bad implementation searches filenames "
                "instead of file contents."
            ),
            prompt=_prompt_search,
        ),
        TargetSpec(
            key="5",
            title="Call a JSON API",
            target_id="lab.api_call",
            function=api_call,
            variant_key="api",
            hints=(
                "Default endpoint: /api/status. Try /api/echo, /api/stats, an endpoint "
                "without the leading slash, or a bad base URL/port. The bad implementation "
                "misspells the endpoint after you enter it."
            ),
            prompt=_prompt_api,
        ),
        TargetSpec(
            key="6",
            title="Transform text",
            target_id="lab.transform",
            function=transform_text,
            variant_key="transform",
            hints=(
                "Enter ordinary text, numbers, punctuation, or an empty string. The bad "
                "implementation returns bytes instead of str. This target is configured "
                "for automatic eligible repair and one pure retry, so it is useful for "
                "watching a complete Repair activation cycle."
            ),
            prompt=_prompt_transform,
        ),
        TargetSpec(
            key="7",
            title="Write a note inside the lab workspace",
            target_id="lab.write_note",
            function=write_note,
            variant_key="write",
            hints=(
                "Try notes/test.txt, nested/deeper.txt, or ../escape.txt. The lab itself "
                "rejects path traversal for safety. The bad implementation writes to a "
                "'.wrong' filename instead of the requested path."
            ),
            prompt=_prompt_write,
        ),
        TargetSpec(
            key="8",
            title="Run a soft-timeout experiment",
            target_id="lab.slow_operation",
            function=slow_operation,
            variant_key="slow",
            hints=(
                "The target has a 0.5 second soft-timeout trigger. Try 0.10, 0.75, or "
                "a nonnumeric value. The bad implementation adds 0.75 seconds. Notice "
                "that a soft timeout is detected only after the function returns; it "
                "does not interrupt the sleep."
            ),
            prompt=_prompt_slow,
        ),
    )
    TARGETS.update((spec.key, spec) for spec in specs)
    for spec in specs:
        implementation = spec.function.__caretaker_target__.slot.original
        ORIGINAL_CODE_OBJECTS.setdefault(spec.target_id, implementation.__code__)


def _target_by_id(target_id: str) -> TargetSpec:
    return next(spec for spec in TARGETS.values() if spec.target_id == target_id)


def _print_result(result: Any) -> None:
    if isinstance(result, (dict, list, tuple)):
        print(json.dumps(result, indent=2, default=str))
    else:
        print(repr(result))


def _close_guard_window(target_id: str) -> None:
    try:
        window = GUARD.close_target_window(target_id)
    except Exception as exc:
        print(f"[Guard] Could not close observation window: {type(exc).__name__}: {exc}")
        return
    if window is not None:
        print(
            f"[Guard] Closed behavior window: {window.event_count} events, "
            f"{window.call_count} correlated call(s)."
        )


def execute_target(spec: TargetSpec) -> None:
    _menu_header("Main", spec.title, title=spec.title)
    print("Target:", spec.target_id)
    print("Behavior substitution:", ACTIVE_VARIANTS[spec.variant_key])
    current = spec.function.__caretaker_target__.slot.load()
    print(
        "FunctionSlot:",
        f"version={current.number}",
        f"candidate={current.candidate_id or '-'}",
        f"state={spec.function.__caretaker_target__.slot.state.name}",
    )
    print("\nIdeas to try:")
    print(textwrap.fill(spec.hints, width=78, initial_indent="  ", subsequent_indent="  "))
    print()

    args = spec.prompt()
    print("\nExecuting...")
    try:
        result = spec.function(*args)
    except BaseException as exc:
        print(f"APPLICATION EXCEPTION: {type(exc).__name__}: {exc}")
        notes = getattr(exc, "__notes__", ())
        for note in notes:
            print(f"  note: {note}")
    else:
        print("RESULT:")
        _print_result(result)
    finally:
        _close_guard_window(spec.target_id)

    print("\nNext useful steps:")
    print("  * Use the attached lab console to inspect Guard / Repair / log evidence")
    print("  * Use the modification menu to substitute or inject another implementation")
    print("  * Run 'help' in the lab console for useful observation commands")


# ---------------------------------------------------------------------------
# Menu breadcrumbs
# ---------------------------------------------------------------------------


def _breadcrumb(*parts: str) -> str:
    return "Caretaker Lab > " + " > ".join(parts)


def _menu_header(*parts: str, title: str | None = None) -> None:
    print(f"\n[{_breadcrumb(*parts)}]")
    if title:
        print(title)
        print("-" * len(title))


# ---------------------------------------------------------------------------
# Modification menu
# ---------------------------------------------------------------------------


def _choose_target(*breadcrumb: str) -> TargetSpec | None:
    _menu_header(*breadcrumb, "Select target", title="Targets")
    for key, spec in TARGETS.items():
        print(f"  {key}. {spec.title} ({spec.target_id})")
    value = input("Select target, or Enter to cancel: ").strip()
    return TARGETS.get(value)


def _choose_variant(spec: TargetSpec, *breadcrumb: str) -> str | None:
    _menu_header(
        *breadcrumb,
        spec.title,
        "Select variant",
        title=f"Variants for {spec.title}",
    )
    print("  1. benign     expected behavior")
    print("  2. bad        application defect / incorrect result")
    print("  3. malicious  contained suspicious side effects + expected result")
    value = input("Select variant, or Enter to cancel: ").strip()
    return {"1": "benign", "2": "bad", "3": "malicious"}.get(value)


def change_behavior_substitution() -> None:
    spec = _choose_target("Main", "Modify implementations")
    if spec is None:
        return
    variant = _choose_variant(spec, "Main", "Modify implementations")
    if variant is None:
        return
    ACTIVE_VARIANTS[spec.variant_key] = variant
    print(
        f"Behavior substitution for {spec.target_id} is now {variant!r}.\n"
        "The Caretaker FunctionSlot itself was not modified. This is useful for "
        "behavioral-drift experiments after accepting a benign Guard baseline."
    )


def mutate_active_code_object() -> None:
    spec = _choose_target("Main", "Modify implementations")
    if spec is None:
        return
    variant_name = _choose_variant(spec, "Main", "Modify implementations")
    if variant_name is None:
        return

    slot = spec.function.__caretaker_target__.slot
    if slot.load().number != 0:
        print(
            "Code-object mutation is limited to the original dispatcher. Restore the "
            "target to its oldest FunctionSlot version first."
        )
        return

    implementation = slot.load().implementation
    variant = VARIANTS[spec.variant_key][variant_name]
    if implementation.__code__.co_argcount != variant.__code__.co_argcount:
        print("Variant signature is incompatible with this dispatcher.")
        return

    print(
        "\nWARNING: this simulates unauthorized in-process tampering by replacing the "
        "function's __code__ object directly. No Caretaker Repair or validation API "
        "is called. Execute the function once, then inspect Guard runtime inspections."
    )
    answer = input("Mutate the active code object? [y/N]: ").strip().lower()
    if answer != "y":
        return

    implementation.__code__ = variant.__code__
    CODE_MUTATIONS[spec.target_id] = variant_name
    print(f"Mutated {spec.target_id} to the {variant_name!r} code object.")


def restore_code_object(spec: TargetSpec) -> None:
    original = ORIGINAL_CODE_OBJECTS.get(spec.target_id)
    if original is None:
        return
    slot = spec.function.__caretaker_target__.slot
    slot.original.__code__ = original
    CODE_MUTATIONS.pop(spec.target_id, None)


def inject_slot_variant() -> None:
    spec = _choose_target("Main", "Modify implementations")
    if spec is None:
        return
    variant_name = _choose_variant(spec, "Main", "Modify implementations")
    if variant_name is None:
        return

    implementation = VARIANTS[spec.variant_key][variant_name]
    source = textwrap.dedent(inspect.getsource(implementation))
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    slot = spec.function.__caretaker_target__.slot

    print(
        "\nWARNING: this lab action deliberately bypasses Repair candidate generation "
        "and validation. It directly activates a FunctionSlot version to simulate "
        "runtime code substitution. Guard may identify it as a changed candidate and "
        "may roll it back after execution."
    )
    answer = input("Inject this implementation? [y/N]: ").strip().lower()
    if answer != "y":
        return

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

    print(
        f"Injected {variant_name!r} into {spec.target_id}; "
        f"FunctionSlot version is now {version.number}."
    )
    print(
        "Execute the target once, then inspect Guard runtime inspections, decisions, "
        "candidate state, and Repair/rollback events."
    )


def rollback_one_version() -> None:
    spec = _choose_target("Main", "Modify implementations")
    if spec is None:
        return
    slot = spec.function.__caretaker_target__.slot
    current = slot.load()
    previous = slot.previous()
    if previous is None:
        print("No previous FunctionSlot version exists.")
        return
    failed = slot.rollback(current.number)
    print(
        f"Rolled back version {failed.number}; active version is now {slot.load().number}."
    )


def restore_original_dispatcher() -> None:
    spec = _choose_target("Main", "Modify implementations")
    if spec is None:
        return
    restore_code_object(spec)
    slot = spec.function.__caretaker_target__.slot
    count = 0
    while slot.previous() is not None:
        slot.rollback(slot.load().number)
        count += 1
    ACTIVE_VARIANTS[spec.variant_key] = "benign"
    print(
        f"Restored {spec.target_id} to its oldest available FunctionSlot version "
        f"after {count} rollback(s); dispatcher behavior is benign."
    )


def reset_all_behavior_substitutions() -> None:
    for key in ACTIVE_VARIANTS:
        ACTIVE_VARIANTS[key] = "benign"
    print("All dispatcher behavior substitutions are now benign.")



def modification_menu() -> None:
    while True:
        _menu_header(
            "Main",
            "Modify implementations",
            title="Implementation modification menu",
        )
        print("1. Change behavior substitution (stable FunctionSlot remains unchanged)")
        print("2. Mutate the active dispatcher's __code__ object (simulated tampering)")
        print("3. Inject a variant directly into the FunctionSlot")
        print("4. Roll back one FunctionSlot version")
        print("5. Restore target to oldest version + original code + benign dispatcher")
        print("6. Reset all dispatcher substitutions to benign")
        print("0. Return to main menu")

        choice = input("Selection: ").strip()
        try:
            if choice == "1":
                change_behavior_substitution()
            elif choice == "2":
                mutate_active_code_object()
            elif choice == "3":
                inject_slot_variant()
            elif choice == "4":
                rollback_one_version()
            elif choice == "5":
                restore_original_dispatcher()
            elif choice == "6":
                reset_all_behavior_substitutions()
            elif choice == "0":
                return
            else:
                print("Unknown selection.")
        except Exception as exc:
            print(f"Modification failed: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Live lab console
# ---------------------------------------------------------------------------


def _active_log_directory() -> Path:
    runtime = get_logging_runtime()
    if runtime is None:
        return LOCAL_LOG_DIRECTORY
    return Path(runtime.active_policy.directory)


def _lab_console_socket_path() -> Path:
    return _active_log_directory() / "run" / "lab-console.sock"


def _resolve_console_target(value: str | None) -> TargetSpec | None:
    if value is None or value in {"", "all", "*"}:
        return None
    for spec in TARGETS.values():
        if value in {spec.key, spec.variant_key, spec.target_id}:
            return spec
    raise KeyError(f"Unknown target {value!r}; use the console 'targets' command")


def _jsonable(value: Any) -> Any:
    import dataclasses
    from datetime import datetime
    from enum import Enum
    from uuid import UUID

    if dataclasses.is_dataclass(value):
        return {
            field.name: _jsonable(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Enum):
        return value.name
    if isinstance(value, (UUID, Path)):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_jsonable(item) for item in value]
    if callable(value):
        return f"{getattr(value, '__module__', '')}.{getattr(value, '__qualname__', repr(value))}"
    return value


def _console_target_state(spec: TargetSpec) -> dict[str, Any]:
    target = spec.function.__caretaker_target__
    return {
        "menu_key": spec.key,
        "title": spec.title,
        "target_id": spec.target_id,
        "behavior_substitution": ACTIVE_VARIANTS[spec.variant_key],
        "code_mutation": CODE_MUTATIONS.get(spec.target_id),
        "slot": target.slot.snapshot(),
    }


def _console_target_policy(spec: TargetSpec) -> dict[str, Any]:
    policy = spec.function.__caretaker_target__.policy
    return {
        "target_id": spec.target_id,
        "repair_mode": policy.mode.name,
        "repair_authority": policy.authority.name,
        "triggers": [type(item).__name__ for item in policy.triggers],
        "retry_attempts": policy.retry.max_attempts,
        "replay_safety": policy.retry.safety.name,
        "logging": {
            "enabled": policy.logging.enabled,
            "calls": policy.logging.capture_calls,
            "exceptions": policy.logging.capture_exceptions,
            "timing": policy.logging.capture_timing,
            "arguments": policy.logging.capture_arguments,
            "results": policy.logging.capture_results,
        },
        "guard": {
            "enabled": policy.guard.enabled,
            "network": policy.guard.observe_network,
            "filesystem": policy.guard.observe_filesystem,
            "subprocesses": policy.guard.observe_subprocesses,
            "imports": policy.guard.observe_imports,
            "deviation_action": policy.guard.deviation_action.name,
        },
        "candidate_guard": {
            "allow_new_capabilities": policy.candidate_guard.allow_new_capabilities,
            "rollback_on_significant_deviation": policy.candidate_guard.rollback_on_significant_deviation,
        },
    }


def _console_guard_inspections(spec: TargetSpec, limit: int) -> list[Any]:
    module_name = spec.function.__caretaker_target__.source.module_name
    inspections = GUARD.store.recent_inspections(module_name, limit=max(limit * 3, 50))
    names = {
        spec.function.__caretaker_target__.source.qualified_name,
        VARIANTS[spec.variant_key]["benign"].__qualname__,
        VARIANTS[spec.variant_key]["bad"].__qualname__,
        VARIANTS[spec.variant_key]["malicious"].__qualname__,
    }
    return [item for item in inspections if item.subject.qualified_name in names][-limit:]


def _console_log_records(limit: int) -> list[dict[str, Any]]:
    event_directory = _active_log_directory() / "application" / "events"
    paths = sorted(event_directory.glob("*.ctlog")) + sorted(
        event_directory.glob("*.ctlog.gz")
    )
    records = []
    for path in paths[-6:]:
        try:
            records.extend(read_segment(path))
        except Exception:
            continue
    return [
        {
            "time": record.occurred_at.isoformat(),
            "channel": record.channel.name,
            "severity": record.severity,
            "logger": record.logger_name,
            "message": record.formatted_message or record.message_template,
            "target_id": str(record.target_id or record.fields.get("target_id", "")),
            "event": str(record.fields.get("event", "")),
            "fields": _jsonable(dict(record.fields)),
        }
        for record in records[-limit:]
    ]


def _lab_console_handler(
    request: dict[str, Any],
    credentials: tuple[int, int, int],
) -> dict[str, Any]:
    command = str(request.get("command", "")).strip().lower()
    target_value = request.get("target")
    limit = max(1, min(int(request.get("limit", 30)), 200))

    if command == "status":
        return {
            "ok": True,
            "pid": os.getpid(),
            "peer_pid": credentials[0],
            "supervised": os.environ.get("CARETAKER_SUPERVISED") == "1",
            "workspace": str(WORKSPACE),
            "data_directory": str(_active_log_directory()),
            "console_socket": str(_lab_console_socket_path()),
            "pending_approvals": len(ENGINE.pending_approvals()),
            "guard_decisions": len(GUARD.decisions),
            "collector_events": len(COLLECTOR_EVENTS),
        }

    if command == "targets":
        return {"ok": True, "targets": [_console_target_state(spec) for spec in TARGETS.values()]}

    if command in {"state", "policy", "summary", "deviations", "inspections", "baseline-accept"}:
        spec = _resolve_console_target(str(target_value or ""))
        if spec is None:
            raise ValueError(f"{command} requires a target")
        if command == "state":
            return {"ok": True, "state": _console_target_state(spec)}
        if command == "policy":
            return {"ok": True, "policy": _console_target_policy(spec)}
        if command == "summary":
            summary = GUARD.recent_summary(spec.target_id, calls=20)
            return {"ok": True, "target_id": spec.target_id, "summary": _jsonable(summary)}
        if command == "deviations":
            deviations = list(
                getattr(GUARD, "_deviations_by_target", {}).get(spec.target_id, ())
            )
            return {
                "ok": True,
                "target_id": spec.target_id,
                "deviations": _jsonable(deviations[-limit:]),
            }
        if command == "inspections":
            return {
                "ok": True,
                "target_id": spec.target_id,
                "inspections": _jsonable(_console_guard_inspections(spec, limit)),
            }
        baseline = GUARD.accept_baseline(spec.target_id)
        return {"ok": True, "target_id": spec.target_id, "baseline": _jsonable(baseline)}

    if command == "events":
        spec = _resolve_console_target(str(target_value)) if target_value else None
        events = GUARD.store.recent_behavior_events(
            target_id=spec.target_id if spec is not None else None,
            limit=limit,
        )
        return {
            "ok": True,
            "target_id": spec.target_id if spec is not None else None,
            "events": _jsonable(events),
        }

    if command == "decisions":
        return {"ok": True, "decisions": _jsonable(GUARD.decisions[-limit:])}

    if command == "repair-events":
        spec = _resolve_console_target(str(target_value)) if target_value else None
        events = ENGINE.store.recent_events(
            spec.target_id if spec is not None else None,
            limit=limit,
        )
        return {
            "ok": True,
            "target_id": spec.target_id if spec is not None else None,
            "events": _jsonable(events),
        }

    if command == "approvals":
        return {"ok": True, "approvals": _jsonable(ENGINE.pending_approvals())}

    if command in {"approve", "reject"}:
        from uuid import UUID

        episode_id = UUID(str(request["episode_id"]))
        if command == "approve":
            activated = ENGINE.approve_repair(episode_id)
            return {
                "ok": True,
                "episode_id": str(episode_id),
                "activated_version": activated.number,
            }
        reason = str(request.get("reason") or "interactive lab rejection")
        ENGINE.reject_repair(episode_id, reason)
        return {"ok": True, "episode_id": str(episode_id), "reason": reason}

    if command == "logs":
        return {
            "ok": True,
            "data_directory": str(_active_log_directory()),
            "records": _console_log_records(limit),
        }

    if command == "collector":
        return {"ok": True, "events": list(COLLECTOR_EVENTS[-limit:])}

    return {"ok": False, "error": f"unsupported lab console command: {command!r}"}


def start_lab_console() -> None:
    global LAB_CONSOLE_SERVER, LAB_CONSOLE_THREAD

    server = ControlSocketServer(
        _lab_console_socket_path(),
        _lab_console_handler,
        allowed_uids={os.getuid()},
    )
    server.start()
    thread = threading.Thread(
        target=server.serve_forever,
        name="caretaker-interactive-lab-console",
        daemon=True,
    )
    thread.start()
    LAB_CONSOLE_SERVER = server
    LAB_CONSOLE_THREAD = thread


def stop_lab_console() -> None:
    global LAB_CONSOLE_SERVER, LAB_CONSOLE_THREAD

    if LAB_CONSOLE_SERVER is not None:
        LAB_CONSOLE_SERVER.stop()
    if LAB_CONSOLE_THREAD is not None:
        LAB_CONSOLE_THREAD.join(timeout=1.0)
    LAB_CONSOLE_SERVER = None
    LAB_CONSOLE_THREAD = None


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


def print_banner() -> None:
    assert SERVERS is not None
    print(
        f"""
Caretaker interactive behavior laboratory
=========================================

Workspace:          {WORKSPACE}
Caretaker data:     {_active_log_directory()}
Lab console socket: {_lab_console_socket_path()}
Local webpage/API:  {SERVERS.application_base}
Synthetic collector:{SERVERS.collector_base}
Supervised:         {os.environ.get('CARETAKER_SUPERVISED') == '1'}

Observe from another terminal
-----------------------------
PYTHONPATH=src:. python -m examples.interactive_caretaker_lab_console

The menu drives application behavior only. Use the attached lab console to
inspect Guard events, Repair events, pending approvals, logs, target state, and
accepted baselines. Type 'help' in that console for commands.

Safety boundary
---------------
The 'malicious' implementations are contained simulations. They read only the
synthetic demo secret under the workspace, write only lab-owned marker files,
run a fixed harmless Python child process, and send only a SHA-256 digest to the
second loopback server. They do not delete files or transmit data off-host.

Suggested first experiment
--------------------------
1. In this menu, run a target with its benign implementation.
2. In the lab console, inspect its Guard events and optionally accept a baseline.
3. Here, change the target's behavior substitution to malicious.
4. Run the same target again.
5. In the console, compare events, deviations, inspections, and Repair state.
6. Restore the original/benign implementation before moving to the next target.

For Repair, try division with the bad implementation, then use the lab console's
'approvals' and 'approve <episode-id>' commands. Text transform demonstrates an
automatic eligible repair and retry.

This lab logs function arguments/results. Do not enter real credentials or
sensitive data.
""".strip()
    )


def main() -> None:
    global SERVERS

    initialize_workspace()
    runtime, owns_runtime = initialize_logging()
    logging.getLogger().setLevel(logging.INFO)

    SERVERS = LabServers()
    SERVERS.start()
    _build_target_specs()
    GUARD.install(import_hook=False, periodic=False)
    start_lab_console()

    print_banner()
    try:
        while True:
            _menu_header("Main", title="Application behavior menu")
            for key, spec in TARGETS.items():
                print(
                    f"{key}. {spec.title:<39} "
                    f"[{ACTIVE_VARIANTS[spec.variant_key]}]"
                )
            print("9. Modify / inject function implementations")
            print("0. Quit")

            choice = input("Selection: ").strip()
            if choice in TARGETS:
                execute_target(TARGETS[choice])
            elif choice == "9":
                modification_menu()
            elif choice == "0":
                return
            else:
                print("Unknown selection.")
    except (EOFError, KeyboardInterrupt):
        print("\nExiting interactive lab.")
    finally:
        stop_lab_console()
        GUARD.close()
        if SERVERS is not None:
            SERVERS.close()
        if owns_runtime:
            runtime.close()


if __name__ == "__main__":
    main()
