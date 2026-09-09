from __future__ import annotations

import threading
import time
import math
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from caretaker import (
    LLMRequestGate,
    LLMUsageLimitError,
    LLMUsagePolicy,
    RuntimeInteractionPolicy,
    RuntimeJobRegistry,
    RuntimeJobState,
    RuntimeJob,
    SQLiteRuntimeJobStore,
)
from caretaker.logging.policy import load_operator_policy


def _wait_for_state(registry, job_id, state: RuntimeJobState) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if registry.status(job_id).state is state:
            return
        time.sleep(0.005)
    assert registry.status(job_id).state is state


def test_long_job_returns_bounded_result_and_status() -> None:
    registry = RuntimeJobRegistry(
        interaction_policy=RuntimeInteractionPolicy(maximum_job_result_bytes=1024)
    )
    try:
        job = registry.submit(
            "test-operation",
            client_id="uid:1000",
            operation=lambda context: {"ok": True, "value": "done"},
        )
        _wait_for_state(registry, job.job_id, RuntimeJobState.SUCCEEDED)
        status = registry.status(job.job_id)
        assert status.public_dict()["result"] == {"ok": True, "value": "done"}
    finally:
        registry.close()


def test_active_capacity_queues_and_queued_cancel_is_terminal() -> None:
    started = threading.Event()
    release = threading.Event()
    registry = RuntimeJobRegistry(
        interaction_policy=RuntimeInteractionPolicy(
            maximum_long_jobs=1,
            maximum_active_jobs_per_client=1,
            maximum_pending_jobs=1,
        )
    )
    try:
        first = registry.submit(
            "first",
            client_id="uid:1000",
            operation=lambda context: (
                started.set(),
                release.wait(2.0),
                context.checkpoint(),
                {"first": True},
            )[-1],
        )
        _wait_for_state(registry, first.job_id, RuntimeJobState.RUNNING)
        second = registry.submit(
            "second",
            client_id="uid:1001",
            operation=lambda context: {"second": True},
        )
        _wait_for_state(registry, second.job_id, RuntimeJobState.QUEUED)
        cancelled = registry.cancel(second.job_id)
        assert cancelled.state is RuntimeJobState.CANCELLED
        release.set()
        _wait_for_state(registry, first.job_id, RuntimeJobState.SUCCEEDED)
        assert registry.status(second.job_id).state is RuntimeJobState.CANCELLED
    finally:
        release.set()
        registry.close()


def test_long_job_result_size_is_fail_closed() -> None:
    registry = RuntimeJobRegistry(
        interaction_policy=RuntimeInteractionPolicy(maximum_job_result_bytes=32)
    )
    try:
        job = registry.submit(
            "oversized",
            client_id="uid:1000",
            operation=lambda context: {"value": "x" * 100},
        )
        _wait_for_state(registry, job.job_id, RuntimeJobState.FAILED)
        assert "exceeds" in (registry.status(job.job_id).error or "")
    finally:
        registry.close()


def test_long_job_nonfinite_result_is_fail_closed() -> None:
    registry = RuntimeJobRegistry(
        interaction_policy=RuntimeInteractionPolicy(maximum_job_result_bytes=1024)
    )
    try:
        job = registry.submit(
            "nonfinite",
            client_id="uid:1000",
            operation=lambda context: {"value": math.nan},
        )
        _wait_for_state(registry, job.job_id, RuntimeJobState.FAILED)
        assert "Out of range" in (registry.status(job.job_id).error or "")
    finally:
        registry.close()


def test_long_job_progress_is_bounded_and_restart_visible(tmp_path) -> None:
    store = SQLiteRuntimeJobStore(tmp_path / "control-jobs.sqlite")
    registry = RuntimeJobRegistry(job_store=store)
    try:
        job = registry.submit(
            "progress-operation",
            client_id="uid:1000",
            operation=lambda context: (
                context.report_progress({"completed": 1, "total": 2}),
                {"ok": True},
            )[-1],
        )
        _wait_for_state(registry, job.job_id, RuntimeJobState.SUCCEEDED)
        assert registry.status(job.job_id).progress == {"completed": 1, "total": 2}
    finally:
        registry.close()

    restarted = RuntimeJobRegistry(job_store=store)
    try:
        restored = restarted.status(job.job_id)
        assert restored.state is RuntimeJobState.SUCCEEDED
        assert restored.progress == {"completed": 1, "total": 2}
        assert restored.public_dict()["result"] == {"ok": True}
    finally:
        restarted.close()


def test_restart_marks_persisted_active_job_interrupted(tmp_path) -> None:
    store = SQLiteRuntimeJobStore(tmp_path / "control-jobs.sqlite")
    job = RuntimeJob(
        job_id=uuid4(),
        command="unfinished-operation",
        client_id="uid:1000",
        submitted_at=datetime.now(timezone.utc),
        state=RuntimeJobState.RUNNING,
        started_at=datetime.now(timezone.utc),
        progress={"phase": "working"},
    )
    store.save(job)

    registry = RuntimeJobRegistry(job_store=store)
    try:
        restored = registry.status(job.job_id)
        assert restored.state is RuntimeJobState.INTERRUPTED
        assert restored.progress == {"phase": "working"}
        assert "restarted" in (restored.error or "")
    finally:
        registry.close()


def test_llm_gate_enforces_concurrency_and_rate_without_queueing() -> None:
    gate = LLMRequestGate(
        LLMUsagePolicy(maximum_requests_per_minute=1, maximum_concurrent_requests=1)
    )
    entered = threading.Event()
    release = threading.Event()

    def hold_request() -> None:
        with gate.request():
            entered.set()
            release.wait(2.0)

    thread = threading.Thread(target=hold_request)
    thread.start()
    assert entered.wait(1.0)
    with pytest.raises(LLMUsageLimitError, match="concurrent-request"):
        with gate.request():
            pass
    release.set()
    thread.join(timeout=2.0)
    with pytest.raises(LLMUsageLimitError, match="rate limit"):
        with gate.request():
            pass


def test_operator_policy_loads_job_and_llm_limits(tmp_path) -> None:
    path = tmp_path / "policy.toml"
    path.write_text(
        """
[logging]
directory = "./data"

[logging.control_plane]
maximum_long_jobs = 3
maximum_pending_jobs = 12
maximum_job_result_bytes = 65536

[logging.llm_usage]
maximum_requests_per_minute = 4
maximum_concurrent_requests = 2
""",
        encoding="utf-8",
    )
    policy, _ = load_operator_policy(path)
    assert policy.control_plane.maximum_long_jobs == 3
    assert policy.control_plane.maximum_pending_jobs == 12
    assert policy.llm_usage == LLMUsagePolicy(
        maximum_requests_per_minute=4,
        maximum_concurrent_requests=2,
    )
