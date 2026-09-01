"""Policy-controlled limits for advisory LLM requests.

The limiter is deliberately local to one Caretaker process.  It is a resource
and abuse-control boundary, not an authority mechanism: a permit never grants
the caller permission to change policy, evidence, or runtime behavior.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from time import monotonic
from collections import deque
from typing import Iterator


@dataclass(frozen=True, slots=True)
class LLMUsagePolicy:
    """Bounds for calls to an advisory language-model provider."""

    maximum_requests_per_minute: int = 6
    maximum_concurrent_requests: int = 1

    def __post_init__(self) -> None:
        if (
            isinstance(self.maximum_requests_per_minute, bool)
            or not isinstance(self.maximum_requests_per_minute, int)
            or self.maximum_requests_per_minute <= 0
        ):
            raise ValueError("maximum_requests_per_minute must be a positive integer")
        if (
            isinstance(self.maximum_concurrent_requests, bool)
            or not isinstance(self.maximum_concurrent_requests, int)
            or self.maximum_concurrent_requests <= 0
        ):
            raise ValueError("maximum_concurrent_requests must be a positive integer")


class LLMUsageLimitError(RuntimeError):
    """Raised when an LLM request is rejected by the configured budget."""


class LLMRequestGate:
    """A thread-safe, fail-fast rate and concurrency gate.

    Requests are rejected rather than queued.  This keeps an event hook or a
    historical batch from accumulating hidden work while a local model is
    saturated.  Callers can expose the rejection as evidence and retry under
    their own explicit policy.
    """

    def __init__(self, policy: LLMUsagePolicy | None = None) -> None:
        self.policy = policy or LLMUsagePolicy()
        self._lock = RLock()
        self._request_times: deque[float] = deque()
        self._active = 0

    @property
    def active_requests(self) -> int:
        with self._lock:
            return self._active

    @property
    def recent_requests(self) -> int:
        with self._lock:
            self._prune(monotonic())
            return len(self._request_times)

    def _prune(self, now: float) -> None:
        cutoff = now - 60.0
        while self._request_times and self._request_times[0] <= cutoff:
            self._request_times.popleft()

    @contextmanager
    def request(self) -> Iterator[None]:
        now = monotonic()
        with self._lock:
            self._prune(now)
            if self._active >= self.policy.maximum_concurrent_requests:
                raise LLMUsageLimitError(
                    "LLM concurrent-request limit reached "
                    f"({self.policy.maximum_concurrent_requests})"
                )
            if len(self._request_times) >= self.policy.maximum_requests_per_minute:
                raise LLMUsageLimitError(
                    "LLM request rate limit reached "
                    f"({self.policy.maximum_requests_per_minute} per minute)"
                )
            self._active += 1
            self._request_times.append(now)
        try:
            yield
        finally:
            with self._lock:
                self._active = max(0, self._active - 1)
