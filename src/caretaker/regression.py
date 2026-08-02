from __future__ import annotations

import copy
from collections import defaultdict, deque
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from .domain import RegisteredCase, RegressionCase


class RegressionCorpus:
    """Bounded runtime corpus of previously successful repair examples.

    The corpus intentionally stores live replay values only in memory. Persistent stores
    receive metadata events, not arbitrary application objects.
    """

    def __init__(self, maximum_cases_per_target: int = 100) -> None:
        self.maximum_cases_per_target = maximum_cases_per_target
        self._cases: dict[str, deque[RegressionCase]] = defaultdict(
            lambda: deque(maxlen=maximum_cases_per_target)
        )
        self._lock = RLock()

    def add_successful_replay(
        self,
        *,
        target_id: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        expected: Any,
        incident_id: UUID | None,
        candidate_id: UUID | None,
        name: str | None = None,
    ) -> RegressionCase | None:
        try:
            case = RegressionCase(
                case_id=uuid4(),
                target_id=target_id,
                name=name or f"repaired-incident-{str(incident_id)[:8] if incident_id else 'unknown'}",
                args=copy.deepcopy(args),
                kwargs=copy.deepcopy(kwargs),
                expected=copy.deepcopy(expected),
                source_incident_id=incident_id,
                source_candidate_id=candidate_id,
            )
        except Exception:
            return None
        with self._lock:
            self._cases[target_id].append(case)
        return case

    def cases_for_target(self, target_id: str) -> tuple[RegressionCase, ...]:
        with self._lock:
            return tuple(self._cases.get(target_id, ()))

    def registered_cases_for_target(self, target_id: str) -> tuple[RegisteredCase, ...]:
        return tuple(
            RegisteredCase(
                name=f"regression:{case.name}",
                args=case.args,
                kwargs=case.kwargs,
                expected=case.expected,
            )
            for case in self.cases_for_target(target_id)
        )
