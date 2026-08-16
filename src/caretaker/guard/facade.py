from __future__ import annotations

from collections.abc import Callable
from typing import Mapping, Protocol
from uuid import UUID

from .models import (
    BehavioralCandidateScore,
    BehaviorProfileSummary,
    GuardEvidenceBundle,
    GuardMode,
    InstrumentationLease,
)
from .policy import GuardBinding
from .policy import CandidateGuardPolicy


class GuardFacade(Protocol):
    def register_target(
        self,
        target_id: str,
        function: Callable,
        binding: GuardBinding,
        function_resolver: Callable[[], Callable] | None = None,
        *,
        periodic: bool = True,
        monitoring_configuration: Mapping[str, object] | None = None,
    ) -> None: ...

    def before_call(
        self,
        target_id: str,
        function: Callable,
        call_id: UUID,
        *,
        candidate_id: UUID | None,
    ) -> None: ...

    def after_call(
        self,
        target_id: str,
        function: Callable,
        call_id: UUID,
        *,
        candidate_id: UUID | None,
        succeeded: bool,
        elapsed_seconds: float,
    ) -> None: ...

    def recent_summary(self, target_id: str, *, calls: int = 20) -> BehaviorProfileSummary | None: ...

    def evidence_bundle(self, target_id: str, *, calls: int = 20) -> GuardEvidenceBundle | None: ...

    def request_instrumentation(
        self,
        target_id: str,
        mode: GuardMode,
        *,
        execution_count: int,
        reason: str,
    ) -> InstrumentationLease: ...

    def evaluate_candidate(
        self,
        target_id: str,
        candidate_source: str,
        *,
        candidate_id: UUID | None = None,
        policy: CandidateGuardPolicy | None = None,
    ) -> BehavioralCandidateScore: ...

    def candidate_deviated(self, candidate_id: UUID) -> bool: ...
