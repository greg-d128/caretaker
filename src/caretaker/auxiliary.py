from __future__ import annotations

import ast
import hashlib
from collections.abc import Callable
from dataclasses import replace
from threading import RLock
from typing import Any
from uuid import uuid4

from .domain import AuxiliaryArtifact, AuxiliaryArtifactKind, CandidateState, SlotRole, utcnow
from .slot import FunctionSlot
from .validation import SubprocessValidationBackend


class AuxiliaryRegistry:
    def __init__(self) -> None:
        self._slots: dict[str, FunctionSlot] = {}
        self._artifacts: dict[str, AuxiliaryArtifact] = {}
        self._lock = RLock()

    def register(self, artifact_id: str, slot: FunctionSlot, artifact: AuxiliaryArtifact) -> None:
        with self._lock:
            self._slots[artifact_id] = slot
            self._artifacts[artifact_id] = artifact

    def resolve(self, artifact_id: str) -> Callable[..., Any]:
        with self._lock:
            slot = self._slots[artifact_id]
            return slot.load().implementation  # type: ignore[return-value]


    def register_callable(
        self,
        artifact_id: str,
        implementation: Callable[..., Any],
        *,
        role: SlotRole = SlotRole.OUTPUT_COMPARATOR,
    ) -> FunctionSlot:
        source = None
        source_hash = None
        try:
            import inspect
            source = inspect.getsource(implementation)
            source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        except (OSError, TypeError):
            pass
        slot = FunctionSlot(
            target_id=artifact_id,
            original=implementation,
            original_source=source,
            original_source_hash=source_hash,
            role=role,
        )
        with self._lock:
            self._slots[artifact_id] = slot
        return slot

    def artifact(self, artifact_id: str) -> AuxiliaryArtifact:
        with self._lock:
            return self._artifacts[artifact_id]


class AuxiliaryFunctionManager:
    def __init__(
        self,
        registry: AuxiliaryRegistry,
        backend: SubprocessValidationBackend | None = None,
    ) -> None:
        self.registry = registry
        self.backend = backend or SubprocessValidationBackend()

    def install_output_validator(
        self,
        *,
        target_id: str,
        source: str,
        entrypoint: str,
        valid_examples: tuple[Any, ...],
        invalid_examples: tuple[Any, ...],
        maximum_runtime_seconds: float = 0.005,
        validation_timeout_seconds: float = 30.0,
        artifact_id: str | None = None,
    ) -> AuxiliaryArtifact:
        result = self.backend.validate_auxiliary(
            source=source,
            entrypoint=entrypoint,
            valid_examples=valid_examples,
            invalid_examples=invalid_examples,
            timeout_seconds=validation_timeout_seconds,
            maximum_runtime_seconds=maximum_runtime_seconds,
        )
        if not result.get("eligible", False):
            raise ValueError(f"Auxiliary validator failed validation: {result.get('checks')}")
        tree = ast.parse(source)
        namespace: dict[str, Any] = {}
        exec(compile(tree, "<caretaker-auxiliary>", "exec", dont_inherit=True), namespace, namespace)
        implementation = namespace[entrypoint]
        source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        resolved_id = artifact_id or f"{target_id}:validator:{source_hash[:12]}"
        slot = FunctionSlot(
            target_id=resolved_id,
            original=implementation,
            original_source=source,
            original_source_hash=source_hash,
            role=SlotRole.OUTPUT_VALIDATOR,
        )
        artifact = AuxiliaryArtifact(
            artifact_id=uuid4(),
            registry_id=resolved_id,
            target_id=target_id,
            kind=AuxiliaryArtifactKind.OUTPUT_VALIDATOR,
            version=0,
            source=source,
            source_hash=source_hash,
            entrypoint=entrypoint,
            generation_id=None,
            parent_artifact_ids=(),
            validation_profile_id="strict-auxiliary-validator-v1",
            created_at=utcnow(),
            accepted_at=utcnow(),
            state=CandidateState.LONG_TERM_ACCEPTED,
        )
        self.registry.register(resolved_id, slot, artifact)
        return artifact
