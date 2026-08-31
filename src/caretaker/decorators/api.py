from __future__ import annotations

import functools
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar, overload
from uuid import uuid4

from ..authority import get_authority_runtime_context
from ..contracts import normalize_validation_result
from ..domain import (
    DifferentialEvidence,
    RepairMode,
    ReplaySafety,
    TargetCapability,
    TimeoutMode,
    ValidatorErrorBehavior,
)
from ..engine import RepairEngine, ResolutionKind
from ..execution import FunctionExecutionContract
from ..integrity.models import IntegrityClass
from ..logging.handler import get_runtime as get_logging_runtime
from ..logging.masking import MaskFunction, apply_mask
from ..logging.models import LogChannel
from ..observation import DifferentialMismatchError
from ..policy import (
    DEFAULT_POLICY,
    ExceptionTrigger,
    OutputValidationTrigger,
    RepairPolicy,
    RetryPolicy,
    TimeoutTrigger,
)
from ..registry import RepairTarget, build_target
from ..runtime import set_runtime_context
from ..state import exception_evidence, value_snapshot


F = TypeVar("F", bound=Callable[..., Any])
_NO_RESULT = object()


def _unwrap_descriptor(value: Any) -> tuple[Callable[..., Any], Callable[[Any], Any]]:
    """Return a callable and a descriptor-preserving wrapper constructor."""
    if isinstance(value, classmethod):
        return value.__func__, classmethod
    if isinstance(value, staticmethod):
        return value.__func__, staticmethod
    if isinstance(value, property):
        if value.fget is None:
            raise TypeError("@repair requires a property getter")
        return value.fget, lambda wrapper: property(
            wrapper, value.fset, value.fdel, value.__doc__
        )
    if not callable(value):
        raise TypeError("@repair requires a function or supported descriptor")
    return value, lambda wrapper: wrapper


def _result_evidence(value: Any) -> dict[str, Any]:
    """Return bounded, data-only evidence for an observed successful result."""
    snapshot = value_snapshot(value, max_length=512)
    return {
        "type_name": snapshot.type_name,
        "representation": snapshot.representation,
        "value_hash": snapshot.value_hash,
        "truncated": snapshot.truncated,
        "redacted": snapshot.redacted,
        "size_bytes": snapshot.size_bytes,
    }


class InvalidOutputError(RuntimeError):
    pass


_default_engine = RepairEngine()


def get_default_engine() -> RepairEngine:
    return _default_engine


def configure_default_engine(engine: RepairEngine) -> None:
    global _default_engine
    _default_engine = engine


@overload
def repair(function: F) -> F: ...


@overload
def repair(
    function: None = None,
    *,
    policy: RepairPolicy | None = None,
    engine: RepairEngine | None = None,
    target_id: str | None = None,
    cases: tuple[Any, ...] = (),
    tags: frozenset[str] = frozenset(),
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY,
    mask: MaskFunction | None = None,
    execution_contract: FunctionExecutionContract | None = None,
) -> Callable[[F], F]: ...


def repair(
    function: F | None = None,
    *,
    policy: RepairPolicy | None = None,
    engine: RepairEngine | None = None,
    target_id: str | None = None,
    cases: tuple[Any, ...] = (),
    tags: frozenset[str] = frozenset(),
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY,
    mask: MaskFunction | None = None,
    execution_contract: FunctionExecutionContract | None = None,
) -> F | Callable[[F], F]:
    """Register a synchronous function for incident capture and in-memory repair."""

    def decorate(original: F) -> F:
        callable_original, rebuild_descriptor = _unwrap_descriptor(original)
        selected_engine = engine or get_default_engine()
        declared_policy = policy or DEFAULT_POLICY
        resolved_target_id = target_id or f"{callable_original.__module__}:{callable_original.__qualname__}"
        selected_policy = get_authority_runtime_context().apply(
            declared_policy, prefix="repair", target_id=resolved_target_id
        )
        target = build_target(
            callable_original,
            policy=selected_policy,
            target_id=target_id,
            registered_cases=tuple(cases),
            tags=tags,
            integrity_class=integrity_class,
            mask_function=mask,
            execution_contract=execution_contract,
        )
        selected_engine.register(target, declared_policy=declared_policy)

        registered_target_id = target.target_id

        @functools.wraps(callable_original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Authority policy generations can replace the immutable RepairTarget
            # in the registry. Resolve it at each call rather than pinning the
            # decoration-time policy forever.
            runtime_target = selected_engine.registry.get(registered_target_id)
            call_id = uuid4()
            tokens = set_runtime_context(
                target_id=runtime_target.target_id,
                call_id=call_id,
                operation="function-call",
            )
            started_at = datetime.now(timezone.utc)
            started_counter = time.perf_counter()
            version = runtime_target.slot.load()
            call_state = selected_engine.state_capture.capture_before(
                version.implementation,
                args,
                kwargs,
                runtime_target.policy.state,
            )
            masked_input = apply_mask(runtime_target.mask_function, args, kwargs)
            if runtime_target.mask_function is not None and call_state.bound_arguments:
                try:
                    masked_bound = inspect.signature(version.implementation).bind_partial(
                        *masked_input.masked_args, **dict(masked_input.masked_kwargs)
                    )
                    masked_bound.apply_defaults()
                    call_state.bound_arguments = {
                        name: value_snapshot(value, name=name)
                        for name, value in masked_bound.arguments.items()
                    }
                except Exception as masking_exc:
                    call_state.bound_arguments = {
                        "<masking-error>": value_snapshot(masking_exc)
                    }
            logging_runtime = get_logging_runtime()
            if logging_runtime is not None and runtime_target.policy.logging.enabled and runtime_target.policy.logging.capture_calls:
                logging_fields = {
                    "event": "repair.function.call.started",
                    "target_id": runtime_target.target_id,
                    "function_version": version.number,
                    "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                    "masking": {
                        "fully_removed_fields": masked_input.fully_removed_fields,
                        "format_preserved_fields": masked_input.format_preserved_fields,
                        "structural_metadata": masked_input.structural_metadata,
                    },
                }
                if runtime_target.policy.logging.capture_arguments:
                    logging_fields["args"] = masked_input.masked_args
                    logging_fields["kwargs"] = dict(masked_input.masked_kwargs)
                logging_runtime.event(
                    logger_name=callable_original.__module__, severity=10,
                    channel=LogChannel.REPAIR,
                    message=f"Repair-enabled call started: {runtime_target.target_id}",
                    fields=logging_fields,
                    function_version=version.number,
                )
            guard_started = False
            completed_output: Any = _NO_RESULT
            pending = selected_engine.handle_pending_guard_signal(
                target=runtime_target,
                version=version,
                function=version.implementation,
                args=args,
                kwargs=kwargs,
                call_state=call_state,
                call_id=call_id,
                started_at=started_at,
            )
            if pending is not None:
                if pending.kind == ResolutionKind.RETRY_SUCCEEDED:
                    completed_output = pending.retry_output
                    if (
                        logging_runtime is not None
                        and runtime_target.policy.logging.enabled
                        and (
                            runtime_target.policy.logging.capture_calls
                            or runtime_target.policy.logging.capture_results
                        )
                    ):
                        completed_fields: dict[str, Any] = {
                            "event": "repair.function.call.completed",
                            "target_id": runtime_target.target_id,
                            "function_version": version.number,
                            "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                            "succeeded": True,
                            "elapsed_seconds": (
                                time.perf_counter() - started_counter
                                if runtime_target.policy.logging.capture_timing
                                else None
                            ),
                        }
                        if runtime_target.policy.logging.capture_results:
                            completed_fields["result"] = _result_evidence(completed_output)
                        logging_runtime.event(
                            logger_name=callable_original.__module__, severity=10,
                            channel=LogChannel.REPAIR,
                            message=f"Repair-enabled call completed: {runtime_target.target_id}",
                            fields=completed_fields,
                            function_version=version.number,
                        )
                    tokens.reset()
                    return completed_output
                version = runtime_target.slot.load()
                call_state = selected_engine.state_capture.capture_before(
                    version.implementation,
                    args,
                    kwargs,
                    runtime_target.policy.state,
                )
            if selected_engine.guard is not None and runtime_target.policy.guard.enabled:
                selected_engine.guard.before_call(
                    runtime_target.target_id,
                    version.implementation,
                    call_id,
                    candidate_id=version.candidate_id,
                )
                guard_started = True
            try:
                differential = runtime_target.policy.observation.differential_execution
                observation = runtime_target.slot.observation()
                previous = runtime_target.slot.previous()
                if (
                    version.candidate_id is not None
                    and observation is not None
                    and previous is not None
                    and differential.mode.name != "DISABLED"
                    and runtime_target.policy.retry.safety is ReplaySafety.PURE
                    and observation.successful_executions < differential.observation_executions
                ):
                    comparator = differential.comparator
                    if comparator is None and differential.comparator_id:
                        comparator = selected_engine.resolve_validator(
                            differential.comparator_id
                        )
                    result = selected_engine.observation.differential_execute(
                        current=version,
                        previous=previous,
                        args=args,
                        kwargs=kwargs,
                        comparator=comparator,
                    )
                    elapsed = time.perf_counter() - started_counter
                    output_acceptable = (
                        not result.original_succeeded
                        or result.equivalent is True
                        or not differential.reject_on_output_difference
                    )
                    state_acceptable = (
                        not differential.require_equivalent_state_changes
                        or not result.original_succeeded
                        or result.state_equivalent is not False
                    )
                    if result.candidate_succeeded and output_acceptable and state_acceptable:
                        selected_output = (
                            result.candidate_result
                            if result.equivalent is not True and not differential.reject_on_output_difference
                            else result.result
                        )
                        selected_engine.record_candidate_observation_success(
                            target=runtime_target,
                            call_id=call_id,
                            output=selected_output,
                            mode="differential",
                        )
                        if result.equivalent and not differential.return_candidate_on_equivalence:
                            completed_output = result.original_result
                            return completed_output
                        completed_output = selected_output
                        return completed_output

                    fallback = result.candidate_exception or DifferentialMismatchError(
                        result.decision_reason
                    )
                    evidence = DifferentialEvidence(
                        original_succeeded=result.original_succeeded,
                        candidate_succeeded=result.candidate_succeeded,
                        original_output=(
                            value_snapshot(result.original_result)
                            if result.original_succeeded
                            else None
                        ),
                        candidate_output=(
                            value_snapshot(result.candidate_result)
                            if result.candidate_succeeded
                            else None
                        ),
                        original_exception=(
                            exception_evidence(
                                result.original_exception, capture_locals=False
                            )
                            if result.original_exception
                            else None
                        ),
                        candidate_exception=(
                            exception_evidence(
                                result.candidate_exception, capture_locals=False
                            )
                            if result.candidate_exception
                            else None
                        ),
                        comparison_reason=result.decision_reason,
                    )
                    resolution = selected_engine.handle_differential_failure(
                        target=runtime_target,
                        version=version,
                        function=version.implementation,
                        args=args,
                        kwargs=kwargs,
                        call_state=call_state,
                        evidence=evidence,
                        call_id=call_id,
                        started_at=started_at,
                        elapsed_seconds=elapsed,
                        fallback_exception=fallback,
                    )
                    if resolution.kind == ResolutionKind.RETRY_SUCCEEDED:
                        completed_output = resolution.retry_output
                        return completed_output
                    selected_engine.observation.record_failure(
                        slot=runtime_target.slot,
                        call_id=call_id,
                        exception=fallback,
                        policy=runtime_target.policy.observation,
                        mode="differential",
                    )
                    if result.original_succeeded and differential.return_original_if_candidate_fails:
                        completed_output = result.original_result
                        return completed_output
                    raise resolution.retry_exception or fallback

                try:
                    output = version.implementation(*args, **kwargs)
                except BaseException as exc:
                    elapsed = time.perf_counter() - started_counter
                    trigger = _matching_exception_trigger(runtime_target.policy, exc)
                    if trigger is None:
                        if version.candidate_id is not None:
                            selected_engine.observation.record_failure(
                                slot=runtime_target.slot,
                                call_id=call_id,
                                exception=exc,
                                policy=runtime_target.policy.observation,
                            )
                        raise
                    resolution = selected_engine.handle_exception(
                        target=runtime_target,
                        version=version,
                        function=version.implementation,
                        args=args,
                        kwargs=kwargs,
                        call_state=call_state,
                        exception=exc,
                        call_id=call_id,
                        started_at=started_at,
                        elapsed_seconds=elapsed,
                    )
                    if resolution.kind == ResolutionKind.RETRY_SUCCEEDED:
                        completed_output = resolution.retry_output
                        return completed_output
                    if version.candidate_id is not None:
                        selected_engine.observation.record_failure(
                            slot=runtime_target.slot,
                            call_id=call_id,
                            exception=resolution.retry_exception or exc,
                            policy=runtime_target.policy.observation,
                        )
                    if (
                        resolution.kind == ResolutionKind.RETRY_FAILED
                        and resolution.retry_exception
                    ):
                        try:
                            resolution.retry_exception.add_note(
                                f"Caretaker incident {resolution.incident_id}; "
                                f"episode {resolution.episode_id}"
                            )
                        except Exception:
                            pass
                        raise resolution.retry_exception
                    try:
                        exc.add_note(f"Caretaker incident {resolution.incident_id}")
                    except Exception:
                        pass
                    raise

                elapsed = time.perf_counter() - started_counter
                for trigger in _output_triggers(runtime_target.policy):
                    validator = (
                        trigger.validator
                        if trigger.validator is not None
                        else selected_engine.resolve_validator(
                            trigger.validator_id or ""
                        )
                    )
                    validation_reason = ""
                    validation_evidence: dict[str, Any] = {}
                    try:
                        validation = normalize_validation_result(validator(output))
                        valid = validation.valid
                        validation_reason = validation.reason
                        validation_evidence = dict(validation.evidence)
                    except Exception as exc:
                        selected_engine.postmortem.capture(
                            exc,
                            component="output-validator",
                            operation=trigger.name,
                        )
                        if trigger.on_validator_error is ValidatorErrorBehavior.FAIL_OPEN:
                            continue
                        valid = False
                        validation_reason = (
                            f"validator raised {type(exc).__name__}: {exc}"
                        )
                    if not valid:
                        resolution = selected_engine.handle_invalid_output(
                            target=runtime_target,
                            version=version,
                            function=version.implementation,
                            args=args,
                            kwargs=kwargs,
                            call_state=call_state,
                            output=output,
                            validator_name=trigger.name,
                            reason=validation_reason or "validator returned false",
                            call_id=call_id,
                            started_at=started_at,
                            elapsed_seconds=elapsed,
                        )
                        if resolution.kind == ResolutionKind.RETRY_SUCCEEDED:
                            completed_output = resolution.retry_output
                            return completed_output
                        if version.candidate_id is not None:
                            selected_engine.observation.record_failure(
                                slot=runtime_target.slot,
                                call_id=call_id,
                                exception=InvalidOutputError(
                                    validation_reason or "output validation failed"
                                ),
                                policy=runtime_target.policy.observation,
                            )
                        if runtime_target.policy.mode is RepairMode.OBSERVE:
                            completed_output = output
                            return completed_output
                        error = InvalidOutputError(
                            f"Output from {runtime_target.target_id} failed validator "
                            f"{trigger.name}: {validation_reason or 'validator returned false'}; "
                            f"incident {resolution.incident_id}"
                        )
                        if validation_evidence:
                            error.add_note(f"Validation evidence: {validation_evidence!r}")
                        raise error

                timeout = _exceeded_soft_timeout(runtime_target.policy, elapsed)
                if timeout is not None:
                    resolution = selected_engine.handle_timeout(
                        target=runtime_target,
                        version=version,
                        function=version.implementation,
                        args=args,
                        kwargs=kwargs,
                        call_state=call_state,
                        configured_seconds=timeout.seconds,
                        output=output,
                        call_id=call_id,
                        started_at=started_at,
                        elapsed_seconds=elapsed,
                    )
                    if resolution.kind == ResolutionKind.RETRY_SUCCEEDED:
                        completed_output = resolution.retry_output
                        return completed_output
                    if version.candidate_id is not None:
                        selected_engine.observation.record_failure(
                            slot=runtime_target.slot,
                            call_id=call_id,
                            exception=TimeoutError(
                                f"soft timeout exceeded: {elapsed:g}s"
                            ),
                            policy=runtime_target.policy.observation,
                        )

                if version.candidate_id is not None:
                    selected_engine.record_candidate_observation_success(
                        target=runtime_target,
                        call_id=call_id,
                        output=output,
                    )
                completed_output = output
                return completed_output
            finally:
                succeeded = sys.exc_info()[0] is None
                elapsed_for_logging = time.perf_counter() - started_counter
                if guard_started and selected_engine.guard is not None:
                    selected_engine.guard.after_call(
                        runtime_target.target_id,
                        version.implementation,
                        call_id,
                        candidate_id=version.candidate_id,
                        succeeded=succeeded,
                        elapsed_seconds=elapsed_for_logging,
                    )
                if (
                    logging_runtime is not None
                    and runtime_target.policy.logging.enabled
                    and (
                        runtime_target.policy.logging.capture_calls
                        or runtime_target.policy.logging.capture_results
                    )
                    and (succeeded or runtime_target.policy.logging.capture_exceptions)
                ):
                    completed_fields = {
                        "event": "repair.function.call.completed" if succeeded else "repair.function.call.failed",
                        "target_id": runtime_target.target_id,
                        "function_version": version.number,
                        "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                        "succeeded": succeeded,
                        "elapsed_seconds": elapsed_for_logging if runtime_target.policy.logging.capture_timing else None,
                    }
                    if succeeded and completed_output is not _NO_RESULT and runtime_target.policy.logging.capture_results:
                        completed_fields["result"] = _result_evidence(completed_output)
                    logging_runtime.event(
                        logger_name=callable_original.__module__,
                        severity=10 if succeeded else 40,
                        channel=LogChannel.REPAIR,
                        message=(
                            f"Repair-enabled call completed: {runtime_target.target_id}"
                            if succeeded else f"Repair-enabled call failed: {runtime_target.target_id}"
                        ),
                        fields=completed_fields,
                        function_version=version.number,
                    )
                tokens.reset()

        setattr(wrapper, "__caretaker_target__", target)
        setattr(wrapper, "__caretaker_engine__", selected_engine)
        return rebuild_descriptor(wrapper)  # type: ignore[return-value]

    if function is not None:
        return decorate(function)
    return decorate


@overload
def caretaker(function: F) -> F:
    ...


@overload
def caretaker(
    function: None = None,
    *,
    policy: RepairPolicy | None = None,
    engine: RepairEngine | None = None,
    target_id: str | None = None,
    cases: tuple[Any, ...] = (),
    tags: frozenset[str] = frozenset(),
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY,
    mask: MaskFunction | None = None,
) -> Callable[[F], F]:
    ...


def caretaker(
    function: F | None = None,
    *,
    policy: RepairPolicy | None = None,
    engine: RepairEngine | None = None,
    target_id: str | None = None,
    cases: tuple[Any, ...] = (),
    tags: frozenset[str] = frozenset(),
    integrity_class: IntegrityClass = IntegrityClass.ORDINARY,
    mask: MaskFunction | None = None,
) -> F | Callable[[F], F]:
    """Register a function as a fully managed Caretaker target.

    ``caretaker`` is the preferred public decorator when a target uses
    multiple Caretaker capabilities.  Logging, Guard, candidate behavior,
    Integrity restrictions, and Repair behavior remain configured through
    the existing ``RepairPolicy``.

    This function delegates directly to ``repair``.  It does not add a
    second wrapper, registration path, or execution boundary.
    """
    return repair(
        function,
        policy=policy,
        engine=engine,
        target_id=target_id,
        cases=cases,
        tags=tags,
        integrity_class=integrity_class,
        mask=mask,
    )


def repair_on_exception(
    *,
    exceptions: tuple[type[BaseException], ...] = (Exception,),
    exclude: tuple[type[BaseException], ...] = (
        KeyboardInterrupt,
        SystemExit,
        GeneratorExit,
    ),
    retry: int = 0,
    replay_safety: ReplaySafety = ReplaySafety.UNKNOWN,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_POLICY
    configured = replace(
        base,
        triggers=(ExceptionTrigger(include=exceptions, exclude=exclude),),
        retry=replace(base.retry, max_attempts=retry, safety=replay_safety),
    )
    return repair(policy=configured, **repair_kwargs)


def repair_on_invalid_output(
    validator: Callable[[Any], Any] | None = None,
    *,
    validator_id: str | None = None,
    name: str = "output-validator",
    retry: int = 0,
    replay_safety: ReplaySafety = ReplaySafety.UNKNOWN,
    on_validator_error: ValidatorErrorBehavior = ValidatorErrorBehavior.FAIL_CLOSED,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_POLICY
    configured = replace(
        base,
        triggers=(
            OutputValidationTrigger(
                validator=validator,
                validator_id=validator_id,
                name=name,
                on_validator_error=on_validator_error,
            ),
        ),
        retry=replace(base.retry, max_attempts=retry, safety=replay_safety),
    )
    return repair(policy=configured, **repair_kwargs)


def repair_on_soft_timeout(
    seconds: float,
    *,
    retry: int = 0,
    replay_safety: ReplaySafety = ReplaySafety.UNKNOWN,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    """Open a Repair incident after a completed call exceeds ``seconds``.

    This is an elapsed-time contract, not an interruption mechanism. The
    original invocation must return before Caretaker can detect the violation.
    """
    base = policy or DEFAULT_POLICY
    configured = replace(
        base,
        triggers=(TimeoutTrigger(seconds=seconds, mode=TimeoutMode.SOFT),),
        retry=replace(base.retry, max_attempts=retry, safety=replay_safety),
    )
    return repair(policy=configured, **repair_kwargs)


def repair_on_timeout(
    seconds: float,
    *,
    retry: int = 0,
    replay_safety: ReplaySafety = ReplaySafety.UNKNOWN,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    """Backward-compatible name for :func:`repair_on_soft_timeout`.

    The call is not interrupted when the threshold is reached.
    """
    import warnings

    warnings.warn(
        "repair_on_timeout() is a soft elapsed-time trigger and does not interrupt "
        "a running function; prefer repair_on_soft_timeout()",
        DeprecationWarning,
        stacklevel=2,
    )
    return repair_on_soft_timeout(
        seconds, retry=retry, replay_safety=replay_safety, policy=policy, **repair_kwargs
    )


def repair_and_retry(
    *,
    retry: int = 1,
    replay_safety: ReplaySafety = ReplaySafety.UNKNOWN,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    return repair_on_exception(
        retry=retry,
        replay_safety=replay_safety,
        policy=policy,
        **repair_kwargs,
    )


def diagnose_only(
    *,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_POLICY
    return repair(policy=replace(base, mode=RepairMode.DIAGNOSE), **repair_kwargs)


def observe_only(
    *,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_POLICY
    return repair(policy=replace(base, mode=RepairMode.OBSERVE), **repair_kwargs)


def _matching_exception_trigger(
    policy: RepairPolicy,
    exception: BaseException,
) -> ExceptionTrigger | None:
    for trigger in policy.triggers:
        if not isinstance(trigger, ExceptionTrigger):
            continue
        if isinstance(exception, trigger.exclude):
            continue
        if isinstance(exception, trigger.include):
            return trigger
    return None


def _output_triggers(policy: RepairPolicy) -> tuple[OutputValidationTrigger, ...]:
    return tuple(
        trigger
        for trigger in policy.triggers
        if isinstance(trigger, OutputValidationTrigger)
    )


def _exceeded_soft_timeout(
    policy: RepairPolicy,
    elapsed_seconds: float,
) -> TimeoutTrigger | None:
    for trigger in policy.triggers:
        if (
            isinstance(trigger, TimeoutTrigger)
            and trigger.mode is TimeoutMode.SOFT
            and elapsed_seconds > trigger.seconds
        ):
            return trigger
    return None
