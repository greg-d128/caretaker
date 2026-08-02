from __future__ import annotations

import functools
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar, overload
from uuid import uuid4

from ..contracts import normalize_validation_result
from ..domain import (
    DifferentialEvidence,
    RepairMode,
    ReplaySafety,
    TargetCapability,
    ValidatorErrorBehavior,
)
from ..engine import RepairEngine, ResolutionKind
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
) -> F | Callable[[F], F]:
    """Register a synchronous function for incident capture and in-memory repair."""

    def decorate(original: F) -> F:
        selected_engine = engine or get_default_engine()
        selected_policy = policy or DEFAULT_POLICY
        target = build_target(
            original,
            policy=selected_policy,
            target_id=target_id,
            registered_cases=tuple(cases),
            tags=tags,
            integrity_class=integrity_class,
            mask_function=mask,
        )
        selected_engine.register(target)

        @functools.wraps(original)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_id = uuid4()
            tokens = set_runtime_context(
                target_id=target.target_id,
                call_id=call_id,
                operation="function-call",
            )
            started_at = datetime.now(timezone.utc)
            started_counter = time.perf_counter()
            version = target.slot.load()
            call_state = selected_engine.state_capture.capture_before(
                version.implementation,
                args,
                kwargs,
                target.policy.state,
            )
            masked_input = apply_mask(target.mask_function, args, kwargs)
            if target.mask_function is not None and call_state.bound_arguments:
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
            if logging_runtime is not None and target.policy.logging.enabled and target.policy.logging.capture_calls:
                logging_fields = {
                    "event": "repair.function.call.started",
                    "target_id": target.target_id,
                    "function_version": version.version,
                    "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                    "masking": {
                        "fully_removed_fields": masked_input.fully_removed_fields,
                        "format_preserved_fields": masked_input.format_preserved_fields,
                        "structural_metadata": masked_input.structural_metadata,
                    },
                }
                if target.policy.logging.capture_arguments:
                    logging_fields["args"] = masked_input.masked_args
                    logging_fields["kwargs"] = dict(masked_input.masked_kwargs)
                logging_runtime.event(
                    logger_name=original.__module__, severity=10,
                    channel=LogChannel.REPAIR,
                    message=f"Repair-enabled call started: {target.target_id}",
                    fields=logging_fields,
                    function_version=version.version,
                )
            guard_started = False
            pending = selected_engine.handle_pending_guard_signal(
                target=target,
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
                    tokens.reset()
                    return pending.retry_output
                version = target.slot.load()
                call_state = selected_engine.state_capture.capture_before(
                    version.implementation,
                    args,
                    kwargs,
                    target.policy.state,
                )
            if selected_engine.guard is not None and target.policy.guard.enabled:
                selected_engine.guard.before_call(
                    target.target_id,
                    version.implementation,
                    call_id,
                    candidate_id=version.candidate_id,
                )
                guard_started = True
            try:
                differential = target.policy.observation.differential_execution
                observation = target.slot.observation()
                previous = target.slot.previous()
                if (
                    version.candidate_id is not None
                    and observation is not None
                    and previous is not None
                    and differential.mode.name != "DISABLED"
                    and target.policy.retry.safety is ReplaySafety.PURE
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
                    if result.candidate_succeeded and (
                        not result.original_succeeded or result.equivalent is True
                    ):
                        selected_engine.observation.record_success(
                            slot=target.slot,
                            call_id=call_id,
                            policy=target.policy.observation,
                            output=result.result,
                            mode="differential",
                        )
                        if result.equivalent and not differential.return_candidate_on_equivalence:
                            return result.original_result
                        return result.result

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
                        target=target,
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
                        return resolution.retry_output
                    selected_engine.observation.record_failure(
                        slot=target.slot,
                        call_id=call_id,
                        exception=fallback,
                        policy=target.policy.observation,
                        mode="differential",
                    )
                    if result.original_succeeded and differential.return_original_if_candidate_fails:
                        return result.original_result
                    raise resolution.retry_exception or fallback

                try:
                    output = version.implementation(*args, **kwargs)
                except BaseException as exc:
                    elapsed = time.perf_counter() - started_counter
                    trigger = _matching_exception_trigger(target.policy, exc)
                    if trigger is None:
                        if version.candidate_id is not None:
                            selected_engine.observation.record_failure(
                                slot=target.slot,
                                call_id=call_id,
                                exception=exc,
                                policy=target.policy.observation,
                            )
                        raise
                    resolution = selected_engine.handle_exception(
                        target=target,
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
                        return resolution.retry_output
                    if version.candidate_id is not None:
                        selected_engine.observation.record_failure(
                            slot=target.slot,
                            call_id=call_id,
                            exception=resolution.retry_exception or exc,
                            policy=target.policy.observation,
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
                for trigger in _output_triggers(target.policy):
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
                            target=target,
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
                            return resolution.retry_output
                        if version.candidate_id is not None:
                            selected_engine.observation.record_failure(
                                slot=target.slot,
                                call_id=call_id,
                                exception=InvalidOutputError(
                                    validation_reason or "output validation failed"
                                ),
                                policy=target.policy.observation,
                            )
                        if target.policy.mode is RepairMode.OBSERVE:
                            return output
                        error = InvalidOutputError(
                            f"Output from {target.target_id} failed validator "
                            f"{trigger.name}: {validation_reason or 'validator returned false'}; "
                            f"incident {resolution.incident_id}"
                        )
                        if validation_evidence:
                            error.add_note(f"Validation evidence: {validation_evidence!r}")
                        raise error

                timeout = _exceeded_soft_timeout(target.policy, elapsed)
                if timeout is not None:
                    resolution = selected_engine.handle_timeout(
                        target=target,
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
                        return resolution.retry_output
                    if version.candidate_id is not None:
                        selected_engine.observation.record_failure(
                            slot=target.slot,
                            call_id=call_id,
                            exception=TimeoutError(
                                f"soft timeout exceeded: {elapsed:g}s"
                            ),
                            policy=target.policy.observation,
                        )

                if version.candidate_id is not None:
                    selected_engine.observation.record_success(
                        slot=target.slot,
                        call_id=call_id,
                        policy=target.policy.observation,
                        output=output,
                    )
                return output
            finally:
                succeeded = sys.exc_info()[0] is None
                elapsed_for_logging = time.perf_counter() - started_counter
                if guard_started and selected_engine.guard is not None:
                    selected_engine.guard.after_call(
                        target.target_id,
                        version.implementation,
                        call_id,
                        candidate_id=version.candidate_id,
                        succeeded=succeeded,
                        elapsed_seconds=elapsed_for_logging,
                    )
                if logging_runtime is not None and target.policy.logging.enabled and target.policy.logging.capture_calls:
                    logging_runtime.event(
                        logger_name=original.__module__,
                        severity=10 if succeeded else 40,
                        channel=LogChannel.REPAIR,
                        message=(
                            f"Repair-enabled call completed: {target.target_id}"
                            if succeeded else f"Repair-enabled call failed: {target.target_id}"
                        ),
                        fields={
                            "event": "repair.function.call.completed" if succeeded else "repair.function.call.failed",
                            "target_id": target.target_id,
                            "function_version": version.version,
                            "candidate_id": str(version.candidate_id) if version.candidate_id else None,
                            "succeeded": succeeded,
                            "elapsed_seconds": elapsed_for_logging if target.policy.logging.capture_timing else None,
                        },
                        function_version=version.version,
                    )
                tokens.reset()

        setattr(wrapper, "__caretaker_target__", target)
        setattr(wrapper, "__caretaker_engine__", selected_engine)
        return wrapper  # type: ignore[return-value]

    if function is not None:
        return decorate(function)
    return decorate


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


def repair_on_timeout(
    seconds: float,
    *,
    retry: int = 0,
    replay_safety: ReplaySafety = ReplaySafety.UNKNOWN,
    policy: RepairPolicy | None = None,
    **repair_kwargs: Any,
) -> Callable[[F], F]:
    base = policy or DEFAULT_POLICY
    configured = replace(
        base,
        triggers=(TimeoutTrigger(seconds=seconds, mode="soft"),),
        retry=replace(base.retry, max_attempts=retry, safety=replay_safety),
    )
    return repair(policy=configured, **repair_kwargs)


def repair_and_retry(
    *,
    retry: int = 1,
    replay_safety: ReplaySafety = ReplaySafety.IDEMPOTENT,
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
            and trigger.mode == "soft"
            and elapsed_seconds > trigger.seconds
        ):
            return trigger
    return None
