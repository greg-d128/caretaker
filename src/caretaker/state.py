from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import pickle
import sys
import threading
import traceback as traceback_module
from dataclasses import dataclass, field
from typing import Any

from .domain import (
    CallSnapshot,
    ChangeKind,
    ExceptionEvidence,
    StateDifference,
    TracebackFrameSnapshot,
    ValueSnapshot,
)
from .policy import StatePolicy


_REDACT_NAMES = {"password", "passwd", "token", "secret", "authorization", "api_key", "apikey"}


@dataclass
class RuntimeStateSnapshot:
    args: tuple[Any, ...] | None = None
    kwargs: dict[str, Any] | None = None
    instance_state: dict[str, Any] | None = None
    globals_state: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def replayable(self) -> bool:
        return self.args is not None and self.kwargs is not None


@dataclass
class CallState:
    bound_arguments: dict[str, ValueSnapshot]
    runtime_snapshot: RuntimeStateSnapshot


class StateCapture:
    def capture_before(
        self,
        function: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        policy: StatePolicy,
    ) -> CallState:
        bound_arguments: dict[str, ValueSnapshot] = {}
        try:
            bound = inspect.signature(function).bind_partial(*args, **kwargs)
            bound.apply_defaults()
            if policy.capture_arguments:
                bound_arguments = {
                    name: value_snapshot(value, name=name)
                    for name, value in bound.arguments.items()
                }
        except Exception as exc:
            bound_arguments = {"<binding-error>": value_snapshot(exc)}

        runtime = RuntimeStateSnapshot()
        if policy.snapshot_arguments:
            try:
                runtime.args = _bounded_deepcopy(args, policy.max_snapshot_bytes)
                runtime.kwargs = _bounded_deepcopy(kwargs, policy.max_snapshot_bytes)
            except Exception as exc:
                runtime.errors.append(f"argument snapshot failed: {type(exc).__name__}: {exc}")

        if (policy.snapshot_instance or policy.capture_instance_state) and args and hasattr(args[0], "__dict__"):
            try:
                runtime.instance_state = _bounded_deepcopy(vars(args[0]), policy.max_snapshot_bytes)
            except Exception as exc:
                runtime.errors.append(f"instance snapshot failed: {type(exc).__name__}: {exc}")

        for name in policy.snapshot_globals:
            if name not in function.__globals__:
                runtime.errors.append(f"global {name!r} not found")
                continue
            try:
                runtime.globals_state[name] = _bounded_deepcopy(function.__globals__[name], policy.max_snapshot_bytes)
            except Exception as exc:
                runtime.errors.append(f"global {name!r} snapshot failed: {type(exc).__name__}: {exc}")
        return CallState(bound_arguments=bound_arguments, runtime_snapshot=runtime)

    def differences(
        self,
        function: Any,
        args: tuple[Any, ...],
        before: RuntimeStateSnapshot,
        policy: StatePolicy,
        kwargs: dict[str, Any] | None = None,
    ) -> tuple[StateDifference, ...]:
        if not policy.detect_mutations:
            return ()
        differences: list[StateDifference] = []
        if before.args is not None:
            for index, previous in enumerate(before.args):
                current = args[index] if index < len(args) else _MISSING
                _append_differences(
                    differences,
                    path=f"arguments[{index}]",
                    before=previous,
                    after=current,
                    restorable=True,
                    limit=policy.max_diff_entries,
                )
        if before.kwargs is not None:
            current_kwargs = kwargs or {}
            for name in sorted(set(before.kwargs) | set(current_kwargs)):
                _append_differences(
                    differences,
                    path=f"keyword_arguments.{name}",
                    before=before.kwargs.get(name, _MISSING),
                    after=current_kwargs.get(name, _MISSING),
                    restorable=True,
                    limit=policy.max_diff_entries,
                )
        if before.instance_state is not None and args and hasattr(args[0], "__dict__"):
            current_state = vars(args[0])
            _append_differences(
                differences,
                path="instance",
                before=before.instance_state,
                after=current_state,
                restorable=policy.snapshot_instance and policy.restore_live_environment,
                limit=policy.max_diff_entries,
            )
        for name, previous in before.globals_state.items():
            current = function.__globals__.get(name, _MISSING)
            _append_differences(
                differences,
                path=f"globals.{name}",
                before=previous,
                after=current,
                restorable=policy.restore_live_environment,
                limit=policy.max_diff_entries,
                snapshot_name=name,
            )
        return tuple(differences[: policy.max_diff_entries])

    def retry_arguments(
        self,
        original_args: tuple[Any, ...],
        original_kwargs: dict[str, Any],
        snapshot: RuntimeStateSnapshot,
        policy: StatePolicy,
    ) -> tuple[tuple[Any, ...], dict[str, Any], bool, list[str]]:
        errors = list(snapshot.errors)
        if not policy.restore_before_retry:
            return original_args, original_kwargs, True, errors
        if snapshot.args is None or snapshot.kwargs is None:
            return original_args, original_kwargs, False, errors
        try:
            return _bounded_deepcopy(snapshot.args, policy.max_snapshot_bytes), _bounded_deepcopy(snapshot.kwargs, policy.max_snapshot_bytes), True, errors
        except Exception as exc:
            errors.append(f"retry argument restore failed: {type(exc).__name__}: {exc}")
            return original_args, original_kwargs, False, errors

    def restore_live_environment(
        self,
        function: Any,
        args: tuple[Any, ...],
        snapshot: RuntimeStateSnapshot,
        policy: StatePolicy,
    ) -> list[str]:
        errors: list[str] = []
        if not policy.restore_live_environment:
            return errors
        if snapshot.instance_state is not None and args and hasattr(args[0], "__dict__"):
            try:
                vars(args[0]).clear()
                vars(args[0]).update(_bounded_deepcopy(snapshot.instance_state, policy.max_snapshot_bytes))
            except Exception as exc:
                errors.append(f"instance restore failed: {type(exc).__name__}: {exc}")
        for name, value in snapshot.globals_state.items():
            try:
                function.__globals__[name] = _bounded_deepcopy(value, policy.max_snapshot_bytes)
            except Exception as exc:
                errors.append(f"global {name!r} restore failed: {type(exc).__name__}: {exc}")
        return errors

    def restore_for_validation(
        self,
        function: Any,
        args: tuple[Any, ...],
        snapshot: RuntimeStateSnapshot,
        policy: StatePolicy,
    ) -> list[str]:
        """Restore captured in-process state before candidate validation.

        Validation itself runs in the selected isolated backend, but the
        application process may have been mutated by the failed call.  This
        boundary restores the captured instance/global state before the
        supervisor accepts validation evidence or activates a candidate.
        Uncaptured external side effects remain outside this guarantee.
        """
        if not policy.restore_for_validation:
            return ["state restoration for validation is disabled by policy"]
        errors = list(snapshot.errors)
        if snapshot.instance_state is not None and args and hasattr(args[0], "__dict__"):
            try:
                vars(args[0]).clear()
                vars(args[0]).update(_bounded_deepcopy(snapshot.instance_state, policy.max_snapshot_bytes))
            except Exception as exc:
                errors.append(f"instance restore for validation failed: {type(exc).__name__}: {exc}")
        for name, value in snapshot.globals_state.items():
            try:
                function.__globals__[name] = _bounded_deepcopy(value, policy.max_snapshot_bytes)
            except Exception as exc:
                errors.append(f"global {name!r} restore for validation failed: {type(exc).__name__}: {exc}")
        return errors


_MISSING = object()

def _bounded_deepcopy(value: Any, maximum_bytes: int) -> Any:
    copied = copy.deepcopy(value)
    try:
        size = len(pickle.dumps(copied, protocol=pickle.HIGHEST_PROTOCOL))
    except Exception:
        size = sys.getsizeof(copied)
    if size > maximum_bytes:
        raise ValueError(f"snapshot size {size} exceeds configured maximum {maximum_bytes}")
    return copied


def _append_differences(
    differences: list[StateDifference],
    *,
    path: str,
    before: Any,
    after: Any,
    restorable: bool,
    limit: int,
    snapshot_name: str | None = None,
    depth: int = 0,
) -> None:
    if len(differences) >= limit or _safe_equal(before, after):
        return
    if before is _MISSING or after is _MISSING:
        differences.append(
            StateDifference(
                path=path,
                change=ChangeKind.ADDED if before is _MISSING else ChangeKind.REMOVED,
                before=None if before is _MISSING else value_snapshot(before, name=snapshot_name),
                after=None if after is _MISSING else value_snapshot(after, name=snapshot_name),
                restorable=restorable,
            )
        )
        return
    if depth < 4 and isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after), key=repr):
            _append_differences(
                differences,
                path=f"{path}.{key}",
                before=before.get(key, _MISSING),
                after=after.get(key, _MISSING),
                restorable=restorable,
                limit=limit,
                depth=depth + 1,
            )
            if len(differences) >= limit:
                break
        return
    if depth < 4 and isinstance(before, (list, tuple)) and isinstance(after, (list, tuple)):
        for index in range(max(len(before), len(after))):
            _append_differences(
                differences,
                path=f"{path}[{index}]",
                before=before[index] if index < len(before) else _MISSING,
                after=after[index] if index < len(after) else _MISSING,
                restorable=restorable,
                limit=limit,
                depth=depth + 1,
            )
            if len(differences) >= limit:
                break
        return
    differences.append(
        StateDifference(
            path=path,
            change=ChangeKind.MUTATED,
            before=value_snapshot(before, name=snapshot_name),
            after=value_snapshot(after, name=snapshot_name),
            restorable=restorable,
        )
    )


def build_call_snapshot(
    *,
    started_at: Any,
    elapsed_seconds: float,
    bound_arguments: dict[str, ValueSnapshot],
    call_attempt: int,
    replayable: bool,
    replay_block_reason: str | None,
) -> CallSnapshot:
    return CallSnapshot(
        started_at=started_at,
        elapsed_seconds=elapsed_seconds,
        bound_arguments=bound_arguments,
        process_id=os.getpid(),
        thread_id=threading.get_ident(),
        task_name=None,
        call_attempt=call_attempt,
        replayable=replayable,
        replay_block_reason=replay_block_reason,
    )


def exception_evidence(
    exception: BaseException,
    *,
    capture_locals: bool = True,
    max_frames: int = 25,
) -> ExceptionEvidence:
    frames: list[TracebackFrameSnapshot] = []
    extracted = traceback_module.extract_tb(exception.__traceback__)
    tb = exception.__traceback__
    index = 0
    while tb is not None and index < max_frames:
        frame = tb.tb_frame
        summary = extracted[index] if index < len(extracted) else None
        local_values: dict[str, ValueSnapshot] = {}
        if capture_locals:
            for name, value in list(frame.f_locals.items())[:100]:
                local_values[name] = value_snapshot(value, name=name)
        frames.append(
            TracebackFrameSnapshot(
                filename=frame.f_code.co_filename,
                line_number=tb.tb_lineno,
                function_name=frame.f_code.co_name,
                source_line=summary.line if summary else None,
                locals=local_values,
            )
        )
        tb = tb.tb_next
        index += 1
    return ExceptionEvidence(
        exception_module=type(exception).__module__,
        exception_type=type(exception).__name__,
        message=str(exception),
        arguments=tuple(value_snapshot(value) for value in getattr(exception, "args", ())),
        traceback=tuple(frames),
    )


def value_snapshot(
    value: Any,
    *,
    name: str | None = None,
    max_length: int = 2_000,
) -> ValueSnapshot:
    if name and any(token in name.lower() for token in _REDACT_NAMES):
        return ValueSnapshot(
            type_name=f"{type(value).__module__}.{type(value).__qualname__}",
            representation="<redacted>",
            redacted=True,
        )
    try:
        representation = repr(value)
    except Exception as exc:
        representation = f"<repr failed: {type(exc).__name__}: {exc}>"
    truncated = len(representation) > max_length
    if truncated:
        representation = representation[:max_length] + "…"
    try:
        digest = hashlib.sha256(representation.encode("utf-8", "replace")).hexdigest()
    except Exception:
        digest = None
    return ValueSnapshot(
        type_name=f"{type(value).__module__}.{type(value).__qualname__}",
        representation=representation,
        value_hash=digest,
        truncated=truncated,
        size_bytes=sys.getsizeof(value, 0),
    )


def _safe_equal(left: Any, right: Any) -> bool:
    try:
        result = left == right
        return bool(result)
    except Exception:
        return repr(left) == repr(right)
