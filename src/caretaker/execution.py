"""Function execution contracts and conservative side-effect assessments.

The contract is a declaration about a target.  The assessment is evidence about
what was observed while the target ran.  Neither one grants Repair authority;
rollout policy remains responsible for deciding whether an execution strategy
may be used.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .domain import ReplaySafety, SideEffectClass
from .evidence.models import BehaviorEvent, BehaviorEventKind


class ExecutionEffectCategory(str, Enum):
    """Bounded categories used when summarizing observed runtime effects."""

    NETWORK = "network"
    FILESYSTEM = "filesystem"
    SUBPROCESS = "subprocess"
    IMPORT = "import"
    DYNAMIC_CODE = "dynamic-code"
    ENVIRONMENT = "environment"


_FILESYSTEM_EVENT_KINDS = frozenset(
    {
        BehaviorEventKind.FILE_OPEN,
        BehaviorEventKind.FILE_READ,
        BehaviorEventKind.FILE_WRITE,
        BehaviorEventKind.DIRECTORY_LIST,
        BehaviorEventKind.DIRECTORY_WALK,
    }
)


def _filesystem_resource_is_mutating(event_kinds: set[str]) -> bool:
    """Classify retained filesystem resources without trusting ambiguity."""

    return (
        BehaviorEventKind.FILE_WRITE.name in event_kinds
        or not any(kind.name in event_kinds for kind in _FILESYSTEM_EVENT_KINDS)
    )


@dataclass(frozen=True, slots=True)
class FunctionExecutionContract:
    """Application declaration for retry and duplicate-execution handling.

    ``retry_safety`` is descriptive metadata.  The effective retry policy still
    controls whether a retry is permitted.  ``side_effects`` is intentionally
    separate because an idempotent operation can still perform externally
    visible effects and therefore cannot automatically be shadowed.
    """

    side_effects: SideEffectClass = SideEffectClass.UNKNOWN
    retry_safety: ReplaySafety = ReplaySafety.UNKNOWN

    def __post_init__(self) -> None:
        if isinstance(self.side_effects, str):
            object.__setattr__(
                self,
                "side_effects",
                SideEffectClass[_enum_name(self.side_effects)],
            )
        if isinstance(self.retry_safety, str):
            object.__setattr__(
                self,
                "retry_safety",
                ReplaySafety[_enum_name(self.retry_safety)],
            )

    @classmethod
    def from_policy(
        cls,
        *,
        retry_safety: ReplaySafety,
        pure_function_confirmed: bool = False,
    ) -> "FunctionExecutionContract":
        """Build compatibility metadata from existing Repair policy settings."""

        # The existing PURE_FUNCTION acknowledgement is already an explicit
        # declaration.  It is the only legacy setting that can establish PURE;
        # retry safety alone must not imply absence of side effects.
        return cls(
            side_effects=(
                SideEffectClass.PURE
                if pure_function_confirmed
                else SideEffectClass.UNKNOWN
            ),
            retry_safety=retry_safety,
        )


@dataclass(frozen=True, slots=True)
class EffectObservation:
    """Bounded evidence about effects observed for one target."""

    categories: tuple[str, ...] = ()
    externally_visible_categories: tuple[str, ...] = ()
    event_kinds: tuple[str, ...] = ()
    event_count: int = 0
    complete: bool = False

    @classmethod
    def from_events(
        cls,
        events: Iterable[BehaviorEvent],
        *,
        complete: bool = False,
    ) -> "EffectObservation":
        categories: set[str] = set()
        mutating: set[str] = set()
        kinds: set[str] = set()
        count = 0
        for event in events:
            count += 1
            kind = event.event_kind
            kinds.add(kind.name)
            category = _category_for_event(kind)
            if category is None:
                continue
            categories.add(category.value)
            if kind in {
                BehaviorEventKind.FILE_WRITE,
                BehaviorEventKind.NETWORK_CONNECT,
                BehaviorEventKind.NETWORK_SEND,
                BehaviorEventKind.SUBPROCESS,
                BehaviorEventKind.DYNAMIC_CODE,
            }:
                mutating.add(category.value)
        return cls(
            categories=tuple(sorted(categories)),
            externally_visible_categories=tuple(sorted(mutating)),
            event_kinds=tuple(sorted(kinds)),
            event_count=count,
            complete=complete,
        )

    @classmethod
    def from_profile(
        cls,
        profile: Any,
        *,
        complete: bool = False,
    ) -> "EffectObservation":
        """Extract categories from a BehaviorProfile or summary.

        Profile summaries preserve event-kind names, so writes and sends remain
        distinguishable even when individual events have been retained only in
        a bounded store.
        """

        # Behavior captures expose the profile under a ``profile`` key while
        # Guard summaries expose the profile fields directly. Accept both
        # forms so callers cannot accidentally omit resource evidence while
        # converting an operator-facing capture into a safety decision.
        if isinstance(profile, Mapping):
            source = profile.get("profile", profile)
        else:
            source = profile

        def field(name: str, default: Any = None) -> Any:
            if isinstance(source, Mapping):
                return source.get(name, default)
            return getattr(source, name, default)

        event_kind_counts = field("event_kind_counts", {}) or {}
        event_kinds = {str(name).upper() for name in event_kind_counts}
        categories: set[str] = set()
        mutating: set[str] = set()
        for name in event_kinds:
            try:
                kind = BehaviorEventKind[name]
            except KeyError:
                continue
            category = _category_for_event(kind)
            if category is None:
                continue
            categories.add(category.value)
            if kind in {
                BehaviorEventKind.FILE_WRITE,
                BehaviorEventKind.NETWORK_CONNECT,
                BehaviorEventKind.NETWORK_SEND,
                BehaviorEventKind.SUBPROCESS,
                BehaviorEventKind.DYNAMIC_CODE,
            }:
                mutating.add(category.value)

        # Resource summaries are an independent evidence surface. They are
        # especially useful when an event-kind count was compacted away but a
        # captured destination/root/operation was retained. Presence proves
        # that activity was observed; it never proves that an absent category
        # did not occur. A retained filesystem root is considered mutating when
        # the event kinds prove a write, or when no filesystem event kind is
        # available to disambiguate the operation. This preserves a useful
        # read-only decision without turning an ambiguous resource summary into
        # evidence of safety.
        resource_fields = {
            "network_destinations": ExecutionEffectCategory.NETWORK,
            "filesystem_roots": ExecutionEffectCategory.FILESYSTEM,
            "subprocesses": ExecutionEffectCategory.SUBPROCESS,
            "imports": ExecutionEffectCategory.IMPORT,
            "dynamic_code_operations": ExecutionEffectCategory.DYNAMIC_CODE,
        }
        for name, category in resource_fields.items():
            if any(value is not None and str(value) for value in (field(name, ()) or ())):
                categories.add(category.value)
                mutating_category = category in {
                    ExecutionEffectCategory.NETWORK,
                    ExecutionEffectCategory.SUBPROCESS,
                    ExecutionEffectCategory.DYNAMIC_CODE,
                }
                if category is ExecutionEffectCategory.FILESYSTEM:
                    mutating_category = _filesystem_resource_is_mutating(event_kinds)
                if mutating_category:
                    mutating.add(category.value)

        resource_kind_categories = {
            "network": ExecutionEffectCategory.NETWORK,
            "file": ExecutionEffectCategory.FILESYSTEM,
            "directory": ExecutionEffectCategory.FILESYSTEM,
            "subprocess": ExecutionEffectCategory.SUBPROCESS,
            "import": ExecutionEffectCategory.IMPORT,
            "dynamic-code": ExecutionEffectCategory.DYNAMIC_CODE,
        }
        for resource_key in (field("resource_counts", {}) or {}):
            category_name = str(resource_key).split(":", 1)[0].strip().lower()
            category = resource_kind_categories.get(category_name)
            if category is None:
                continue
            categories.add(category.value)
            mutating_category = category in {
                ExecutionEffectCategory.NETWORK,
                ExecutionEffectCategory.SUBPROCESS,
                ExecutionEffectCategory.DYNAMIC_CODE,
            }
            if mutating_category:
                mutating.add(category.value)
            elif category is ExecutionEffectCategory.FILESYSTEM:
                if _filesystem_resource_is_mutating(event_kinds):
                    mutating.add(category.value)

        return cls(
            categories=tuple(sorted(categories)),
            externally_visible_categories=tuple(sorted(mutating)),
            event_kinds=tuple(sorted(event_kinds)),
            event_count=sum(
                int(value)
                for value in event_kind_counts.values()
                if isinstance(value, int) and value >= 0
            ),
            complete=complete,
        )

    @classmethod
    def from_behavior_capture(
        cls,
        capture: Mapping[str, Any],
        *,
        complete: bool = False,
    ) -> "EffectObservation":
        """Extract effect evidence from a Guard behavior capture.

        Completeness is deliberately caller-supplied. A capture can prove
        observed network/filesystem/subprocess activity, but its bounded or
        sampled nature cannot prove that an unlisted effect did not happen.
        """

        if not isinstance(capture, Mapping):
            raise TypeError("behavior capture must be an object")
        return cls.from_profile(capture, complete=complete)


@dataclass(frozen=True, slots=True)
class ShadowEligibility:
    """Decision input for a future rollout adapter."""

    eligible: bool
    requires_isolation: bool
    reason: str
    observed_effects: tuple[str, ...] = ()
    observed_external_effects: tuple[str, ...] = ()
    evidence_complete: bool = False


def assess_shadow_eligibility(
    contract: FunctionExecutionContract,
    observation: EffectObservation | None = None,
) -> ShadowEligibility:
    """Conservatively determine whether duplicate execution is appropriate.

    This is an eligibility assessment, not an authorization decision.  Unknown
    or incomplete evidence never becomes evidence of purity.  A rollout policy
    may impose stricter requirements, but may not use this result to bypass its
    authority or validation gates.
    """

    observed = observation or EffectObservation()
    effects = observed.categories
    externally_visible = observed.externally_visible_categories

    if contract.side_effects in {
        SideEffectClass.UNKNOWN,
        SideEffectClass.IDEMPOTENT,
        SideEffectClass.SIDE_EFFECTING,
    }:
        return ShadowEligibility(
            eligible=False,
            requires_isolation=True,
            reason=(
                "function contract does not establish safe duplicate execution"
            ),
            observed_effects=effects,
            observed_external_effects=externally_visible,
            evidence_complete=observed.complete,
        )

    if not observed.complete:
        return ShadowEligibility(
            eligible=False,
            requires_isolation=True,
            reason="effect observation is incomplete; absence of evidence is not proof of purity",
            observed_effects=effects,
            observed_external_effects=externally_visible,
            evidence_complete=False,
        )

    if contract.side_effects is SideEffectClass.PURE and effects:
        return ShadowEligibility(
            eligible=False,
            requires_isolation=True,
            reason="pure function contract conflicts with observed resource activity",
            observed_effects=effects,
            observed_external_effects=externally_visible,
            evidence_complete=True,
        )

    if contract.side_effects is SideEffectClass.READ_ONLY and externally_visible:
        return ShadowEligibility(
            eligible=False,
            requires_isolation=True,
            reason="read-only function contract conflicts with observed mutating activity",
            observed_effects=effects,
            observed_external_effects=externally_visible,
            evidence_complete=True,
        )

    return ShadowEligibility(
        eligible=True,
        requires_isolation=False,
        reason="contract and complete observed effect evidence permit duplicate execution",
        observed_effects=effects,
        observed_external_effects=externally_visible,
        evidence_complete=True,
    )


def _category_for_event(kind: BehaviorEventKind) -> ExecutionEffectCategory | None:
    if kind in {
        BehaviorEventKind.NETWORK_DNS,
        BehaviorEventKind.NETWORK_CONNECT,
        BehaviorEventKind.NETWORK_SEND,
    }:
        return ExecutionEffectCategory.NETWORK
    if kind in {
        BehaviorEventKind.FILE_OPEN,
        BehaviorEventKind.FILE_READ,
        BehaviorEventKind.FILE_WRITE,
        BehaviorEventKind.DIRECTORY_LIST,
        BehaviorEventKind.DIRECTORY_WALK,
    }:
        return ExecutionEffectCategory.FILESYSTEM
    if kind is BehaviorEventKind.SUBPROCESS:
        return ExecutionEffectCategory.SUBPROCESS
    if kind is BehaviorEventKind.IMPORT:
        return ExecutionEffectCategory.IMPORT
    if kind is BehaviorEventKind.DYNAMIC_CODE:
        return ExecutionEffectCategory.DYNAMIC_CODE
    if kind is BehaviorEventKind.ENVIRONMENT_READ:
        return ExecutionEffectCategory.ENVIRONMENT
    return None


def _enum_name(value: str) -> str:
    return value.strip().upper().replace("-", "_").replace(" ", "_")
