from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol


@dataclass(frozen=True, slots=True)
class MaskingResult:
    masked_args: tuple[Any, ...]
    masked_kwargs: Mapping[str, Any]
    structural_metadata: Mapping[str, Any] = field(default_factory=dict)
    stable_tokens: Mapping[str, str] = field(default_factory=dict)
    fully_removed_fields: tuple[str, ...] = ()
    format_preserved_fields: tuple[str, ...] = ()


class MaskFunction(Protocol):
    def __call__(
        self,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> MaskingResult | tuple[tuple[Any, ...], Mapping[str, Any]]:
        ...


def apply_mask(
    mask: MaskFunction | None,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> MaskingResult:
    if mask is None:
        return MaskingResult(masked_args=args, masked_kwargs=dict(kwargs))
    result = mask(args, kwargs)
    if isinstance(result, MaskingResult):
        return result
    masked_args, masked_kwargs = result
    return MaskingResult(masked_args=tuple(masked_args), masked_kwargs=dict(masked_kwargs))


def mask_card_number(value: str, *, preserve_last: int = 4) -> tuple[str, Mapping[str, Any]]:
    digits = "".join(character for character in value if character.isdigit())
    suffix = digits[-preserve_last:] if preserve_last else ""
    hidden = max(0, len(digits) - len(suffix))
    masked_digits = "X" * hidden + suffix
    groups = [masked_digits[index:index + 4] for index in range(0, len(masked_digits), 4)]
    return "-".join(groups), {
        "original_length": len(digits),
        "digit_only": bool(digits) and len(digits) == len(value.replace("-", "").replace(" ", "")),
        "format_preserved": True,
    }
