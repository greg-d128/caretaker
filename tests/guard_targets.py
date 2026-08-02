from __future__ import annotations


def stable(value: int) -> int:
    return value


def failing(value: int) -> int:
    raise ValueError("broken")


def ordinary(value: int) -> int:
    return value + 1


def replacement_shape(value: int) -> int:
    return value * 100
