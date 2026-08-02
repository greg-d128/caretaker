def broken_divide(total: float, count: int) -> float:
    return total / count


def classify(value: int) -> str:
    if value >= 0:
        return "positive"
    return "negative"


def returns_bad_shape(value: int) -> dict[str, int]:
    return {"unexpected": value}


def bad_payload(value: int) -> dict[str, int]:
    return {"unexpected": value}


def slow_identity(value: int) -> int:
    import time
    time.sleep(0.02)
    return value

import logging
import time

_retry_counter = 0


def reset_retry_counter() -> None:
    global _retry_counter
    _retry_counter = 0


def retry_gate() -> bool:
    global _retry_counter
    _retry_counter += 1
    return _retry_counter < 2


def always_fails(value: int) -> int:
    raise ValueError("broken")


def invalid_result(value: int) -> int:
    return -1


def slow_result(value: int) -> int:
    time.sleep(0.02)
    return value


def logged_failure(value: int) -> int:
    logging.getLogger("caretaker-test.application").warning(
        "processing value=%s token=super-secret-token", value
    )
    raise ValueError("logged failure")
