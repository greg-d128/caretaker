from __future__ import annotations

import logging
from pathlib import Path

from caretaker.logging import OperatorLoggingPolicy, configure, logged


runtime = configure(
    OperatorLoggingPolicy.application_defaults(
        directory=str(Path("./caretaker-demo-data")),
        application_id="logging-demo",
    ),
    attach_root=True,
)
logger = logging.getLogger("demo")
logger.setLevel(logging.INFO)


@logged(timing=True, exceptions=True, baseline_dimensions=("kind",))
def calculate(kind: str, value: int) -> int:
    logger.info("calculating", extra={"kind": kind})
    return value * 2


try:
    print(calculate("ordinary", 21))
finally:
    runtime.close()
