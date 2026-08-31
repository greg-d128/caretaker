"""Process entrypoint for the reviewed failure-corpus oracle mappings.

This is a contract fixture, not an implementation of the application
stimuli. It is intentionally separate from ``manifest.json`` and returns only
the reviewed expected observation for the requested scenario.
"""

from __future__ import annotations

import json
import sys

from trusted_mappings import result_for_scenario


def main() -> int:
    request = json.load(sys.stdin)
    scenario = request.get("scenario") if isinstance(request, dict) else None
    scenario_id = scenario.get("scenario_id") if isinstance(scenario, dict) else None
    if not isinstance(scenario_id, str):
        raise SystemExit("scenario request must contain scenario.scenario_id")
    print(json.dumps(result_for_scenario(scenario_id), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
