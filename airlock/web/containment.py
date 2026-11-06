"""Runtime containment probe used by the demo Arena path.

These snippets are intentionally policy-allowable: they pass the production
gate and are stopped by the sandbox (timeout / limits), not by a deny verdict.
The production gate is not loosened for this demo.
"""

from __future__ import annotations

import uuid
from typing import Any

from airlock.schemas import ActionRequest
from airlock.web.pipeline import Pipeline

# Wall-clock sleep longer than arena timeout_s (10). Policy allows time.sleep;
# the sandbox watchdog kills the container and records killed_by=timeout.
TIMEOUT_PROBE_CODE = (
    "import time\n"
    "print('containment probe: sleeping past the wall-clock timeout')\n"
    "time.sleep(100)\n"
    "print('should not reach')\n"
)

HEALTHY_CODE = "print(1+1)\n"

CONTAINMENT_CONTEXT = {"mode": "live", "planner": "arena", "probe": "timeout"}
HEALTHY_CONTEXT = {"mode": "live", "planner": "arena", "probe": "healthy_followup"}


def _action(task_id: str, n: int, code: str, caps: dict[str, Any]) -> ActionRequest:
    return ActionRequest(
        id=f"{task_id}-a{n}",
        task_id=task_id,
        tool="run_code",
        lang="python",
        code=code,
        network="none",
        requested=dict(caps),
    )


def run_containment_then_healthy(pipeline: Pipeline, caps: dict[str, Any]) -> dict[str, Any]:
    """Run a timeout probe, then a healthy print, through the real pipeline.

    Both actions go through the same policy + sandbox + verifier + receipt path
    as Arena submissions. The probe must be allowed by the gate and terminated
    by the sandbox; the follow-up must succeed with cleanup evidence.
    """
    task_id = f"contain-{uuid.uuid4().hex[:12]}"
    probe = pipeline.run_action(
        _action(task_id, 1, TIMEOUT_PROBE_CODE, caps),
        None,
        None,
        context=CONTAINMENT_CONTEXT,
    )
    probe["label"] = "1. Runtime containment: sleep past the wall-clock timeout"
    probe["intent"] = "containment_probe"
    healthy = pipeline.run_action(
        _action(task_id, 2, HEALTHY_CODE, caps),
        None,
        None,
        context=HEALTHY_CONTEXT,
    )
    healthy["label"] = "2. Healthy follow-up: print(1+1) after the probe"
    healthy["intent"] = "healthy"
    return {
        "task_id": task_id,
        "kind": "containment_then_healthy",
        "mode": "live",
        "planner": "arena",
        "steps": [probe, healthy],
    }
