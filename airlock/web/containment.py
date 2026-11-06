"""Runtime containment probes used by the demo Arena path.

Each snippet is intentionally policy-allowable: it passes the production gate
and is stopped by the sandbox (timeout / memory / read-only rootfs / network
none), not by a deny verdict. The production gate is not loosened for this
demo. Timeout was the first filmable probe; memory, write-outside and egress
use the same Pipeline path.
"""

from __future__ import annotations

import io
import uuid
import zipfile
from typing import Any, Literal

from airlock.schemas import ActionRequest
from airlock.web.pipeline import Pipeline

ProbeName = Literal["timeout", "memory", "write", "egress"]

# Wall-clock sleep longer than arena timeout_s (10). Policy allows time.sleep;
# the sandbox watchdog kills the container and records killed_by=timeout.
TIMEOUT_PROBE_CODE = (
    "import time\n"
    "print('containment probe: sleeping past the wall-clock timeout')\n"
    "time.sleep(100)\n"
    "print('should not reach')\n"
)

# Constant-size allocs are denied (R-PY-HUGE-ALLOC); a loop of 1 MiB chunks is
# allow-listed and hits the cgroup memory cap (arena mem_mb=128).
MEMORY_PROBE_CODE = (
    "print('containment probe: allocating past the memory cap')\n"
    "chunks = []\n"
    "for i in range(400):\n"
    "    chunks.append(' ' * (1024 * 1024))\n"
    "print('should not reach', len(chunks))\n"
)

# zipfile.extractall destination is not path-checked by the current gate;
# extract onto read-only rootfs fails with EROFS inside the sandbox.
WRITE_PROBE_CODE = (
    "import zipfile\n"
    "print('containment probe: extract outside /work/out onto read-only rootfs')\n"
    "z = zipfile.ZipFile('/work/input/probe.zip')\n"
    "try:\n"
    "    z.extractall('/')\n"
    "    print('WRITE_UNEXPECTED_SUCCESS')\n"
    "except OSError as e:\n"
    "    print('WRITE_BLOCKED', e)\n"
)

# FancyURLopener.retrieve is allow-listed; --network none makes the fetch fail.
EGRESS_PROBE_CODE = (
    "from urllib.request import FancyURLopener\n"
    "print('containment probe: HTTP retrieve under network=none')\n"
    "op = FancyURLopener()\n"
    "try:\n"
    "    op.retrieve('http://203.0.113.50/probe', '/work/out/egress.txt')\n"
    "    print('EGRESS_UNEXPECTED_SUCCESS')\n"
    "except OSError as e:\n"
    "    print('EGRESS_BLOCKED', e)\n"
)

HEALTHY_CODE = "print(1+1)\n"

PROBE_CODES: dict[ProbeName, str] = {
    "timeout": TIMEOUT_PROBE_CODE,
    "memory": MEMORY_PROBE_CODE,
    "write": WRITE_PROBE_CODE,
    "egress": EGRESS_PROBE_CODE,
}

PROBE_LABELS: dict[ProbeName, str] = {
    "timeout": "Runtime containment: sleep past the wall-clock timeout",
    "memory": "Runtime containment: allocate past the memory cap",
    "write": "Runtime containment: write outside /work/out (read-only rootfs)",
    "egress": "Runtime containment: blocked egress under network=none",
}

HEALTHY_CONTEXT = {"mode": "live", "planner": "arena", "probe": "healthy_followup"}


def probe_zip_bytes() -> bytes:
    """Tiny zip for the write-outside probe (member extracted onto '/')."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("probe.txt", "airlock-write-outside-probe\n")
    return buf.getvalue()


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


def _run_one(
    pipeline: Pipeline,
    caps: dict[str, Any],
    probe: ProbeName,
    task_id: str,
    index: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    inputs = {"probe.zip": probe_zip_bytes()} if probe == "write" else None
    probe_step = pipeline.run_action(
        _action(task_id, index, PROBE_CODES[probe], caps),
        inputs,
        None,
        context={"mode": "live", "planner": "arena", "probe": probe},
    )
    probe_step["label"] = f"{index}. {PROBE_LABELS[probe]}"
    probe_step["intent"] = "containment_probe"
    probe_step["probe"] = probe
    healthy = pipeline.run_action(
        _action(task_id, index + 1, HEALTHY_CODE, caps),
        None,
        None,
        context=dict(HEALTHY_CONTEXT, after_probe=probe),
    )
    healthy["label"] = f"{index + 1}. Healthy follow-up after {probe}: print(1+1)"
    healthy["intent"] = "healthy"
    healthy["probe"] = "healthy_followup"
    return probe_step, healthy


def run_containment_then_healthy(
    pipeline: Pipeline,
    caps: dict[str, Any],
    probe: ProbeName = "timeout",
) -> dict[str, Any]:
    """Run one runtime probe, then a healthy print, through the real pipeline."""
    if probe not in PROBE_CODES:
        raise ValueError(f"unknown probe: {probe}")
    task_id = f"contain-{uuid.uuid4().hex[:12]}"
    probe_step, healthy = _run_one(pipeline, caps, probe, task_id, 1)
    return {
        "task_id": task_id,
        "kind": "containment_then_healthy",
        "mode": "live",
        "planner": "arena",
        "probe": probe,
        "steps": [probe_step, healthy],
    }


def run_containment_suite(pipeline: Pipeline, caps: dict[str, Any]) -> dict[str, Any]:
    """Run timeout, memory, write-outside and egress probes, each with a healthy follow-up."""
    task_id = f"contain-suite-{uuid.uuid4().hex[:12]}"
    steps: list[dict[str, Any]] = []
    n = 1
    for name in ("timeout", "memory", "write", "egress"):
        probe_step, healthy = _run_one(pipeline, caps, name, task_id, n)  # type: ignore[arg-type]
        steps.extend([probe_step, healthy])
        n += 2
    return {
        "task_id": task_id,
        "kind": "containment_suite",
        "mode": "live",
        "planner": "arena",
        "probe": "all",
        "steps": steps,
    }
