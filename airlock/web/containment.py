"""Runtime containment probes used by the demo Arena path.

Only probes that pass the *current* production gate and fail closed at the
sandbox are offered as filmable runtime containment. Timeout and memory meet
that bar. Write-outside and egress are not staged via policy gaps: those entry
points are denied by the gate (zip extract destinations, FancyURLopener /
retrieve). Gate deny vs sandbox containment stay distinct.

Each probe result carries structured evidence: PASS / FAILED / INCONCLUSIVE /
UNSUPPORTED. Green (PASS) requires gate allow, mechanism evidence, a healthy
follow-up with exit 0 and stdout ``2``, and cleanup. Unexpected success is
FAILED. Busy/error mid-suite preserves completed steps.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from airlock.schemas import ActionRequest
from airlock.web.limits import BusyError
from airlock.web.pipeline import Pipeline

ProbeName = Literal["timeout", "memory"]
SupportedProbe = ProbeName
# Named for honesty in the API surface; these are not runnable runtime demos.
UnsupportedProbe = Literal["write", "egress"]
AnyProbe = Literal["timeout", "memory", "write", "egress"]

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

HEALTHY_CODE = "print(1+1)\n"

PROBE_CODES: dict[SupportedProbe, str] = {
    "timeout": TIMEOUT_PROBE_CODE,
    "memory": MEMORY_PROBE_CODE,
}

PROBE_LABELS: dict[SupportedProbe, str] = {
    "timeout": "Runtime containment: sleep past the wall-clock timeout",
    "memory": "Runtime containment: allocate past the memory cap",
}

# Mechanism evidence required for PASS (sandbox identity, not a soft stdout tag).
PROBE_EXPECT: dict[SupportedProbe, dict[str, str]] = {
    "timeout": {"killed_by": "timeout"},
    "memory": {"killed_by": "oom"},
}

UNSUPPORTED: dict[UnsupportedProbe, dict[str, str]] = {
    "write": {
        "reason": (
            "Write-outside is not offered as a runtime containment demo: "
            "zipfile.extract/extractall destinations outside /work/out/ are "
            "denied by the production gate (R-PY-ZIP-EXTRACT). Rootfs "
            "read-only does not protect writable tmpfs mounts such as /tmp; "
            "those must stay gate-denied. See tests/test_sandbox.py S15 for "
            "direct sandbox read-only proofs that bypass the gate."
        ),
        "gate_rule": "R-PY-ZIP-EXTRACT",
    },
    "egress": {
        "reason": (
            "Blocked egress is not offered as a runtime containment demo: "
            "network-capable urllib entry points (FancyURLopener, retrieve, "
            "urlopen, urlretrieve) are denied by the production gate. "
            "--network none remains the sandbox backstop for anything that "
            "still reaches a container. See tests/test_sandbox.py S19/S20."
        ),
        "gate_rule": "R-PY-ATTR-DENIED",
    },
}

SUITE_PROBES: tuple[SupportedProbe, ...] = ("timeout", "memory")
# Each supported probe runs one containment action + one healthy follow-up.
SLOTS_PER_PROBE = 2

HEALTHY_CONTEXT = {"mode": "live", "planner": "arena", "probe": "healthy_followup"}


def slots_for(mode: str, probe: AnyProbe | None = None) -> int:
    """Arena rate-limit slots required for an atomic admission."""
    if mode == "containment_suite":
        return SLOTS_PER_PROBE * len(SUITE_PROBES)
    if probe in UNSUPPORTED:
        return 0
    return SLOTS_PER_PROBE


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


def _cleanup_ok(step: dict[str, Any]) -> bool:
    clean = step.get("cleanup") or {}
    return bool(clean.get("container_absent")) and bool(clean.get("network_absent"))


def evaluate_pair(
    probe: SupportedProbe, probe_step: dict[str, Any], healthy: dict[str, Any]
) -> dict[str, Any]:
    """Structured PASS/FAILED/INCONCLUSIVE for one probe + healthy follow-up."""
    expect = PROBE_EXPECT[probe]
    evidence: dict[str, Any] = {
        "probe": probe,
        "gate_verdict": probe_step.get("verdict"),
        "probe_status": probe_step.get("status"),
        "killed_by": (probe_step.get("execution") or {}).get("killed_by"),
        "probe_exit": (probe_step.get("execution") or {}).get("exit_code"),
        "healthy_exit": (healthy.get("execution") or {}).get("exit_code"),
        "healthy_stdout": (healthy.get("execution") or {}).get("stdout"),
        "probe_cleanup_ok": _cleanup_ok(probe_step),
        "healthy_cleanup_ok": _cleanup_ok(healthy),
        "required_killed_by": expect["killed_by"],
    }
    if probe_step.get("status") == "error" or healthy.get("status") == "error":
        return {
            "state": "INCONCLUSIVE",
            "reason": "sandbox error before mechanism evidence was observed",
            "evidence": evidence,
        }
    if probe_step.get("verdict") != "allow":
        return {
            "state": "INCONCLUSIVE",
            "reason": "gate denied the probe; this path is for runtime containment, not gate deny",
            "evidence": evidence,
        }
    killed = evidence["killed_by"]
    stdout = (probe_step.get("execution") or {}).get("stdout") or ""
    if killed is None and "should not reach" in stdout:
        return {
            "state": "FAILED",
            "reason": "unexpected success: probe finished without the expected kill",
            "evidence": evidence,
        }
    if killed != expect["killed_by"]:
        return {
            "state": "FAILED" if killed else "INCONCLUSIVE",
            "reason": (
                f"expected killed_by={expect['killed_by']}, got {killed!r}"
                if killed
                else "missing killed_by mechanism evidence"
            ),
            "evidence": evidence,
        }
    healthy_stdout = (evidence["healthy_stdout"] or "").strip()
    if (
        healthy.get("verdict") == "allow"
        and evidence["healthy_exit"] == 0
        and healthy_stdout == "2"
        and evidence["probe_cleanup_ok"]
        and evidence["healthy_cleanup_ok"]
    ):
        return {
            "state": "PASS",
            "reason": f"sandbox killed_by={killed}; healthy follow-up exit 0 stdout 2; cleanup ok",
            "evidence": evidence,
        }
    return {
        "state": "FAILED",
        "reason": "mechanism kill observed but healthy follow-up or cleanup did not check out",
        "evidence": evidence,
    }


def unsupported_result(probe: UnsupportedProbe) -> dict[str, Any]:
    meta = UNSUPPORTED[probe]
    return {
        "task_id": None,
        "kind": "containment_unsupported",
        "mode": "live",
        "planner": "arena",
        "probe": probe,
        "steps": [],
        "result": {
            "state": "UNSUPPORTED",
            "reason": meta["reason"],
            "gate_rule": meta["gate_rule"],
        },
        "incomplete": False,
    }


def _probe_step(
    pipeline: Pipeline,
    caps: dict[str, Any],
    probe: SupportedProbe,
    task_id: str,
    index: int,
) -> dict[str, Any]:
    step = pipeline.run_action(
        _action(task_id, index, PROBE_CODES[probe], caps),
        None,
        None,
        context={"mode": "live", "planner": "arena", "probe": probe},
    )
    step["label"] = f"{index}. {PROBE_LABELS[probe]}"
    step["intent"] = "containment_probe"
    step["probe"] = probe
    return step


def _healthy_step(
    pipeline: Pipeline,
    caps: dict[str, Any],
    probe: SupportedProbe,
    task_id: str,
    index: int,
) -> dict[str, Any]:
    step = pipeline.run_action(
        _action(task_id, index, HEALTHY_CODE, caps),
        None,
        None,
        context=dict(HEALTHY_CONTEXT, after_probe=probe),
    )
    step["label"] = f"{index}. Healthy follow-up after {probe}: print(1+1)"
    step["intent"] = "healthy"
    step["probe"] = "healthy_followup"
    return step


def _unexecuted_healthy(probe: SupportedProbe, index: int, reason: str) -> dict[str, Any]:
    return {
        "label": f"{index}. Healthy follow-up after {probe}: unexecuted",
        "intent": "healthy",
        "probe": "healthy_followup",
        "status": "unexecuted",
        "verdict": None,
        "error": reason,
        "after_probe": probe,
    }


def _busy_payload(
    *,
    task_id: str,
    kind: str,
    probe: str,
    steps: list[dict[str, Any]],
    results: list[dict[str, Any]],
    remaining: list[str],
    reason: str,
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "kind": kind,
        "mode": "live",
        "planner": "arena",
        "probe": probe,
        "steps": steps,
        "results": results,
        "result": {
            "state": "INCONCLUSIVE",
            "reason": reason,
            "completed": results,
        },
        "incomplete": True,
        "remaining": remaining,
        "error": "busy",
    }


def run_containment_then_healthy(
    pipeline: Pipeline,
    caps: dict[str, Any],
    probe: AnyProbe = "timeout",
) -> dict[str, Any]:
    """Run one supported runtime probe + healthy follow-up, or return UNSUPPORTED.

    Each sandbox action is recorded before the next slot is requested. Busy on
    the healthy follow-up keeps the completed probe receipt/cleanup and marks
    healthy as unexecuted (never claims nothing started).
    """
    if probe in UNSUPPORTED:
        return unsupported_result(probe)  # type: ignore[arg-type]
    if probe not in PROBE_CODES:
        raise ValueError(f"unknown probe: {probe}")
    task_id = f"contain-{uuid.uuid4().hex[:12]}"
    steps: list[dict[str, Any]] = []
    try:
        probe_step = _probe_step(pipeline, caps, probe, task_id, 1)  # type: ignore[arg-type]
    except BusyError:
        return _busy_payload(
            task_id=task_id,
            kind="containment_then_healthy",
            probe=probe,
            steps=[],
            results=[],
            remaining=[probe, "healthy_followup"],
            reason="busy: no sandbox slot available before the probe started",
        )
    steps.append(probe_step)
    try:
        healthy = _healthy_step(pipeline, caps, probe, task_id, 2)  # type: ignore[arg-type]
    except BusyError:
        steps.append(_unexecuted_healthy(probe, 2, "busy"))  # type: ignore[arg-type]
        return _busy_payload(
            task_id=task_id,
            kind="containment_then_healthy",
            probe=probe,
            steps=steps,
            results=[],
            remaining=["healthy_followup"],
            reason="busy: probe completed; healthy follow-up not started",
        )
    steps.append(healthy)
    result = evaluate_pair(probe, probe_step, healthy)  # type: ignore[arg-type]
    probe_step["containment_result"] = result
    healthy["containment_result"] = result
    return {
        "task_id": task_id,
        "kind": "containment_then_healthy",
        "mode": "live",
        "planner": "arena",
        "probe": probe,
        "steps": steps,
        "result": result,
        "incomplete": False,
    }


def run_containment_suite(pipeline: Pipeline, caps: dict[str, Any]) -> dict[str, Any]:
    """Run timeout then memory, each with a healthy follow-up (4 arena slots).

    Fits the default AIRLOCK_ARENA_PER_MIN=6 budget. Records every completed
    action before requesting the next slot so Busy mid-pair (action 2 or 4)
    preserves the probe receipt/cleanup.
    """
    task_id = f"contain-suite-{uuid.uuid4().hex[:12]}"
    steps: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    n = 1
    remaining = list(SUITE_PROBES)
    while remaining:
        name = remaining[0]
        try:
            probe_step = _probe_step(pipeline, caps, name, task_id, n)
        except BusyError:
            return _busy_payload(
                task_id=task_id,
                kind="containment_suite",
                probe="suite",
                steps=steps,
                results=results,
                remaining=[name, "healthy_followup", *remaining[1:]],
                reason="busy: sandbox contention before next probe; completed actions kept",
            )
        steps.append(probe_step)
        try:
            healthy = _healthy_step(pipeline, caps, name, task_id, n + 1)
        except BusyError:
            steps.append(_unexecuted_healthy(name, n + 1, "busy"))
            rem = ["healthy_followup", *remaining[1:]]
            return _busy_payload(
                task_id=task_id,
                kind="containment_suite",
                probe="suite",
                steps=steps,
                results=results,
                remaining=rem,
                reason=f"busy: {name} probe completed; healthy follow-up not started",
            )
        steps.append(healthy)
        result = evaluate_pair(name, probe_step, healthy)
        probe_step["containment_result"] = result
        healthy["containment_result"] = result
        results.append(result)
        remaining.pop(0)
        n += 2
    states = {r["state"] for r in results}
    if states == {"PASS"}:
        overall = "PASS"
        reason = "timeout and memory probes contained with healthy follow-ups"
    elif "FAILED" in states:
        overall = "FAILED"
        reason = "at least one supported probe failed its evidence checks"
    else:
        overall = "INCONCLUSIVE"
        reason = "supported probes did not all produce PASS evidence"
    return {
        "task_id": task_id,
        "kind": "containment_suite",
        "mode": "live",
        "planner": "arena",
        "probe": "suite",
        "steps": steps,
        "results": results,
        "result": {"state": overall, "reason": reason, "completed": results},
        "incomplete": False,
    }
