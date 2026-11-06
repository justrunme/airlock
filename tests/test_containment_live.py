"""Live Docker proofs for timeout/memory containment through Policy→Pipeline→Sandbox.

Skipped when Docker is unavailable. FakeRunner wiring tests do not substitute for these.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock.policy import PolicyEngine
from airlock.sandbox import SandboxRunner
from airlock.schemas import ActionRequest
from airlock.verifier import Verifier
from airlock.web.chain import ReceiptChain, load_or_create_signer
from airlock.web.containment import (
    MEMORY_PROBE_CODE,
    TIMEOUT_PROBE_CODE,
    evaluate_pair,
    run_containment_then_healthy,
)
from airlock.web.limits import Gate
from airlock.web.pipeline import Pipeline


def docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=5)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return True


pytestmark = pytest.mark.skipif(
    not docker_available(), reason="Docker required for live containment proof"
)


def _pipeline(tmp: Path) -> Pipeline:
    return Pipeline(
        PolicyEngine(),
        SandboxRunner,
        ReceiptChain(tmp / "receipts", load_or_create_signer(tmp / "keys")),
        tmp / "work",
        Gate(2),
        Verifier(),
    )


@pytest.mark.parametrize(
    ("probe", "code", "killed"),
    [
        ("timeout", TIMEOUT_PROBE_CODE, "timeout"),
        ("memory", MEMORY_PROBE_CODE, "oom"),
    ],
)
def test_live_probe_through_pipeline(tmp_path, probe, code, killed):
    """Real gate allow → sandbox kill → healthy follow-up. Not FakeRunner."""
    d = PolicyEngine().evaluate(
        ActionRequest(
            id="pre",
            task_id="t",
            tool="run_code",
            lang="python",
            code=code,
            network="none",
            requested={"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32},
        )
    )
    assert d.verdict == "allow", (d.rules_fired, d.reason)

    caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}
    if probe == "timeout":
        caps = {**caps, "timeout_s": 2}

    out = run_containment_then_healthy(_pipeline(tmp_path), caps, probe)
    assert out["incomplete"] is False
    probe_step, healthy = out["steps"]
    assert probe_step["verdict"] == "allow"
    assert probe_step["execution"]["killed_by"] == killed
    assert healthy["execution"]["exit_code"] == 0
    assert (healthy["execution"]["stdout"] or "").strip() == "2"
    assert probe_step["cleanup"]["container_absent"] is True
    assert healthy["cleanup"]["container_absent"] is True
    assert evaluate_pair(probe, probe_step, healthy)["state"] == "PASS"


def test_live_gate_still_denies_zip_tmp_and_fancyurlopener():
    """Negative: hardened entry points never reach Docker."""
    for code in (
        "from urllib.request import FancyURLopener\n"
        "FancyURLopener().retrieve('http://203.0.113.50/x','/work/out/x')\n",
        "import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall('/tmp')\n",
    ):
        d = PolicyEngine().evaluate(
            ActionRequest(
                id="a",
                task_id="t",
                tool="run_code",
                lang="python",
                code=code,
                network="none",
                requested={"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32},
            )
        )
        assert d.verdict == "deny"
