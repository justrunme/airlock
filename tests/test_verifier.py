"""Tests for verifier (V29-V34)."""

import subprocess
import tempfile
from pathlib import Path

import pytest

from airlock.sandbox import SandboxRunner
from airlock.schemas import ActionRequest
from airlock.verifier import Verifier


def docker_available() -> bool:
    """Check if Docker is available."""
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


class TestVerifier:
    """Test verifier checks V29-V34."""

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_v29_container_absent_after_run(self):
        """V29: Container absent after run."""
        runner = SandboxRunner()
        verifier = Verifier()

        action = ActionRequest(
            id="act_v29",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('hello')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))

            cleanup = verifier.verify_cleanup(execution.container_name)
            assert cleanup.container_absent

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_v30_absent_after_timeout_kill(self):
        """V30: Absent after timeout kill."""
        runner = SandboxRunner()
        verifier = Verifier()

        action = ActionRequest(
            id="act_v30",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="sleep 100",
        )
        caps = {"timeout_s": 2, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))
            assert execution.killed_by == "timeout"

            cleanup = verifier.verify_cleanup(execution.container_name)
            assert cleanup.container_absent

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_v31_absent_after_oom(self):
        """V31: Absent after OOM."""
        runner = SandboxRunner()
        verifier = Verifier()

        action = ActionRequest(
            id="act_v31",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="x = ' ' * (200 * 1024 * 1024)",
        )
        caps = {"timeout_s": 10, "mem_mb": 64, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))

            cleanup = verifier.verify_cleanup(execution.container_name)
            assert cleanup.container_absent

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_v32_no_dangling_networks(self):
        """V32: No dangling networks/volumes."""
        runner = SandboxRunner()
        verifier = Verifier()

        action = ActionRequest(
            id="act_v32",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('hello')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))

            cleanup = verifier.verify_cleanup(execution.container_name)
            assert cleanup.network_absent

    def test_v33_secret_in_output_flagged(self):
        """V33: Secret planted in output → flagged."""
        verifier = Verifier()

        output = "Here is a secret: AKIAIOSFODNN7EXAMPLE"
        scan_result, flagged = verifier._scan_for_secrets(output)

        assert scan_result == "flagged"
        assert len(flagged) > 0

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_v34_artifact_hashes_match(self):
        """V34: Write known file in /work/out, verify artifact with independent sha256."""
        from hashlib import sha256

        runner = SandboxRunner()

        known_content = b"Test file with known content for V34 verification"
        expected_hash = sha256(known_content).hexdigest()

        action = ActionRequest(
            id="act_v34",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code=f"with open('/work/out/test_output.txt', 'wb') as f: f.write({repr(known_content)})",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            work_dir = Path(tmpdir)
            execution = runner.run(action, caps, work_dir)

            # Verify artifact is in result
            artifact = next((a for a in execution.artifacts if a.name == "test_output.txt"), None)
            assert artifact is not None, (
                f"Artifact not found. Got: {[a.name for a in execution.artifacts]}"
            )

            # Verify sha256 matches independently computed hash
            assert artifact.sha256 == expected_hash


def _exec(**kw):
    from airlock.schemas import Execution

    base = {
        "container_name": "airlock-x",
        "image_digest": "sha256:" + "0" * 64,
        "runtime": "runc",
        "started": "s",
        "ended": "e",
        "exit_code": 0,
        "stdout_sha256": "0" * 64,
    }
    base.update(kw)
    return Execution(**base)


def _check(v, cid):
    return next(c for c in v.checks if c.id == cid)


def test_truncation_and_dropped_artifacts_flagged():
    from airlock.schemas import DroppedArtifact
    from airlock.verifier import Verifier

    ex = _exec(
        stdout_truncated=True,
        artifacts_dropped=[DroppedArtifact(path="big", size=20_000_000, reason="over_size_cap")],
    )
    v = Verifier().verify(ex, {}, "")
    assert _check(v, "V-OUTPUT-COMPLETE").pass_ is False
    assert "stdout" in _check(v, "V-OUTPUT-COMPLETE").detail
    assert _check(v, "V-ARTIFACTS-COMPLETE").pass_ is False
    assert "big (20000000 B, over_size_cap)" in _check(v, "V-ARTIFACTS-COMPLETE").detail


def test_complete_output_passes_and_invalid_report_fails():
    from airlock.verifier import Verifier

    v = Verifier().verify(_exec(), {}, "")
    assert _check(v, "V-OUTPUT-COMPLETE").pass_ is True
    assert _check(v, "V-ARTIFACTS-COMPLETE").pass_ is True
    assert _check(v, "V-REPORT-VALID").pass_ is True
    v = Verifier().verify(_exec(report_invalid=True, exit_code=137), {}, "")
    assert _check(v, "V-REPORT-VALID").pass_ is False


def test_truncation_flags_are_in_signed_receipt(tmp_path):
    """S5: the flags are part of the signed Execution, so tampering breaks the signature."""
    from airlock.receipt import ReceiptSigner
    from airlock.schemas import DroppedArtifact

    ex = _exec(
        stderr_truncated=True,
        artifacts_dropped=[DroppedArtifact(path="f64", size=3, reason="too_many_files")],
    )
    dumped = ex.model_dump(mode="json")
    assert dumped["stderr_truncated"] is True
    assert dumped["artifacts_dropped"] == [{"path": "f64", "size": 3, "reason": "too_many_files"}]
    from airlock.schemas import BlastRadius, BlastRadiusFactor, Decision

    decision = Decision(
        action_id="a",
        verdict="allow",
        blast_radius=BlastRadius(
            score=1, factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1")
        ),
        caps={},
        policy_sha256="0" * 64,
    )
    signer = ReceiptSigner()
    receipt = signer.sign({"task_id": "t", "action_id": "a", "decision": decision, "execution": ex})
    assert receipt.execution.stderr_truncated is True
    assert signer.verify(receipt)
    tampered = receipt.model_copy(deep=True)
    tampered.execution.stderr_truncated = False
    assert not signer.verify(tampered)
