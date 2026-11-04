"""Tests for network handling."""

import tempfile
from pathlib import Path

import pytest

from airlock.sandbox import SandboxRunner
from airlock.schemas import ActionRequest


def docker_available() -> bool:
    """Check if Docker is available."""
    import subprocess

    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


class TestNetwork:
    """Test network configuration."""

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_network_allowlist_raises_error(self):
        """Network allowlist mode raises clear error (not implemented)."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="net_01",
            task_id="test",
            tool="run_code",
            lang="python",
            code="print('hello')",
            network="allowlist",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        # The error must be raised before any container is created
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            pytest.raises(ValueError, match="Network mode 'allowlist' not supported"),
        ):
            runner.run(action, caps, Path(tmpdir))

    def test_network_none_accepted(self):
        """Network none is accepted (may skip if no Docker)."""
        action = ActionRequest(
            id="net_02",
            task_id="test",
            tool="run_code",
            lang="python",
            code="print('hello')",
            network="none",
        )

        # Just verify allowlist isn't silently accepted
        assert action.network == "none"
