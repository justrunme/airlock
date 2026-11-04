"""Shared pytest configuration."""

import os
import shutil
import subprocess


def pytest_report_header(config):
    """Report which container runtime the Docker tests will use."""
    requested = os.environ.get("AIRLOCK_RUNTIME") or "auto-detect (runsc if installed, else runc)"
    available = "no docker CLI"
    if shutil.which("docker"):
        try:
            out = subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            available = out.stdout.strip() if out.returncode == 0 else "daemon unreachable"
        except (OSError, subprocess.SubprocessError):
            available = "daemon unreachable"
    return [f"airlock runtime: {requested}", f"docker runtimes: {available[:200]}"]
