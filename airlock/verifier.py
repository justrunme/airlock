"""Post-execution verification."""

import re
import subprocess
from typing import Any

from airlock.schemas import Cleanup, Execution, Verification, VerificationCheck


class Verifier:
    """Verifies execution results and cleanup."""

    SECRET_PATTERNS = [
        r"[A-Z0-9]{32,}",  # Generic long uppercase alphanumeric
        r"sk-[a-zA-Z0-9]{32,}",  # sk- style keys
        r"xox[baprs]-[a-zA-Z0-9-]{10,}",  # Slack tokens
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub tokens
        r"AKIA[0-9A-Z]{16}",  # AWS access keys
        r"AIza[0-9A-Za-z_-]{35}",  # Google API keys
    ]

    def __init__(self):
        """Initialize verifier."""
        pass

    def verify(self, execution: Execution, caps: dict[str, Any], output: str) -> Verification:
        """Verify execution results."""
        checks = []

        if execution.exit_code == 0:
            checks.append(VerificationCheck(id="V-EXIT-OK", pass_=True))
        else:
            checks.append(
                VerificationCheck(
                    id="V-EXIT-OK",
                    pass_=False,
                    detail=f"Exit code {execution.exit_code}",
                )
            )

        if execution.killed_by:
            checks.append(
                VerificationCheck(
                    id="V-KILLED",
                    pass_=True,
                    detail=f"Killed by {execution.killed_by}",
                )
            )

        if execution.peak_mem_mb and execution.peak_mem_mb <= caps.get("mem_mb", 256):
            checks.append(VerificationCheck(id="V-MEM-LIMIT", pass_=True))
        elif execution.peak_mem_mb:
            checks.append(
                VerificationCheck(
                    id="V-MEM-LIMIT",
                    pass_=False,
                    detail=f"Memory {execution.peak_mem_mb}MB",
                )
            )

        # The report itself was not trusted (forged, missing, or the
        # container did not end normally).
        checks.append(
            VerificationCheck(
                id="V-REPORT-VALID",
                pass_=not execution.report_invalid,
                detail="report_invalid: output and artifacts discarded"
                if execution.report_invalid
                else None,
            )
        )

        # Output completeness: truncated streams and dropped artifacts fail.
        truncated = [
            name
            for name, flag in (
                ("stdout", execution.stdout_truncated),
                ("stderr", execution.stderr_truncated),
            )
            if flag
        ]
        checks.append(
            VerificationCheck(
                id="V-OUTPUT-COMPLETE",
                pass_=not truncated,
                detail=f"truncated: {', '.join(truncated)}" if truncated else None,
            )
        )
        dropped = execution.artifacts_dropped
        checks.append(
            VerificationCheck(
                id="V-ARTIFACTS-COMPLETE",
                pass_=not dropped,
                detail="dropped: "
                + ", ".join(f"{d.path} ({d.size} B, {d.reason})" for d in dropped[:10])
                if dropped
                else None,
            )
        )

        secret_scan, flagged = self._scan_for_secrets(output)

        return Verification(checks=checks, secret_scan=secret_scan, flagged_patterns=flagged)

    def verify_cleanup(self, container_name: str | None) -> Cleanup:
        """Verify container cleanup."""
        if not container_name:
            return Cleanup(
                container_absent=False,
                network_absent=False,
                evidence="No container name provided - cleanup verification failed",
            )

        # Check if container exists using docker ps -a
        try:
            result = subprocess.run(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--filter",
                    f"name=^/{container_name}$",
                    "--format",
                    "{{.Names}}",
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )

            if result.returncode == 0 and not result.stdout.strip():
                container_absent = True
                evidence = f"Container {container_name} not found in docker ps -a"
            elif result.returncode == 0 and result.stdout.strip():
                container_absent = False
                evidence = f"Container still exists: {container_name}"
            else:
                # Fall back to inspect with case-insensitive error check
                inspect_result = subprocess.run(
                    ["docker", "inspect", container_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if (
                    inspect_result.returncode != 0
                    and "no such object" in inspect_result.stderr.lower()
                ):
                    container_absent = True
                    evidence = "docker inspect: container not found"
                else:
                    container_absent = False
                    evidence = f"Could not verify container absence: {result.stderr.strip()}"

        except subprocess.TimeoutExpired:
            return Cleanup(
                container_absent=False,
                network_absent=False,
                evidence="Verification timeout",
            )

        # Check for dangling networks
        try:
            net_result = subprocess.run(
                [
                    "docker",
                    "network",
                    "ls",
                    "--filter",
                    f"name={container_name}",
                    "--format={{.Name}}",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            network_absent = not net_result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            network_absent = False

        return Cleanup(
            container_absent=container_absent,
            network_absent=network_absent,
            evidence=evidence,
        )

    def _scan_for_secrets(self, text: str) -> tuple[str, list[str]]:
        """Scan text for secret patterns."""
        flagged = []

        for pattern in self.SECRET_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                flagged.extend(matches[:3])

        if flagged:
            return "flagged", flagged
        return "clean", []
