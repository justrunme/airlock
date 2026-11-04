"""Sandbox runner using Docker."""

import base64
import binascii
import contextlib
import io
import json
import os
import secrets
import subprocess
import tarfile
import tempfile
import threading
import uuid
import warnings
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from airlock.schemas import ActionRequest, Artifact, DroppedArtifact, Execution

BOOTSTRAP_SOURCE = (Path(__file__).parent / "bootstrap.py").read_text()


class SandboxRunner:
    """Runs code in isolated Docker containers."""

    DEFAULT_IMAGE = "python:3.12-slim"
    MAX_OUTPUT_SIZE = 1024 * 1024  # 1 MiB per stream, enforced in the bootstrap
    MAX_ARTIFACTS = 64

    def __init__(
        self,
        image: str | None = None,
        runtime: str | None = None,
        inputs_dir: Path | str | None = None,
    ):
        """Initialize sandbox runner.

        ``inputs_dir`` (or AIRLOCK_INPUTS_DIR) is the only host directory that
        ``ActionRequest.files_in`` may read from. Without it, files_in is refused.
        """
        env_inputs = os.environ.get("AIRLOCK_INPUTS_DIR")
        chosen = inputs_dir if inputs_dir is not None else env_inputs
        self.inputs_dir = Path(chosen).resolve(strict=True) if chosen else None
        self.image = image or os.environ.get("AIRLOCK_IMAGE", self.DEFAULT_IMAGE)
        self.runtime = runtime or self._detect_runtime()
        self.image_digest = self._get_image_digest()

    def _detect_runtime(self) -> str:
        """Detect best available runtime."""
        # Check for explicit override
        env_runtime = os.environ.get("AIRLOCK_RUNTIME")
        if env_runtime:
            warnings.warn(
                f"Using explicit AIRLOCK_RUNTIME={env_runtime} override",
                RuntimeWarning,
                stacklevel=2,
            )
            return env_runtime

        # Detect available runtimes
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            runtimes = json.loads(result.stdout.strip())

            # Prefer runsc (gVisor) if available
            if "runsc" in runtimes:
                return "runsc"

            # Fall back to runc
            if "runc" in runtimes:
                return "runc"

            raise RuntimeError(f"No compatible runtime found. Available: {list(runtimes.keys())}")
        except (
            subprocess.CalledProcessError,
            json.JSONDecodeError,
            subprocess.TimeoutExpired,
        ) as e:
            raise RuntimeError(f"Failed to detect Docker runtimes: {e}") from e

    def _get_image_digest(self) -> str:
        """Get the digest of the image."""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", self.image],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            digest_ref = result.stdout.strip()
            if "@sha256:" in digest_ref:
                return digest_ref.split("@")[1]
            return "sha256:unknown"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return "sha256:unknown"

    def _check_runtime(self, requested_runtime: str) -> None:
        """Verify the requested runtime is available."""
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            runtimes = json.loads(result.stdout.strip())
            if requested_runtime not in runtimes:
                raise RuntimeError(
                    f"Requested runtime '{requested_runtime}' not available. "
                    f"Available runtimes: {list(runtimes.keys())}"
                )
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Failed to check Docker runtimes: {e}") from e

    def run(
        self,
        action: ActionRequest,
        caps: dict[str, Any],
        work_dir: Path | None = None,
        input_files: dict[str, bytes] | None = None,
    ) -> Execution:
        """Execute action in sandbox.

        Data path (no host mounts, read-only rootfs): the host builds a tar
        archive with the job and its inputs, streams it to the fixed bootstrap
        program over stdin, and reads one JSON result document back from its
        stdout. Inputs appear under /work/input, outputs are taken from
        /work/out.
        """
        # Validate before touching Docker (raises ValueError for allowlist).
        if action.network != "none":
            raise ValueError(f"Network mode '{action.network}' not supported")

        self._check_runtime(self.runtime)

        container_name = f"airlock-{uuid.uuid4().hex[:16]}"
        started = datetime.now(UTC).isoformat()
        killed_by = None
        watchdog_timer = None

        if work_dir is None:
            work_dir = Path(tempfile.mkdtemp(prefix="airlock-"))

        output_dir = work_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)

        archive = self._build_input_archive(action, input_files)
        # Per-run nonce: first stdin line for the bootstrap only. The job gets
        # /dev/null as stdin and never sees it in argv, env or files.
        nonce = secrets.token_hex(16)

        try:
            # Step 1: Create container (stdin kept open for the archive)
            create_cmd = self._build_docker_create_command(action, caps, container_name)
            subprocess.run(create_cmd, capture_output=True, timeout=30, check=True)

            # Step 2: Start attached with stdin, under a watchdog
            timeout = caps.get("timeout_s", 30)

            def timeout_handler() -> None:
                nonlocal killed_by
                killed_by = "timeout"
                with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                    subprocess.run(
                        ["docker", "kill", container_name],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )

            watchdog_timer = threading.Timer(timeout, timeout_handler)
            watchdog_timer.start()

            start_stdout = b""
            try:
                result = subprocess.run(
                    ["docker", "start", "-a", "-i", container_name],
                    input=nonce.encode() + b"\n" + archive,
                    capture_output=True,
                    timeout=timeout + 15,
                )
                start_stdout = result.stdout or b""
            except subprocess.TimeoutExpired:
                killed_by = "timeout"
                with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                    subprocess.run(
                        ["docker", "kill", container_name],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
            finally:
                watchdog_timer.cancel()

            ended = datetime.now(UTC).isoformat()

            # Step 3: Inspect container for exit code, OOM, runtime
            inspect_data = self._inspect_container(container_name)
            if inspect_data["oom_killed"] and killed_by is None:
                killed_by = "oom"

            report = self._parse_report(start_stdout, nonce)
            notes: list[str] = []
            stdout_truncated = stderr_truncated = False
            dropped: list[DroppedArtifact] = []
            report_invalid = False

            if (
                report is not None
                and "error" not in report
                and killed_by is None
                and inspect_data["exit_code"] == 0
            ):
                exit_code = report["exit_code"]
                stdout = self._b64(report["stdout_b64"])
                stderr = self._b64(report["stderr_b64"])
                stdout_truncated = report["stdout_truncated"]
                stderr_truncated = report["stderr_truncated"]
                artifacts, dropped = self._store_artifacts(report["artifacts"], output_dir)
                dropped += [DroppedArtifact(**d) for d in report["artifacts_dropped"]]
                notes = list(report["notes"])
            else:
                # Never trust anything the container printed in this case.
                exit_code = inspect_data["exit_code"]
                stdout = b""
                artifacts = []
                if report is not None and "error" in report and killed_by is None:
                    stderr = f"bootstrap error: {report['error']}\n".encode()
                    notes = ["bootstrap_error"]
                    if exit_code == 0:
                        exit_code = 2
                else:
                    report_invalid = True
                    stderr = b"Timeout\n" if killed_by == "timeout" else b""
                    notes = ["report_invalid"]
                    if exit_code == 0:
                        # The bootstrap exits 0 only after a valid report.
                        exit_code = 137 if killed_by else 125

            stdout = stdout[: self.MAX_OUTPUT_SIZE]
            stderr = stderr[: self.MAX_OUTPUT_SIZE]
            (output_dir / "stdout.txt").write_bytes(stdout)
            (output_dir / "stderr.txt").write_bytes(stderr)

            return Execution(
                container_name=container_name,
                image_digest=inspect_data["image_digest"],
                runtime=inspect_data["runtime"],
                started=started,
                ended=ended,
                exit_code=exit_code,
                killed_by=killed_by,
                peak_mem_mb=inspect_data["peak_mem_mb"],
                stdout_sha256=sha256(stdout).hexdigest(),
                stderr_sha256=sha256(stderr).hexdigest(),
                artifacts=artifacts,
                report_invalid=report_invalid,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                artifacts_dropped=dropped,
                notes=notes,
            )

        finally:
            if watchdog_timer is not None:
                watchdog_timer.cancel()

            # Step 4: Always cleanup
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

    @staticmethod
    def _b64(value: Any) -> bytes:
        if not isinstance(value, str):
            return b""
        try:
            return base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            return b""

    REPORT_KEYS: dict[str, Any] = {
        "v": int,
        "nonce": str,
        "exit_code": int,
        "signal": (int, type(None)),
        "stdout_b64": str,
        "stderr_b64": str,
        "stdout_truncated": bool,
        "stderr_truncated": bool,
        "stdout_bytes": int,
        "stderr_bytes": int,
        "artifacts": list,
        "artifacts_dropped": list,
        "notes": list,
    }

    @classmethod
    def _parse_report(cls, raw: bytes, nonce: str) -> dict[str, Any] | None:
        """Parse the bootstrap report strictly; None unless it is exactly one
        well-formed document carrying this run's nonce."""

        def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            keys = [k for k, _ in pairs]
            if len(keys) != len(set(keys)):
                raise ValueError("duplicate key")
            return dict(pairs)

        try:
            doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
        except (ValueError, UnicodeDecodeError):
            return None  # empty, garbage, or more than one document
        if not isinstance(doc, dict) or doc.get("v") != 2 or type(doc.get("v")) is not int:
            return None
        if not isinstance(doc.get("nonce"), str) or not secrets.compare_digest(doc["nonce"], nonce):
            return None
        if set(doc) == {"v", "nonce", "error"}:
            return doc if isinstance(doc["error"], str) else None
        if set(doc) != set(cls.REPORT_KEYS):
            return None
        for key, typ in cls.REPORT_KEYS.items():
            value = doc[key]
            if typ is int and (type(value) is not int):
                return None
            if typ is bool and type(value) is not bool:
                return None
            if typ not in (int, bool) and not isinstance(value, typ):
                return None
        if isinstance(doc["signal"], bool):
            return None
        if not all(isinstance(n, str) for n in doc["notes"]):
            return None
        for entry in doc["artifacts"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "size", "b64"}
                or not isinstance(entry["path"], str)
                or not isinstance(entry["b64"], str)
                or type(entry["size"]) is not int
            ):
                return None
        for entry in doc["artifacts_dropped"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"path", "size", "reason"}
                or not isinstance(entry["path"], str)
                or not isinstance(entry["reason"], str)
                or type(entry["size"]) is not int
            ):
                return None
        if not -(2**31) <= doc["exit_code"] < 2**31:
            return None
        return doc

    def _allowed_input(self, host_path: str) -> Path:
        """Resolve a files_in entry; it must be a regular file inside inputs_dir."""
        if self.inputs_dir is None:
            raise ValueError("files_in is disabled: no inputs_dir / AIRLOCK_INPUTS_DIR configured")
        try:
            path = (self.inputs_dir / host_path).resolve(strict=True)
        except (OSError, RuntimeError) as e:
            raise ValueError(f"files_in entry not found: {host_path!r}") from e
        if not path.is_relative_to(self.inputs_dir) or not path.is_file():
            raise ValueError(f"files_in entry outside inputs_dir: {host_path!r}")
        return path

    def _build_input_archive(
        self, action: ActionRequest, input_files: dict[str, bytes] | None
    ) -> bytes:
        """Build the tar archive streamed to the bootstrap over stdin."""
        files: dict[str, bytes] = {}
        job_name = "job.py" if action.lang == "python" else "job.sh"
        files[job_name] = (action.code or "").encode()

        inputs: dict[str, bytes] = {}
        for host_path in action.files_in:
            path = self._allowed_input(host_path)
            inputs[path.name] = path.read_bytes()
        inputs.update(input_files or {})
        for name, content in inputs.items():
            rel = self._safe_relpath(name)
            if rel is None:
                raise ValueError(f"Unsafe input file name: {name!r}")
            files[f"input/{rel}"] = content

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(content))
        return buf.getvalue()

    @staticmethod
    def _safe_relpath(name: str) -> str | None:
        if not name or name.startswith("/") or "\\" in name or "\x00" in name:
            return None
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if not parts or any(p == ".." for p in parts):
            return None
        return "/".join(parts)

    def _store_artifacts(
        self, entries: list[dict[str, Any]], output_dir: Path
    ) -> tuple[list[Artifact], list[DroppedArtifact]]:
        """Write artifacts to the host and recompute their sha256 here."""
        artifacts: list[Artifact] = []
        dropped: list[DroppedArtifact] = []
        out_root = output_dir / "out"
        for i, entry in enumerate(entries):
            rel = self._safe_relpath(entry["path"])
            content = self._b64(entry["b64"])
            if i >= self.MAX_ARTIFACTS:
                dropped.append(
                    DroppedArtifact(path=entry["path"], size=len(content), reason="too_many_files")
                )
                continue
            if rel is None:
                dropped.append(
                    DroppedArtifact(path=entry["path"], size=len(content), reason="unsafe_path")
                )
                continue
            dest = out_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            artifacts.append(Artifact(name=rel, sha256=sha256(content).hexdigest()))
        return artifacts, dropped

    def process_limits(self, caps: dict[str, Any]) -> dict[str, int]:
        """The two process numbers a run gets from ``caps["pids"]``.

        ``job_nproc`` is RLIMIT_NPROC for the job uid, set by the bootstrap. It
        is the job-facing cap under both runtimes and exactly the value in the
        signed decision caps. ``cgroup_pids_headroom`` is docker --pids-limit.
        Under runc it equals job_nproc. Under gVisor the cgroup counts the
        sandbox kernel's own host threads, not job processes, and hitting it
        kills the whole sandbox with exit 2 and no output, so runsc gets
        headroom and the job meets RLIMIT_NPROC (or the memory cap) first.
        """
        job_nproc = int(caps.get("pids", 64))
        headroom = job_nproc if self.runtime == "runc" else max(4 * job_nproc, 512)
        return {"job_nproc": job_nproc, "cgroup_pids_headroom": headroom}

    def _build_docker_create_command(
        self,
        action: ActionRequest,
        caps: dict[str, Any],
        container_name: str,
    ) -> list[str]:
        """Build Docker create command."""
        limits = self.process_limits(caps)
        pids_limit = limits["job_nproc"]
        cgroup_pids = limits["cgroup_pids_headroom"]
        mem_mb = caps.get("mem_mb", 256)

        cmd = [
            "docker",
            "create",
            "--interactive",
            "--name",
            container_name,
            "--read-only",
            "--tmpfs",
            "/work:rw,noexec,nosuid,nodev,size=64m,uid=0,gid=0,mode=0755",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--tmpfs",
            "/dev/shm:rw,noexec,nosuid,nodev,size=8m,mode=1777",
            # The fixed bootstrap starts as uid 0 with only SETUID/SETGID/SETPCAP, so it
            # can run the job as uid 65534. Different uids keep the job away
            # from the bootstrap's /proc entries, memory and report channel.
            "--user",
            "0:0",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "SETUID",
            "--cap-add",
            "SETGID",
            # only so the job child can empty its bounding set before setuid
            "--cap-add",
            "SETPCAP",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(cgroup_pids),
            "--memory",
            f"{mem_mb}m",
            "--memory-swap",
            f"{mem_mb}m",
            "--cpus",
            str(caps.get("cpus", 0.5)),
            "--ulimit",
            "nofile=256:256",
        ]

        # Network
        if action.network == "none":
            cmd.extend(["--network", "none"])
        else:
            raise ValueError(f"Network mode '{action.network}' not supported")

        # Runtime
        cmd.extend(["--runtime", self.runtime])

        # Explicit minimal environment
        cmd.extend(["-e", "LANG=C.UTF-8"])
        cmd.extend(["-e", "LC_ALL=C.UTF-8"])

        cmd.extend(["-w", "/work"])

        # Use digest if available
        if self.image_digest and self.image_digest != "sha256:unknown":
            image_ref = f"{self.image.split(':')[0]}@{self.image_digest}"
        else:
            image_ref = self.image

        cmd.append(image_ref)

        # Fixed, repository-owned bootstrap; the job itself arrives over stdin.
        cmd.extend(["python3", "-c", BOOTSTRAP_SOURCE, str(pids_limit)])

        return cmd

    def _inspect_container(self, container_name: str) -> dict[str, Any]:
        """Inspect container for exit code, OOM, runtime and image."""
        fallback = {
            "exit_code": 1,
            "oom_killed": False,
            "peak_mem_mb": None,
            "runtime": self.runtime,
            "image_digest": self.image_digest,
        }
        try:
            result = subprocess.run(
                [
                    "docker",
                    "inspect",
                    container_name,
                    "--format",
                    "{{json .State}}|{{json .HostConfig.Runtime}}|{{.Image}}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            parts = result.stdout.strip().split("|")
            state = json.loads(parts[0])
            runtime = json.loads(parts[1]) if len(parts) > 1 else self.runtime
        except (
            subprocess.TimeoutExpired,
            subprocess.CalledProcessError,
            json.JSONDecodeError,
            IndexError,
            OSError,
        ):
            return fallback

        return {
            "exit_code": int(state.get("ExitCode", 1)),
            "oom_killed": bool(state.get("OOMKilled", False)),
            "peak_mem_mb": None,  # Not available from inspect
            "runtime": runtime or self.runtime,
            # The container is created from image@digest, so the pinned digest
            # is what ran; fall back to the resolved one.
            "image_digest": self.image_digest,
        }
