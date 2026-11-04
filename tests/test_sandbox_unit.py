"""Unit tests for sandbox runner with fake docker."""

import os
import subprocess
from pathlib import Path

import pytest

from airlock.sandbox import SandboxRunner
from airlock.schemas import ActionRequest


class TestSandboxUnit:
    """Unit tests for sandbox runner without Docker daemon."""

    @pytest.fixture(autouse=True)
    def setup_fake_docker(self, monkeypatch, tmp_path):
        """Set up fake docker on PATH."""
        fake_docker_dir = Path(__file__).parent / "fake_docker"
        old_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", f"{fake_docker_dir}:{old_path}")

        log_file = tmp_path / "docker.log"
        monkeypatch.setenv("FAKE_DOCKER_LOG", str(log_file))
        self.docker_log = log_file

        # Reset log
        if log_file.exists():
            log_file.unlink()
        log_file.touch()

        # Default env vars
        monkeypatch.setenv("FAKE_DOCKER_RUNTIMES", '{"runc": {}, "runsc": {}}')
        monkeypatch.setenv("FAKE_DOCKER_DIGEST", "python:3.12-slim@sha256:abc123def456")
        monkeypatch.setenv("FAKE_DOCKER_CONTAINER_ID", "airlock-test123")
        monkeypatch.setenv("FAKE_DOCKER_CREATE_EXIT", "0")
        monkeypatch.setenv("FAKE_DOCKER_START_EXIT", "0")
        monkeypatch.setenv("FAKE_DOCKER_START_STDOUT", "hello\n")
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT", "0")
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT_CODE", "0")
        monkeypatch.setenv("FAKE_DOCKER_OOM", "false")
        monkeypatch.setenv("FAKE_DOCKER_RUNTIME", "runsc")

    @pytest.mark.parametrize("runtime", ["runc", "runsc"])
    def test_job_process_limit_is_exactly_the_decision_cap(self, runtime):
        """The arena asks for pids=32; the job must get 32, not a silent floor of 64."""
        from airlock.web.app import ARENA_CAPS

        runner = SandboxRunner(runtime=runtime)
        action = ActionRequest(id="p", task_id="t", tool="run_code", lang="bash", code="true")
        cmd = runner._build_docker_create_command(action, dict(ARENA_CAPS), "airlock-x")
        assert ARENA_CAPS["pids"] == 32
        assert cmd[-1] == "32"  # RLIMIT_NPROC handed to the bootstrap

    @pytest.mark.parametrize("runtime", ["runc", "runsc"])
    def test_process_limits_match_docker_create(self, runtime):
        """Review 5 M1: the published job_nproc / cgroup headroom are what docker gets."""
        from airlock.web.app import ARENA_CAPS

        runner = SandboxRunner(runtime=runtime)
        action = ActionRequest(id="p", task_id="t", tool="run_code", lang="bash", code="true")
        cmd = runner._build_docker_create_command(action, dict(ARENA_CAPS), "airlock-x")
        limits = runner.process_limits(ARENA_CAPS)
        assert limits["job_nproc"] == 32 and cmd[-1] == "32"
        assert cmd[cmd.index("--pids-limit") + 1] == str(limits["cgroup_pids_headroom"])
        assert limits["cgroup_pids_headroom"] == (32 if runtime == "runc" else 512)

    def get_docker_commands(self):
        """Get logged docker commands."""
        if not self.docker_log.exists():
            return []
        return self.docker_log.read_text().strip().split("\n")

    def test_exact_sequence_create_start_inspect_rm(self, tmp_path):
        """Test exact docker command sequence."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="test_01",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        result = runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        # Container lifecycle: create -> start -a -i (archive on stdin) -> inspect -> rm -f
        assert any(" info " in cmd for cmd in commands)
        assert any(" image inspect " in cmd for cmd in commands)
        lifecycle = [
            cmd.split()[1]
            for cmd in commands
            if cmd.split()[1:2] and cmd.split()[1] in {"create", "start", "inspect", "rm", "cp"}
        ]
        assert lifecycle == ["create", "start", "inspect", "rm"]
        assert not any(" cp " in cmd for cmd in commands)
        start_cmd = next(cmd for cmd in commands if cmd.split()[1:2] == ["start"])
        assert "-a" in start_cmd.split() and "-i" in start_cmd.split()
        rm_cmd = next(cmd for cmd in commands if cmd.split()[1:2] == ["rm"])
        assert "-f" in rm_cmd.split()
        archive_line = next(cmd for cmd in commands if cmd.startswith("stdin-archive "))
        assert "job.py" in archive_line

        assert result.container_name.startswith("airlock-")
        assert result.exit_code == 0

    def test_docker_create_flags(self, tmp_path, monkeypatch):
        """Test all flags passed to docker create."""
        monkeypatch.delenv("AIRLOCK_RUNTIME", raising=False)
        runner = SandboxRunner()
        action = ActionRequest(
            id="test_02",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 256, "cpus": 1.0, "pids": 128}

        runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        create_cmd = next(cmd for cmd in commands if "create" in cmd)

        # Required flags
        assert "--read-only" in create_cmd
        assert "--cap-drop ALL" in create_cmd
        assert "--security-opt no-new-privileges" in create_cmd
        # Bootstrap starts as root with only SETUID/SETGID and drops the job
        # to 65534 (see bootstrap.py); every other capability is dropped.
        assert "--user 0:0" in create_cmd
        assert "--cap-add SETUID" in create_cmd
        assert "--cap-add SETGID" in create_cmd
        cap_adds = create_cmd.split("--cap-add ")[1:]
        assert sorted(c.split()[0] for c in cap_adds) == ["SETGID", "SETUID"]
        # runsc: cgroup pids gets headroom for the sandbox kernel's threads;
        # the job itself is capped by RLIMIT_NPROC=128 (bootstrap argv[1]).
        assert "--pids-limit 512" in create_cmd
        assert create_cmd.rstrip().endswith(" 128")
        assert "--memory 256m" in create_cmd
        assert "--memory-swap 256m" in create_cmd
        assert "--cpus 1.0" in create_cmd
        assert "--ulimit nofile=256:256" in create_cmd
        assert "--tmpfs /work:rw,noexec,nosuid,nodev,size=64m,uid=0,gid=0,mode=0755" in create_cmd
        assert "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777" in create_cmd
        assert "--tmpfs /dev/shm:rw,noexec,nosuid,nodev,size=8m,mode=1777" in create_cmd
        assert "--network none" in create_cmd
        assert "--runtime runsc" in create_cmd
        assert "--interactive" in create_cmd

        # No host mounts
        assert "-v" not in create_cmd and "--volume" not in create_cmd
        assert "--mount" not in create_cmd

        # Minimal env
        assert "LANG=C.UTF-8" in create_cmd
        assert "LC_ALL=C.UTF-8" in create_cmd

        # Digest-based image
        assert "@sha256:" in create_cmd

    def test_create_failure_error_verdict(self, tmp_path, monkeypatch):
        """Test create failure raises error."""
        monkeypatch.setenv("FAKE_DOCKER_CREATE_EXIT", "1")

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_03",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        with pytest.raises(subprocess.CalledProcessError):
            runner.run(action, caps, tmp_path)

    def test_start_exit_125_not_contained(self, tmp_path, monkeypatch):
        """Test start exit 125/126 is recorded."""
        monkeypatch.setenv("FAKE_DOCKER_START_EXIT", "125")
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT_CODE", "125")

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_04",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        # Exit 125 passes through
        result = runner.run(action, caps, tmp_path)
        assert result.exit_code == 125

    def test_oom_killed_sets_killed_by(self, tmp_path, monkeypatch):
        """Test OOMKilled true sets killed_by=oom."""
        monkeypatch.setenv("FAKE_DOCKER_OOM", "true")
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT_CODE", "137")

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_05",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="x = ' ' * (1024 * 1024 * 1024)",
        )
        caps = {"timeout_s": 10, "mem_mb": 64, "cpus": 0.5, "pids": 64}

        result = runner.run(action, caps, tmp_path)

        assert result.killed_by == "oom"
        assert result.exit_code == 137

    def test_watchdog_timeout_calls_kill_and_rm(self, tmp_path, monkeypatch):
        """Test timeout handling calls rm -f."""
        # Simulate timeout by making start raise TimeoutExpired
        import subprocess

        original_run = subprocess.run

        def mock_run(cmd, *args, **kwargs):
            # Let everything through except start
            if isinstance(cmd, list) and "start" in cmd:
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 10))
            return original_run(cmd, *args, **kwargs)

        monkeypatch.setattr("subprocess.run", mock_run)

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_06",
            task_id="task_01",
            tool="run_code",
            lang="bash",
            code="sleep 100",
        )
        caps = {"timeout_s": 1, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        result = runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        # Should have rm -f in finally block
        assert any("rm" in cmd and "-f" in cmd for cmd in commands)
        assert result.killed_by == "timeout"

    def test_rm_always_called_in_finally(self, tmp_path, monkeypatch):
        """Test rm -f always called even on exceptions."""
        monkeypatch.setenv("FAKE_DOCKER_START_EXIT", "1")
        monkeypatch.setenv("FAKE_DOCKER_START_STDERR", "Error\n")

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_07",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="raise Exception()",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        # rm should be called
        assert any("rm" in cmd for cmd in commands)

    def test_runtime_check_fails_when_unavailable(self, tmp_path):
        """Test _check_runtime fails when runtime unavailable."""
        # Directly test the runtime check with a missing runtime

        runner = SandboxRunner()

        # Mock a check that will fail
        with pytest.raises(RuntimeError, match="not available"):
            # Manually test the check logic by calling it with a non-existent runtime
            runner._check_runtime("nonexistent_runtime")

    def test_network_allowlist_raises_valueerror_before_docker(self, tmp_path):
        """Test network allowlist raises ValueError before any docker call."""
        # Clear log to track calls during run()
        self.docker_log.write_text("")

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_09",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
            network="allowlist",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        with pytest.raises(ValueError, match="not supported"):
            runner.run(action, caps, tmp_path)

        # Should not have called docker create/start/etc during run()
        commands = self.get_docker_commands()
        # Should NOT have create, start, inspect, etc
        assert not any("create" in cmd for cmd in commands)
        assert not any("start" in cmd for cmd in commands)

    def test_code_in_file_not_argv(self, tmp_path):
        """Test code is put in file, not passed via argv."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="test_10",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('hello world')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        create_cmd = next(cmd for cmd in commands if "create" in cmd)

        # The user code never appears in argv; only the fixed bootstrap does.
        assert "hello world" not in create_cmd
        from airlock.sandbox import BOOTSTRAP_SOURCE

        assert BOOTSTRAP_SOURCE.replace("\n", "\\n") in create_cmd

        # The job travels inside the stdin archive
        archive_line = next(cmd for cmd in commands if cmd.startswith("stdin-archive "))
        assert "job.py" in archive_line.split(" ", 1)[1].split(",")

    def test_explicit_runtime_override(self, tmp_path, monkeypatch):
        """Test AIRLOCK_RUNTIME override."""
        monkeypatch.setenv("AIRLOCK_RUNTIME", "runc")

        runner = SandboxRunner()
        action = ActionRequest(
            id="test_11",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        create_cmd = next(cmd for cmd in commands if "create" in cmd)
        assert "--runtime runc" in create_cmd

    def test_no_rm_flag_in_create(self, tmp_path):
        """Test --rm flag is NOT passed to create."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="test_12",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        runner.run(action, caps, tmp_path)

        commands = self.get_docker_commands()
        create_cmd = next(cmd for cmd in commands if "create" in cmd)

        # Should NOT have --rm
        assert "--rm" not in create_cmd

    def test_artifacts_hashed_on_host_and_unsafe_paths_dropped(self, tmp_path, monkeypatch):
        """Artifacts from the report are written under output/out and re-hashed on the host."""
        from hashlib import sha256

        monkeypatch.setenv(
            "FAKE_DOCKER_ARTIFACTS",
            '{"report.json": "{\\"n\\": 3}", "../escape.txt": "x", "sub/a.csv": "a,b\\n"}',
        )
        runner = SandboxRunner()
        action = ActionRequest(
            id="test_13",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('x')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        result = runner.run(action, caps, tmp_path, input_files={"app.log": b"line\n"})

        names = {a.name: a.sha256 for a in result.artifacts}
        assert set(names) == {"report.json", "sub/a.csv"}
        on_disk = (tmp_path / "output" / "out" / "report.json").read_bytes()
        assert (
            names["report.json"] == sha256(on_disk).hexdigest() == sha256(b'{"n": 3}').hexdigest()
        )
        assert not (tmp_path / "output" / "escape.txt").exists()
        assert (tmp_path / "output" / "stdout.txt").read_text() == "hello\n"

        archive_line = next(c for c in self.get_docker_commands() if c.startswith("stdin-archive "))
        assert "input/app.log" in archive_line

    def test_unsafe_input_name_rejected_before_docker(self, tmp_path):
        """Input file names with traversal are rejected before any container exists."""
        self.docker_log.write_text("")
        runner = SandboxRunner()
        action = ActionRequest(
            id="test_14",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('x')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        with pytest.raises(ValueError, match="Unsafe input"):
            runner.run(action, caps, tmp_path, input_files={"../etc/passwd": b"x"})
        assert not any(" create " in cmd for cmd in self.get_docker_commands())


class TestReportForgeryUnit:
    """The host accepts the bootstrap report only under strict conditions."""

    setup_fake_docker = TestSandboxUnit.setup_fake_docker
    get_docker_commands = TestSandboxUnit.get_docker_commands

    def _run(self, tmp_path):
        runner = SandboxRunner()
        action = ActionRequest(
            id="forge", task_id="task_01", tool="run_code", lang="python", code="print('x')"
        )
        return runner.run(action, {"timeout_s": 10, "mem_mb": 128, "pids": 64}, tmp_path)

    def test_valid_report_accepted_and_nonce_sent(self, tmp_path):
        result = self._run(tmp_path)
        assert result.report_invalid is False
        assert result.exit_code == 0
        assert "stdin-nonce-len 32" in self.get_docker_commands()
        assert (tmp_path / "output" / "stdout.txt").read_text() == "hello\n"

    def test_nonce_not_in_argv_or_env(self, tmp_path):
        self._run(tmp_path)
        create_cmd = next(c for c in self.get_docker_commands() if c.split()[1:2] == ["create"])
        assert not any(
            len(tok) == 32 and set(tok) <= set("0123456789abcdef") for tok in create_cmd.split()
        )

    @pytest.mark.parametrize(
        "mode", ["wrong_nonce", "second_line", "junk_prefix", "dup_key", "string_exit", "none"]
    )
    def test_forged_or_malformed_report_rejected(self, tmp_path, monkeypatch, mode):
        monkeypatch.setenv("FAKE_DOCKER_REPORT_MODE", mode)
        monkeypatch.setenv("FAKE_DOCKER_START_EXIT", "3")
        monkeypatch.setenv("FAKE_DOCKER_ARTIFACTS", '{"a.txt": "forged"}')
        monkeypatch.setenv("FAKE_DOCKER_RAW_STDOUT", '{"v":2,"exit_code":0}')
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT_CODE", "0")
        result = self._run(tmp_path)
        assert result.report_invalid is True
        assert result.exit_code != 0  # never defaults to 0
        assert result.artifacts == []
        assert (tmp_path / "output" / "stdout.txt").read_bytes() == b""
        assert "report_invalid" in result.notes

    def test_report_ignored_when_container_exit_nonzero(self, tmp_path, monkeypatch):
        """A valid-looking report is not trusted if PID 1 did not exit 0."""
        monkeypatch.setenv("FAKE_DOCKER_CONTAINER_EXIT", "137")
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT_CODE", "137")
        result = self._run(tmp_path)
        assert result.report_invalid is True
        assert result.exit_code == 137

    def test_report_ignored_after_oom(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FAKE_DOCKER_OOM", "true")
        monkeypatch.setenv("FAKE_DOCKER_INSPECT_EXIT_CODE", "137")
        result = self._run(tmp_path)
        assert result.killed_by == "oom"
        assert result.report_invalid is True
        assert result.exit_code == 137

    def test_truncation_and_dropped_propagated(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FAKE_DOCKER_TRUNC", "true")
        monkeypatch.setenv(
            "FAKE_DOCKER_DROPPED",
            '[{"path": "big.bin", "size": 9000000, "reason": "over_size_cap"}]',
        )
        result = self._run(tmp_path)
        assert result.stdout_truncated is True
        assert [(d.path, d.size, d.reason) for d in result.artifacts_dropped] == [
            ("big.bin", 9000000, "over_size_cap")
        ]


def test_runc_pids_limit_equals_nproc(tmp_path, monkeypatch):
    fake_docker_dir = Path(__file__).parent / "fake_docker"
    monkeypatch.setenv("PATH", f"{fake_docker_dir}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_DOCKER_LOG", str(tmp_path / "log"))
    runner = SandboxRunner(runtime="runc")
    action = ActionRequest(id="p", task_id="t", tool="run_code", lang="python", code="1")
    cmd = runner._build_docker_create_command(action, {"pids": 100}, "airlock-x")
    assert cmd[cmd.index("--pids-limit") + 1] == "100"
    assert cmd[-1] == "100"


class TestFilesInAllowList:
    """files_in reads only regular files under the configured inputs_dir (review M3)."""

    @pytest.fixture
    def runner(self, tmp_path, monkeypatch):
        monkeypatch.setattr(SandboxRunner, "_detect_runtime", lambda self: "runc")
        monkeypatch.setattr(SandboxRunner, "_get_image_digest", lambda self: "sha256:x")
        monkeypatch.delenv("AIRLOCK_INPUTS_DIR", raising=False)
        allowed = tmp_path / "inputs"
        allowed.mkdir()
        (allowed / "app.log").write_text("ok\n")
        (tmp_path / "secret").write_text("s3cret\n")
        (allowed / "link").symlink_to(tmp_path / "secret")
        return SandboxRunner(inputs_dir=allowed), tmp_path

    def _action(self, files):
        return ActionRequest(
            id="f", task_id="t", tool="run_code", lang="bash", code="true", files_in=files
        )

    def test_reads_file_inside_inputs_dir(self, runner):
        r, _ = runner
        archive = r._build_input_archive(self._action(["app.log"]), None)
        assert b"input/app.log" in archive

    @pytest.mark.parametrize("entry", ["../secret", "link", "/etc/passwd", "missing", "."])
    def test_rejects_paths_outside_inputs_dir(self, runner, entry):
        r, tmp_path = runner
        if entry == "/etc/passwd":
            entry = str(tmp_path / "secret")
        with pytest.raises(ValueError):
            r._build_input_archive(self._action([entry]), None)

    def test_disabled_without_inputs_dir(self, runner, monkeypatch):
        r, _ = runner
        r.inputs_dir = None
        with pytest.raises(ValueError, match="disabled"):
            r._build_input_archive(self._action(["app.log"]), None)
