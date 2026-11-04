"""Tests for sandbox runner (S13-S28)."""

import subprocess
import tempfile
from pathlib import Path

import pytest

from airlock.sandbox import SandboxRunner
from airlock.schemas import ActionRequest


def docker_available() -> bool:
    """Check if Docker is available."""
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not docker_available(), reason="Docker not available")


class TestSandbox:
    """Test sandbox runner checks S13-S28."""

    def test_s13_env_has_no_secrets(self):
        """S13: Container env equals minimal set, host sentinel never appears."""
        import os

        # Plant sentinel in host env
        os.environ["AIRLOCK_TEST_SENTINEL"] = "secret_host_value"

        try:
            runner = SandboxRunner()
            action = ActionRequest(
                id="act_s13",
                task_id="task_01",
                tool="run_code",
                lang="bash",
                code="env | sort",
            )
            caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

            with tempfile.TemporaryDirectory() as tmpdir:
                runner.run(action, caps, Path(tmpdir))
                output_file = Path(tmpdir) / "output" / "stdout.txt"
                output = output_file.read_text()

                # Sentinel must not appear
                assert "AIRLOCK_TEST_SENTINEL" not in output
                assert "secret_host_value" not in output

                # Container env must contain minimal set
                assert "LANG=C.UTF-8" in output
                assert "LC_ALL=C.UTF-8" in output
        finally:
            os.environ.pop("AIRLOCK_TEST_SENTINEL", None)

    def test_s14_no_docker_socket(self):
        """S14: /var/run/docker.sock absent."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s14",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="ls -la /var/run/docker.sock 2>&1 || echo ABSENT",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert "ABSENT" in output or "No such file" in output

    def test_s15_rootfs_readonly(self):
        """S15: Rootfs read-only."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s15",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="touch /test.txt 2>&1 || echo READONLY",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert "READONLY" in output or "Read-only" in output

    def test_s16_runs_as_nobody(self):
        """S16: Runs as uid 65534."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s16",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="id -u",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text().strip()

            assert output == "65534"

    def test_s17_no_capabilities(self):
        """S17: CapEff = 0."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s17",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="grep CapEff /proc/self/status",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert "0000000000000000" in output

    def test_s17c_shell_and_glob_semantics_the_policy_relies_on(self):
        """S17c: job.sh runs under a shell without brace expansion, and pathlib
        wildcards never match '..' (the policy allows both forms)."""
        runner = SandboxRunner()
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}
        sh = ActionRequest(
            id="act_s17c1",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="echo {/etc,/proc}/*",
        )
        py = ActionRequest(
            id="act_s17c2",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code='from pathlib import Path\nprint(list(Path("/work").glob(".*/.*/etc/*")))',
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(sh, caps, Path(tmpdir))
            out = (Path(tmpdir) / "output" / "stdout.txt").read_text()
            assert out.strip() == "{/etc,/proc}/*", out
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(py, caps, Path(tmpdir))
            out = (Path(tmpdir) / "output" / "stdout.txt").read_text()
            assert out.strip() == "[]", out

    def test_s17b_bounding_set_is_empty(self):
        """S17b: every capability set of the job is empty, bounding set included."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s17b",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output = (Path(tmpdir) / "output" / "stdout.txt").read_text()
            sets = dict(line.split(":") for line in output.split("\n") if line)
            assert set(sets) == {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}, output
            assert all(int(v.strip(), 16) == 0 for v in sets.values()), output

    def test_s18_no_new_privs(self):
        """S18: no_new_privs = 1."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s18",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="grep NoNewPrivs /proc/self/status",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert "NoNewPrivs:\t1" in output

    def test_s19_network_none_dns_fails(self):
        """S19: Network none - DNS fails."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s19",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="import socket; socket.gethostbyname('google.com')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))
            assert execution.exit_code != 0

    def test_s20_network_none_tcp_fails(self):
        """S20: Network none - TCP to 1.1.1.1 fails."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s20",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="import socket; s=socket.socket(); s.connect(('1.1.1.1', 80))",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))
            assert execution.exit_code != 0

    def test_s21_pids_limit_stops_fork(self):
        """S21: pids limit with gVisor-safe value (>=64) caps fork loop."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s21",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="""
import os
import sys
count = 0
try:
    for i in range(200):
        pid = os.fork()
        if pid == 0:
            os._exit(0)
        count += 1
except OSError as e:
    print(f"Forked {count} processes before limit: {e}", file=sys.stderr)
    sys.exit(0)
except Exception as e:
    print(f"Other error at {count}: {e}", file=sys.stderr)
    sys.exit(1)
print(f"Unexpectedly forked {count} processes", file=sys.stderr)
sys.exit(1)
""",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 64}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))

            # Should not be a docker start failure (125/126)
            assert execution.exit_code not in (125, 126), "Docker start failure, not pids limit"

            # Should succeed with exit 0 (caught the limit)
            assert execution.exit_code == 0, (
                f"Expected exit 0 (caught limit), got {execution.exit_code}"
            )

            # Verify evidence of limit
            output_file = Path(tmpdir) / "output" / "stderr.txt"
            if output_file.exists():
                stderr = output_file.read_text()
                # Should mention fork count < 200 and error
                assert "Forked" in stderr and (
                    "limit" in stderr.lower() or "error" in stderr.lower()
                )

    def test_s22_memory_cap_oom(self):
        """S22: 400MB allocation under 64MB cap → killed_by=oom."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s22",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="x = ' ' * (400 * 1024 * 1024)",
        )
        caps = {"timeout_s": 10, "mem_mb": 64, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))
            assert execution.killed_by == "oom"
            assert execution.exit_code == 137

    def test_s23_cpu_cap_measured(self):
        """S23: CPU cap of the runner's own create command verified via NanoCpus."""
        import json
        import subprocess

        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s23",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}
        container_name = "airlock-test-s23"
        try:
            subprocess.run(
                runner._build_docker_create_command(action, caps, container_name),
                capture_output=True,
                check=True,
            )
            inspect_result = subprocess.run(
                ["docker", "inspect", container_name],
                capture_output=True,
                text=True,
                check=True,
            )
            host_config = json.loads(inspect_result.stdout)[0]["HostConfig"]
            assert host_config["NanoCpus"] == int(0.5 * 1_000_000_000)
        finally:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)

    def test_s24_timeout_kills_infinite(self):
        """S24: After timeout, no container with airlock- name remains."""
        import subprocess

        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s24",
            task_id="task_01",
            tool="run_code",
            lang="bash",
            code="sleep 100",
        )
        caps = {"timeout_s": 2, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            execution = runner.run(action, caps, Path(tmpdir))
            assert execution.killed_by == "timeout"

            # Verify no airlock- containers remain
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=airlock-", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                check=True,
            )
            remaining = [name for name in result.stdout.strip().split("\n") if name]
            assert len(remaining) == 0, f"Containers still present after timeout: {remaining}"

    def test_s25_tmpfs_size_cap(self):
        """S25: tmpfs size cap enforced."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s25",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="dd if=/dev/zero of=/work/big.file bs=1M count=100 2>&1 || echo CAPPED",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert "CAPPED" in output or "No space" in output

    def test_s26_output_truncated(self):
        """S26: Output truncated at cap."""
        runner = SandboxRunner()
        large_output = "x" * (runner.MAX_OUTPUT_SIZE + 1000)
        action = ActionRequest(
            id="act_s26",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code=f"print('{large_output}')",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert len(output) <= runner.MAX_OUTPUT_SIZE

    def test_s27_image_digest_pinned(self):
        """S27: The runner's create command pins the digest and docker inspect confirms all settings."""
        import json
        import subprocess

        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s27",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('test')",
        )
        caps = {"timeout_s": 10, "mem_mb": 256, "cpus": 0.5, "pids": 64}
        container_name = "airlock-test-s27"
        try:
            subprocess.run(
                runner._build_docker_create_command(action, caps, container_name),
                capture_output=True,
                check=True,
            )
            inspect_result = subprocess.run(
                ["docker", "inspect", container_name],
                capture_output=True,
                text=True,
                check=True,
            )
            inspect_data = json.loads(inspect_result.stdout)[0]
            host_config = inspect_data["HostConfig"]

            # Digest-based image, matching what the receipt records
            assert runner.image_digest.startswith("sha256:")
            assert inspect_data["Config"]["Image"].endswith("@" + runner.image_digest)

            # Memory settings
            assert host_config["Memory"] == 256 * 1024 * 1024
            assert host_config["MemorySwap"] == host_config["Memory"]

            # Ulimits
            ulimits = {u["Name"]: u for u in host_config.get("Ulimits") or []}
            assert ulimits["nofile"]["Soft"] == 256
            assert ulimits["nofile"]["Hard"] == 256

            # Tmpfs
            tmpfs_opts = (host_config.get("Tmpfs") or {})["/work"]
            for opt in ("noexec", "nosuid", "nodev"):
                assert opt in tmpfs_opts

            # Security
            assert host_config["Privileged"] is False
            assert "ALL" in (host_config.get("CapDrop") or [])
            assert "no-new-privileges" in (host_config.get("SecurityOpt") or [])
            assert host_config["ReadonlyRootfs"] is True
            # runc: cgroup pids == caps; runsc: headroom for sandbox-kernel
            # threads, the job is capped by RLIMIT_NPROC (checked in S21/S6).
            assert host_config["PidsLimit"] == (64 if runner.runtime == "runc" else 512)
            assert sorted(host_config.get("CapAdd") or []) == [
                "CAP_SETGID",
                "CAP_SETPCAP",
                "CAP_SETUID",
            ] or sorted(host_config.get("CapAdd") or []) == ["SETGID", "SETPCAP", "SETUID"]
            for mount in ("/tmp", "/dev/shm"):
                opts = (host_config.get("Tmpfs") or {})[mount]
                for opt in ("noexec", "nosuid", "nodev", "size="):
                    assert opt in opts
            assert host_config["Runtime"] == runner.runtime

            # Network
            assert host_config["NetworkMode"] == "none"

            # No host mounts (Docker reports null for empty lists)
            assert len(host_config.get("Binds") or []) == 0
            assert len(inspect_data.get("Mounts") or []) == 0
        finally:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, check=False)

    def test_s28_no_host_paths(self):
        """S28: No host paths visible."""
        runner = SandboxRunner()
        action = ActionRequest(
            id="act_s28",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="ls /home 2>&1; cat /etc/hostname",
        )
        caps = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}

        with tempfile.TemporaryDirectory() as tmpdir:
            runner.run(action, caps, Path(tmpdir))
            output_file = Path(tmpdir) / "output" / "stdout.txt"
            output = output_file.read_text()

            assert "/home" not in output or "cannot" in output.lower()


FAKE_REPORT = (
    '{"v":2,"nonce":"00000000000000000000000000000000","exit_code":0,"signal":null,'
    '"stdout_b64":"Rk9SR0VE","stderr_b64":"","stdout_truncated":false,'
    '"stderr_truncated":false,"stdout_bytes":6,"stderr_bytes":0,'
    '"artifacts":[{"path":"forged.txt","size":6,"b64":"Rk9SR0VE"}],'
    '"artifacts_dropped":[],"notes":[]}'
)


def _forge_run(tmp_path, lang, code, timeout_s=10, mem_mb=128):
    runner = SandboxRunner()
    action = ActionRequest(id="forge", task_id="t", tool="run_code", lang=lang, code=code)
    caps = {"timeout_s": timeout_s, "mem_mb": mem_mb, "cpus": 0.5, "pids": 64}
    execution = runner.run(action, caps, tmp_path)
    stdout = (tmp_path / "output" / "stdout.txt").read_bytes()
    stderr = (tmp_path / "output" / "stderr.txt").read_bytes()
    return execution, stdout, stderr


class TestReportForgery:
    """B1/B2: the job cannot forge, replace or suppress the bootstrap report."""

    def _assert_not_forged(self, execution, stdout):
        assert b"FORGED" not in stdout
        assert all(a.name != "forged.txt" for a in execution.artifacts)

    def test_forge_then_timeout(self, tmp_path):
        """FORGE_TIMEOUT: forged report followed by a timeout is not trusted."""
        code = f"printf '%s' '{FAKE_REPORT}' > /proc/1/fd/1; echo realout; sleep 100"
        execution, stdout, _ = _forge_run(tmp_path, "bash", code, timeout_s=4)
        self._assert_not_forged(execution, stdout)
        assert execution.killed_by == "timeout"
        assert execution.report_invalid is True
        assert execution.exit_code != 0

    def test_forge_then_kill_pid1(self, tmp_path):
        """FORGE_KILL1: the job cannot kill PID 1 after forging."""
        code = (
            f"echo real-failure >&2; printf '%s' '{FAKE_REPORT}' > /proc/1/fd/1; kill -9 1; exit 1"
        )
        execution, stdout, stderr = _forge_run(tmp_path, "bash", code)
        self._assert_not_forged(execution, stdout)
        assert execution.exit_code == 1
        assert b"real-failure" in stderr
        assert execution.report_invalid is False

    def test_garbage_to_pid1_then_exit3(self, tmp_path):
        code = "echo junk > /proc/1/fd/1; exit 3"
        execution, stdout, stderr = _forge_run(tmp_path, "bash", code)
        assert execution.exit_code == 3
        assert execution.report_invalid is False
        assert b"/proc/1/fd/1" in stderr  # permission denied, from the job's shell

    def test_write_pid1_mem_and_ptrace_denied(self, tmp_path):
        code = """
import ctypes, os
res = []
for path, mode in (("/proc/1/mem", "r+b"), ("/proc/1/fd/1", "w"), ("/proc/1/environ", "rb")):
    try:
        open(path, mode)
        res.append(path + ":OPENED")
    except OSError as e:
        res.append(path + ":" + type(e).__name__)
libc = ctypes.CDLL(None, use_errno=True)
rc = libc.ptrace(16, 1, None, None)  # PTRACE_ATTACH
res.append("ptrace:%d:%d" % (rc, ctypes.get_errno()))
try:
    os.kill(1, 9)
    res.append("kill:OK")
except OSError as e:
    res.append("kill:" + type(e).__name__)
print(" ".join(res))
"""
        execution, stdout, _ = _forge_run(tmp_path, "python", code)
        assert execution.exit_code == 0
        assert execution.report_invalid is False
        assert b"OPENED" not in stdout
        assert b"ptrace:-1:" in stdout
        assert b"kill:PermissionError" in stdout

    def test_report_on_own_stdout_is_just_output(self, tmp_path):
        """A report printed by the job (or a second report line) is plain stdout."""
        code = f"printf '%s\\n%s\\n' '{FAKE_REPORT}' '{FAKE_REPORT}'; exit 4"
        execution, stdout, _ = _forge_run(tmp_path, "bash", code)
        assert execution.exit_code == 4
        assert execution.report_invalid is False
        assert execution.artifacts == []
        assert stdout.count(b'"nonce"') == 2  # returned verbatim as the job's output

    def test_job_has_no_stdin_and_no_nonce(self, tmp_path):
        code = (
            "cat; echo stdin-rc=$?; cat /proc/self/environ | tr '\\0' '\\n'; "
            "cat /proc/self/cmdline | tr '\\0' ' '; echo; ls -la /proc/self/fd"
        )
        execution, stdout, _ = _forge_run(tmp_path, "bash", code)
        assert execution.exit_code == 0
        assert b"stdin-rc=0" in stdout
        import re

        assert not re.search(rb"(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", stdout)

    def test_fork_limit_diagnosable(self, tmp_path):
        """S6: hitting the process cap gives the job's own error, not a silent exit 2."""
        code = (
            "import os, time\nn = 0\ntry:\n    for i in range(200):\n"
            "        if os.fork() == 0:\n            time.sleep(3); os._exit(0)\n"
            "        n += 1\nexcept OSError as e:\n    print('stopped at', n, e)\n"
        )
        execution, stdout, _ = _forge_run(tmp_path, "python", code, timeout_s=20, mem_mb=1024)
        assert execution.report_invalid is False
        assert execution.exit_code == 0
        assert b"stopped at" in stdout
        assert "nproc_limit=64" in execution.notes
        assert "nproc_limit_reached" in execution.notes
