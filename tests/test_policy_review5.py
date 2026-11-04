"""Regression tests for the fifth independent adversarial review (H1, H2).

Each DENY case was ALLOW before the fix. The ALLOW cases pin that the fix
did not turn ordinary log work into a false DENY.
"""

import pytest

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest

P = "from pathlib import Path\n"

PY_DENY = [
    # H1: glob/rglob patterns that climb out of the base directory
    P + 'for f in Path("/work/input").glob("../../etc/*"):\n print(f)',
    P + 'for f in Path("/work/input").glob("../../*"):\n print(f)',
    P + 'print(list(Path("/work/input").glob("../../proc/self/*")))',
    P + 'for f in Path("/work/out").glob("../../etc/*"):\n print(f)',
    P + 'for f in Path("/work/input").rglob("../../../etc/*"):\n print(f)',
    P + 'print(list(Path("/work/input").glob("**/../../../etc/*")))',
    P + 'print(list(Path("/work/input/x").glob("../../../etc/*")))',
    P + 'print(list(Path("/work/input").glob("[.][.]/[.][.]/etc/*")))',
    P + 'print(list(Path("/work/input").glob(pattern="../../*")))',
    P + 'p = "../../*"\nprint(list(Path("/work/input").glob(p)))',
    P + 'print(list(Path("/work/input").glob("/etc/*")))',
    "import pathlib\nprint(list(pathlib.Path('/work/input').glob('../*')))",
    "from pathlib import Path as Q\nprint(list(Q('/work/input').rglob('../*')))",
    P + "def g(p):\n return list(Path('/work/input').glob(p))\nprint(g('../../*'))",
    # H1: Path bases derived by navigation the checker cannot resolve
    P + 'print(list(Path("/work/input").parent.parent.glob("*")))',
    P + 'q = Path("/work/input").parent\nprint(list(q.iterdir()))',
    P + 'print(list(Path("/work/input").resolve().parents[1].iterdir()))',
    P + 'print(Path("/work/input").parent.parent.joinpath("etc/passwd").open().read())',
    P + 'print(Path("/work/input").with_name("..").iterdir())',
    P + 'for f in Path("/work/input").iterdir():\n print(list(f.parent.parent.iterdir()))',
    P + 'print(list(Path("/work/input").parent.walk()))',
    P + 'print(Path("/work/input").parent.parent.joinpath("etc/shadow").stat())',
    P + "def r(p):\n return p.open().read()\nprint(r(Path('/').joinpath('etc/passwd')))",
    P + 'print(list(Path("/etc").walk()))',
    "help()",
]

SH_DENY = [
    # H2: test / [ operands go through the path allow-list
    "test -r /etc/passwd && echo yes",
    "test -e ../etc",
    "test -e .. && echo y",
    "test /work/input/a -nt /etc/passwd",
    'test -e /et""c/passwd',
    r"test -e /e\tc/passwd",
    "test -e ~root",
    "test -d ~",
    # shell pathname expansion in echo/printf lists directories
    "echo /etc/*",
    "echo /e*",
    "printf '%s\\n' /proc/*",
    "echo /work/input/../../*",
    # awk ARGV rewriting opens files the path check never saw
    "awk 'BEGIN{ARGV[1]=\"/etc/passwd\"} {print}' /work/input/a.log",
    "awk 'BEGIN{ARGC=2; ARGV[1]=\"/etc/passwd\"} {print}'",
    "awk '{print}' ARGV=/etc/passwd /work/input/a.log",
    # printf hex strings only become paths through expansion, which stays denied
    'printf -v p "%b" "\\x2fetc\\x2fpasswd"; cat $p',
    'cat $(printf "%b" "\\x2fetc\\x2fpasswd")',
    "echo /etc/passwd | xargs cat",
]

PY_ALLOW = [
    P + 'for f in Path("/work/input").glob("*.log"):\n print(f.read_text()[:10])',
    P + 'for f in sorted(Path("/work/input").rglob("**/*.log")):\n print(f)',
    P + 'print(list(Path("/work/input").glob("app-[0-9].log")))',
    P + 'print(list(Path("/work/input").iterdir()))',
    P + 'print(Path("/work/input/app.log").stat().st_size)',
]

SH_ALLOW = [
    "test -e /work/input/app.log && echo ok",
    "test -n x",
    "test -f app.log || echo missing",
    "echo *",
    "cat /work/input/*.log | wc -l",
    'printf "%b" "\\x2fetc\\x2fpasswd"',
    "echo done > /work/out/x.txt",
]


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


def verdict(engine, lang, code):
    action = ActionRequest(id="r5", task_id="r5", tool="run_code", lang=lang, code=code)
    return engine.evaluate(action).verdict


@pytest.mark.parametrize("code", PY_DENY)
def test_python_deny(engine, code):
    assert verdict(engine, "python", code) == "deny"


@pytest.mark.parametrize("code", SH_DENY)
def test_shell_deny(engine, code):
    assert verdict(engine, "bash", code) == "deny"


@pytest.mark.parametrize("code", PY_ALLOW)
def test_python_allow(engine, code):
    assert verdict(engine, "python", code) == "allow"


@pytest.mark.parametrize("code", SH_ALLOW)
def test_shell_allow(engine, code):
    assert verdict(engine, "bash", code) == "allow"
