"""Narrow hardening: zip extract destinations and urllib network entry points."""

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest


def _decide(code: str):
    return PolicyEngine().evaluate(
        ActionRequest(
            id="a",
            task_id="t",
            tool="run_code",
            lang="python",
            code=code,
            network="none",
            requested={"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32},
        )
    )


def test_fancyurlopener_and_retrieve_denied():
    for code in (
        "from urllib.request import FancyURLopener\nprint(FancyURLopener)\n",
        "from urllib.request import FancyURLopener\nFancyURLopener().retrieve('http://x','/work/out/x')\n",
        "import urllib.request\nurllib.request.urlretrieve('http://x','/work/out/x')\n",
    ):
        d = _decide(code)
        assert d.verdict == "deny", code


def test_zip_extract_destinations():
    for dest in ("'/'", "'/tmp'", "'/tmp/out'", "'/work'", "'/work/input'"):
        d = _decide(f"import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall({dest})\n")
        assert d.verdict == "deny", dest
        assert "R-PY-ZIP-EXTRACT" in d.rules_fired

    d = _decide("import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall()\n")
    assert d.verdict == "deny"

    d = _decide(
        "import zipfile\nzipfile.ZipFile('/work/input/a.zip').extract('a.txt', path='/tmp')\n"
    )
    assert d.verdict == "deny"

    # Exact /work/out directory and confined descendants are allowed.
    for dest in ("'/work/out'", "'/work/out/x'"):
        d = _decide(
            f"import zipfile\n"
            f"zipfile.ZipFile('/work/input/a.zip').extractall({dest})\n"
            f"print('ok')\n"
        )
        assert d.verdict == "allow", (dest, d.rules_fired, d.reason)


def test_zip_extractall_bound_method_and_getattr_denied():
    """Observation (b): destination checks alone miss bound refs / getattr."""
    bound = _decide(
        "import zipfile\nz=zipfile.ZipFile('/work/input/a.zip')\nf=z.extractall\nf('/tmp')\n"
    )
    assert bound.verdict == "deny"
    assert "R-PY-PATH-METHOD-REF" in bound.rules_fired

    g = _decide(
        "import zipfile\nz=zipfile.ZipFile('/work/input/a.zip')\ngetattr(z,'extractall')('/tmp')\n"
    )
    assert g.verdict == "deny"
    assert "R-PY-PATH-METHOD-REF" in g.rules_fired

    # Callback-style reference without an immediate call.
    cb = _decide(
        "import zipfile\nz=zipfile.ZipFile('/work/input/a.zip')\ncbs=[z.extractall]\nprint(cbs)\n"
    )
    assert cb.verdict == "deny"
    assert "R-PY-PATH-METHOD-REF" in cb.rules_fired
