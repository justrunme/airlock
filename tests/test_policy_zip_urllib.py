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
    # Writable tmpfs outside /work/out — gate must deny (RO rootfs is not enough).
    for dest in ("'/'", "'/tmp'", "'/tmp/out'", "'/work'", "'/work/input'"):
        d = _decide(f"import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall({dest})\n")
        assert d.verdict == "deny", dest
        assert "R-PY-ZIP-EXTRACT" in d.rules_fired

    # Default destination (cwd /work) denied.
    d = _decide("import zipfile\nzipfile.ZipFile('/work/input/a.zip').extractall()\n")
    assert d.verdict == "deny"

    # Explicit member extract to /tmp denied.
    d = _decide(
        "import zipfile\nzipfile.ZipFile('/work/input/a.zip').extract('a.txt', path='/tmp')\n"
    )
    assert d.verdict == "deny"

    # Under /work/out still allowed.
    d = _decide(
        "import zipfile\n"
        "zipfile.ZipFile('/work/input/a.zip').extractall('/work/out/x')\n"
        "print('ok')\n"
    )
    assert d.verdict == "allow", (d.rules_fired, d.reason)
