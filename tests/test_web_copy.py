"""Pin honest wording on the public page."""

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "airlock" / "web" / "static"
HTML = (STATIC / "index.html").read_text()
JS = (STATIC / "app.js").read_text()


def _text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def test_process_cap_is_named_rlimit_nproc():
    """The job's process cap is RLIMIT_NPROC, not a docker pids count."""
    assert "32 pids" not in _text(HTML)
    assert "32 processes (RLIMIT_NPROC)" in _text(HTML)
    assert "pids ${c.pids}" not in JS
    assert "processes (RLIMIT_NPROC)" in JS


def test_no_bare_zero_false_allow_claim():
    """Every '0 false-ALLOW' must be scoped to a corpus and the independent corpus named."""
    text = _text(HTML)
    for m in re.finditer(r"0 false[- ]allow", text, re.I):
        assert "corpus" in text[m.end() : m.end() + 30], text[m.start() - 40 : m.end() + 40]
    assert "on this corpus" in text
    assert "independent" in text and "46" in text


def test_corpus_table_renders_independent_metrics():
    """The corpus table must show the independent corpus from metrics.json."""
    assert "m.independent" in JS
    assert "false_allow_security_relevant" in JS
