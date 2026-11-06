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


def test_live_and_replay_are_labelled():
    """Judges must see live vs replay without mistaking scripted proposals for a model call."""
    text = _text(HTML)
    assert 'class="mode-tag">live' in HTML
    assert 'class="mode-tag">replay' in HTML
    assert "replay" in text and "live" in text
    assert "replay_compromised" in JS
    assert "was not tampered with" in text


def test_judge_path_orders_useful_attack_probe_verify():
    """Filmable story: useful live result → attack → runtime probe → receipt/tamper."""
    assert 'data-step="1"' in HTML and "Useful result" in HTML
    assert 'data-step="2"' in HTML and "Attack contained" in HTML
    assert 'data-step="3"' in HTML and "Runtime probe" in HTML
    assert 'data-step="4"' in HTML and "Receipt" in HTML
    assert "containment_then_healthy" in JS
    assert "Download report.md" in JS
    i_real = HTML.index('data-tab="real"')
    i_inj = HTML.index('data-tab="injected"')
    i_arena = HTML.index('data-tab="arena"')
    i_ver = HTML.index('data-tab="verify"')
    assert i_real < i_inj < i_arena < i_ver


def test_no_employer_names_in_ui():
    assert "CONTACT Software" not in HTML and "CONTACT Software" not in JS
