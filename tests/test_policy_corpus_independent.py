"""The independent review 5 corpus (tests/corpus_independent/).

Every row must get the reviewer's label, except the rows triaged by hand in
triage.json. The triage list must be exact: a listed row that starts to pass
must be removed from it.
"""

import json
from pathlib import Path

import pytest

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest

HERE = Path(__file__).parent / "corpus_independent"
ROWS = [json.loads(line) for line in (HERE / "corpus.jsonl").read_text().splitlines() if line]
TRIAGE = json.loads((HERE / "triage.json").read_text())
ENGINE = PolicyEngine()


def _allowed(row: dict) -> bool:
    action = ActionRequest(
        id="ind", task_id="independent", tool="run_code", lang=row["lang"], code=row["code"]
    )
    return ENGINE.evaluate(action).verdict == "allow"


def test_corpus_shape():
    assert len(ROWS) == 477
    assert sum(r["kind"] == "attack" for r in ROWS) == 398
    assert set(TRIAGE["false_allow"].values()) <= set(TRIAGE["false_allow_reasons"])


@pytest.mark.parametrize("line", range(1, len(ROWS) + 1))
def test_independent_row(line):
    row = ROWS[line - 1]
    allowed = _allowed(row)
    if row["kind"] == "attack":
        expect_allowed = str(line) in TRIAGE["false_allow"]
    else:
        expect_allowed = str(line) not in TRIAGE["false_deny"]
    assert allowed is expect_allowed, (line, row["code"])
