"""Cross-check the browser verifier (verify.js) against the Python signer."""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from airlock.receipt import canonical_json, parse_receipt_unchecked
from airlock.web.chain import ReceiptChain, load_or_create_signer, public_key_hex

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "tests" / "vectors"
CLI = ROOT / "tests" / "js" / "verify_cli.mjs"
NODE = shutil.which("node")

sys.path.insert(0, str(ROOT / "scripts"))
import make_js_fixtures  # noqa: E402

needs_node = pytest.mark.skipif(NODE is None, reason="node not installed")


@pytest.mark.parametrize(
    "vec", json.loads((VECTORS / "jcs_vectors.json").read_text()), ids=lambda v: v["name"]
)
def test_jcs_vectors_match_python(vec):
    assert canonical_json(json.loads(vec["input"])).decode() == vec["expected"]


def test_receipt_fixture_is_current():
    on_disk = json.loads((VECTORS / "receipt_fixture.json").read_text())
    assert on_disk == make_js_fixtures.build(), "run python scripts/make_js_fixtures.py"
    for text in on_disk["receipts"]:
        parse_receipt_unchecked(text)


def _decision(verdict: str) -> dict:
    return {
        "schema_v": 1,
        "action_id": "a1",
        "verdict": verdict,
        "rules_fired": ["X"] if verdict != "allow" else [],
        "blast_radius": {"score": 1, "factors": {"fs_write": "none", "net": "none", "procs": "1"}},
        "caps": {"timeout_s": 5},
        "policy_sha256": "f" * 64,
        "reason": None,
    }


def _node(path: Path, pub: str) -> tuple[int, dict]:
    proc = subprocess.run(
        [NODE, str(CLI), str(path), pub], capture_output=True, text=True, timeout=30
    )
    return proc.returncode, json.loads(proc.stdout)


@needs_node
def test_fresh_python_receipt_verifies_in_node_and_tamper_fails(tmp_path):
    signer = load_or_create_signer(tmp_path / "keys")
    chain = ReceiptChain(tmp_path / "receipts", signer)
    receipt = chain.append({"task_id": "t", "action_id": "a1", "decision": _decision("deny")})
    pub = public_key_hex(signer)
    text = chain.get_text(receipt.hash)

    good = tmp_path / "good.json"
    good.write_text(text)
    code, res = _node(good, pub)
    assert code == 0 and res["ok"] is True
    assert res["hash"] == receipt.hash

    bad = tmp_path / "bad.json"
    bad.write_text(re.sub(r'"verdict":\s*"deny"', '"verdict": "allow"', text, count=1))
    assert bad.read_text() != text
    code, res = _node(bad, pub)
    assert code == 1
    assert [c["id"] for c in res["checks"] if not c["ok"]] == ["hash"]

    other = load_or_create_signer(tmp_path / "other")
    code, res = _node(good, public_key_hex(other))
    assert code == 1
    assert [c["id"] for c in res["checks"] if not c["ok"]] == ["signature"]


@needs_node
def test_replay_receipt_with_context_verifies_in_node_and_tamper_fails(tmp_path):
    signer = load_or_create_signer(tmp_path / "keys")
    chain = ReceiptChain(tmp_path / "receipts", signer)
    ctx = {"mode": "replay_compromised", "planner": "scripted"}
    receipt = chain.append(
        {"task_id": "replay-1", "action_id": "a1", "decision": _decision("deny"), "context": ctx}
    )
    pub = public_key_hex(signer)
    text = chain.get_text(receipt.hash)
    assert json.loads(text)["context"] == ctx

    good = tmp_path / "good.json"
    good.write_text(text)
    code, res = _node(good, pub)
    assert code == 0 and res["ok"] is True

    # hiding that the planner was scripted breaks the hash
    bad = tmp_path / "bad.json"
    bad.write_text(text.replace('"scripted"', '"model"'))
    code, res = _node(bad, pub)
    assert code == 1
    assert [c["id"] for c in res["checks"] if not c["ok"]] == ["hash"]

    # context must be an object of strings
    odd = tmp_path / "odd.json"
    odd.write_text(text.replace('"scripted"', "7"))
    code, res = _node(odd, pub)
    assert code == 1
    assert [c["id"] for c in res["checks"] if not c["ok"]][0] == "schema"


def test_receipt_without_context_keeps_old_encoding(tmp_path):
    chain = ReceiptChain(tmp_path / "r", load_or_create_signer(tmp_path / "k"))
    receipt = chain.append({"task_id": "t", "action_id": "a1", "decision": _decision("deny")})
    assert "context" not in json.loads(chain.get_text(receipt.hash))
