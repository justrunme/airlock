"""Strict receipt parsing: one accepted encoding per receipt (review S4, M4, M5)."""

import json

import pytest

from airlock.cli import (
    EXIT_CHAIN_LINK_BROKEN,
    EXIT_HASH_MISMATCH,
    EXIT_SCHEMA_ERROR,
    EXIT_SIGNATURE_INVALID,
    EXIT_SUCCESS,
    sign_chain_head,
    verify_chain,
    verify_receipt,
)
from airlock.receipt import (
    ReceiptFormatError,
    ReceiptHashError,
    ReceiptSignatureError,
    ReceiptSigner,
    load_receipt,
    parse_receipt_unchecked,
)
from airlock.schemas import BlastRadius, BlastRadiusFactor, Decision, Execution


def _data(aid="a1", exit_code=0):
    return {
        "task_id": "t",
        "action_id": aid,
        "decision": Decision(
            action_id=aid,
            verdict="deny",
            blast_radius=BlastRadius(
                score=10, factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1")
            ),
            caps={"timeout_s": 30, "cpus": 0.5},
            policy_sha256="abc",
        ).model_dump(by_alias=True),
        "execution": Execution(
            container_name="airlock-x",
            image_digest="sha256:x",
            runtime="runsc",
            started="a",
            ended="b",
            exit_code=exit_code,
            stdout_sha256="h",
        ).model_dump(by_alias=True),
    }


@pytest.fixture
def env(tmp_path):
    signer = ReceiptSigner()
    signer.save_keys(tmp_path / "k", tmp_path / "pub")
    raw = signer.sign(_data()).model_dump_json(by_alias=True)
    return signer, tmp_path, raw


def _drop(raw, section, key):
    j = json.loads(raw)
    del j[section][key]
    return json.dumps(j)


def _set(raw, key, fn):
    j = json.loads(raw)
    j[key] = fn(j[key])
    return json.dumps(j)


SCHEMA_CASES = {
    "exit_code string": lambda r: r.replace('"exit_code":0', '"exit_code":"0"'),
    "exit_code float": lambda r: r.replace('"exit_code":0', '"exit_code":0.0'),
    "score string": lambda r: r.replace('"score":10', '"score":"10"'),
    "score float": lambda r: r.replace('"score":10', '"score":10.0'),
    "dup key allow first": lambda r: r.replace(
        '"verdict":"deny"', '"verdict":"allow","verdict":"deny"'
    ),
    "dup key deny first": lambda r: r.replace(
        '"verdict":"deny"', '"verdict":"deny","verdict":"allow"'
    ),
    "missing killed_by": lambda r: _drop(r, "execution", "killed_by"),
    "missing reason": lambda r: _drop(r, "decision", "reason"),
    "missing stdout_sha256": lambda r: _drop(r, "execution", "stdout_sha256"),
    "extra top field": lambda r: _set(r, "task_id", lambda v: v)[:-1] + ',"x":1}',
    "sig uppercase": lambda r: _set(r, "sig_ed25519", str.upper),
    "hash uppercase": lambda r: _set(r, "hash", str.upper),
    "sig not hex": lambda r: _set(r, "sig_ed25519", lambda v: "zz"),
    "sig short": lambda r: _set(r, "sig_ed25519", lambda v: v[:-2]),
    "int above 2**53": lambda r: r.replace('"exit_code":0', '"exit_code":9007199254740993'),
    "NaN": lambda r: r.replace('"cpus":0.5', '"cpus":NaN'),
    "bool for int": lambda r: r.replace('"exit_code":0', '"exit_code":false'),
    "not an object": lambda r: "[" + r + "]",
    "truncated json": lambda r: r[:-1],
}


@pytest.mark.parametrize("name", list(SCHEMA_CASES))
def test_malformed_receipt_is_schema_error(env, name):
    _, d, raw = env
    text = SCHEMA_CASES[name](raw)
    assert text != raw
    with pytest.raises(ReceiptFormatError):
        parse_receipt_unchecked(text)
    p = d / "r.json"
    p.write_text(text)
    assert verify_receipt(p, d / "pub") == EXIT_SCHEMA_ERROR


@pytest.mark.parametrize(
    "fmt",
    [
        lambda j: json.dumps(j),
        lambda j: json.dumps(j, indent=4),
        lambda j: json.dumps(dict(reversed(list(j.items())))),
    ],
)
def test_equivalent_encodings_still_verify(env, fmt):
    _, d, raw = env
    p = d / "r.json"
    p.write_text(fmt(json.loads(raw)))
    assert verify_receipt(p, d / "pub") == EXIT_SUCCESS


def test_canonical_bytes_match_signed_digest(env):
    signer, _, raw = env
    r = load_receipt(raw, signer.public_key)
    assert signer.verify(r)


def test_load_receipt_requires_a_key(env):
    # Review 5 M2: the public loader must never accept a receipt on parse alone.
    _, _, raw = env
    with pytest.raises(TypeError):
        load_receipt(raw)  # type: ignore[call-arg]


def test_load_receipt_rejects_wrong_hash(env):
    signer, _, raw = env
    doc = json.loads(raw)
    doc["context"] = {"forged": "yes"}
    with pytest.raises(ReceiptHashError):
        load_receipt(json.dumps(doc), signer.public_key)
    # the unchecked parser still accepts it, which is why it carries that name
    parse_receipt_unchecked(json.dumps(doc))


def test_load_receipt_rejects_wrong_signature_and_wrong_key(env):
    signer, _, raw = env
    doc = json.loads(raw)
    doc["sig_ed25519"] = ("0" if doc["sig_ed25519"][0] != "0" else "1") + doc["sig_ed25519"][1:]
    with pytest.raises(ReceiptSignatureError):
        load_receipt(json.dumps(doc), signer.public_key)
    with pytest.raises(ReceiptSignatureError):
        load_receipt(raw, ReceiptSigner().public_key)


def test_value_change_is_hash_mismatch(env):
    _, d, raw = env
    p = d / "r.json"
    p.write_text(raw.replace('"verdict":"deny"', '"verdict":"allow"'))
    assert verify_receipt(p, d / "pub") == EXIT_HASH_MISMATCH


def test_sign_rejects_unsafe_int():
    with pytest.raises(ReceiptFormatError):
        ReceiptSigner().sign(_data(exit_code=2**53 + 1))


def _chain(env):
    signer, d, _ = env
    c = d / "chain"
    c.mkdir()
    prev = None
    for i in range(3):
        r = signer.sign(_data(f"a{i}"), prev_hash=prev)
        (c / f"{i}.json").write_text(r.model_dump_json(by_alias=True))
        prev = r.hash
    return c


@pytest.mark.parametrize(
    ("head", "rc"),
    [
        ("{}", EXIT_SCHEMA_ERROR),
        ("not json", EXIT_SCHEMA_ERROR),
        ('{"head_hash": "' + "0" * 64 + '"}', EXIT_SCHEMA_ERROR),
        (
            '{"head_hash": "' + "A" * 64 + '", "sig_ed25519": "' + "0" * 128 + '"}',
            EXIT_SCHEMA_ERROR,
        ),
        (
            '{"head_hash": "' + "0" * 64 + '", "sig_ed25519": "' + "0" * 128 + '"}',
            EXIT_SIGNATURE_INVALID,
        ),
    ],
)
def test_chain_head_errors(env, head, rc):
    _, d, _ = env
    c = _chain(env)
    h = d / "head.json"
    h.write_text(head)
    assert verify_chain(c, d / "pub", h) == rc


def test_chain_head_detects_dropped_tail(env):
    _, d, _ = env
    c = _chain(env)
    h = d / "head.json"
    assert sign_chain_head(c, d / "k", h) == EXIT_SUCCESS
    assert verify_chain(c, d / "pub", h) == EXIT_SUCCESS
    (c / "2.json").unlink()
    assert verify_chain(c, d / "pub", h) == EXIT_CHAIN_LINK_BROKEN


def test_chain_head_inside_dir_is_excluded(env):
    _, d, _ = env
    c = _chain(env)
    h = c / "head.json"
    assert sign_chain_head(c, d / "k", d / "tmp_head.json") == EXIT_SUCCESS
    h.write_text((d / "tmp_head.json").read_text())
    assert verify_chain(c, d / "pub", c / "." / "head.json") == EXIT_SUCCESS
