"""Evidence Bundle v1 + Task Verdict: positive path and mandatory tamper matrix.

Offline verifier must not need a server or network. Trusted key is supplied by
the auditor out of band. Bundled signing.pub is never the trust anchor.
"""

from __future__ import annotations

import io
import json
import socket
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from airlock.evidence.bundle import (  # noqa: E402
    INPUT_NAME,
    MANIFEST_NAME,
    REPORT_NAME,
    STATUS_BUNDLE,
    STATUS_HASH,
    STATUS_OK_FAILED_RECOUNT,
    STATUS_OK_INCONCLUSIVE,
    STATUS_OK_VERIFIED,
    STATUS_SCHEMA,
    STATUS_SIGNATURE,
    STATUS_UNSUPPORTED_VERIFIER,
    VERDICT_NAME,
    EvidenceBundleError,
    build_evidence_bundle,
    verify_evidence_bundle,
)
from airlock.evidence.counts_v1 import format_counts_block, verifier_code_hash  # noqa: E402
from airlock.evidence.verdict import (  # noqa: E402
    VERDICT_DOMAIN,
    sign_task_verdict,
    verify_task_verdict,
)
from airlock.receipt import ReceiptSigner, hash_data  # noqa: E402
from airlock.web import tasks  # noqa: E402
from airlock.web.app import Settings, create_app  # noqa: E402
from tests.test_web_api import FakeRunner  # noqa: E402

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "evidence_bundle"


def _replay_client(tmp_path: Path) -> tuple[TestClient, ReceiptSigner, Path]:
    from airlock.schemas import Cleanup
    from airlock.web.chain import load_or_create_signer

    settings = Settings(data_dir=tmp_path / "data")
    app = create_app(settings, runner_factory=FakeRunner, llm_factory=lambda: None)
    # Avoid docker in verify_cleanup (same stub as tests/test_web_api.py).
    app.state.pipeline.verifier.verify_cleanup = lambda name: Cleanup(
        container_absent=True, network_absent=True, evidence="fake runner"
    )
    client = TestClient(app)
    signer = load_or_create_signer(settings.data_dir / "keys")
    return client, signer, settings.data_dir


def _run_replay(client: TestClient) -> dict:
    r = client.post("/api/task", json={"kind": "injected", "mode": "replay_compromised"})
    assert r.status_code == 200, r.text
    return r.json()


def _load_bundle(data_dir: Path, task_id: str) -> bytes:
    path = data_dir / "evidence_bundles" / f"{task_id}.zip"
    assert path.is_file(), f"missing bundle for {task_id}"
    return path.read_bytes()


def _rewrite_zip(blob: bytes, replace: dict[str, bytes], drop: set[str] | None = None) -> bytes:
    drop = drop or set()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zin:
        members = {i.filename: zin.read(i) for i in zin.infolist() if not i.is_dir()}
    for k, v in replace.items():
        members[k] = v
    for k in drop:
        members.pop(k, None)
    # Rebuild manifest hashes if present and not explicitly replaced.
    if MANIFEST_NAME in members and MANIFEST_NAME not in replace:
        man = json.loads(members[MANIFEST_NAME])
        man["members"] = [
            {"path": p, "sha256": hash_data(d), "size": len(d)}
            for p, d in members.items()
            if p != MANIFEST_NAME
        ]
        members[MANIFEST_NAME] = json.dumps(man, indent=2, sort_keys=True).encode() + b"\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name, data in members.items():
            zout.writestr(name, data)
    return buf.getvalue()


def test_replay_bundle_verifies_offline_with_external_pubkey(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    assert out["task_verdict"]["domain"] == VERDICT_DOMAIN
    assert out["task_verdict"]["input_log_sha256"] == hash_data(tasks.sample_log(True))
    assert out["evidence_bundle"]["available"] is True
    blob = _load_bundle(data_dir, out["task_id"])
    # Auditor key = app public key loaded out of band (not from the zip).
    result = verify_evidence_bundle(blob, signer.public_key)
    assert result.status in (STATUS_OK_VERIFIED, STATUS_OK_FAILED_RECOUNT, STATUS_OK_INCONCLUSIVE)
    # Replay with correct counts should VERIFIED.
    assert result.status == STATUS_OK_VERIFIED
    assert result.recount_status == "VERIFIED"
    # CLI path
    pub = tmp_path / "trusted.pem"
    pub.write_text(signer.export_public_key())
    bundle_path = tmp_path / "bundle.zip"
    bundle_path.write_bytes(blob)
    from airlock.cli import verify_bundle

    assert verify_bundle(bundle_path, pub) == 0


def test_signed_verdict_binds_input_report_and_receipt_chain(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    tv = out["task_verdict"]
    assert tv["report_sha256"] == hash_data(out["report"]["text"].encode())
    assert tv["report_commitment"] == f"sha256:{tv['report_sha256']}"
    receipts = tv["action_receipts"]
    assert len(receipts) >= 4
    assert [r["seq"] for r in receipts] == list(range(1, len(receipts) + 1))
    # Every receipt hash appears in the API steps in the same order.
    step_ids = [s["receipt_id"] for s in out["steps"]]
    assert [r["receipt_hash"] for r in receipts] == step_ids
    verify_task_verdict(json.dumps(tv), signer.public_key)


def test_tamper_input_report_verdict_fail(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])

    flipped_input = _rewrite_zip(blob, {INPUT_NAME: b"INFO x\nERROR tampered\n"})
    assert verify_evidence_bundle(flipped_input, signer.public_key).status == STATUS_HASH

    bad_report = (out["report"]["text"] or "") + "\n# tampered\n"
    flipped_report = _rewrite_zip(blob, {REPORT_NAME: bad_report.encode()})
    assert verify_evidence_bundle(flipped_report, signer.public_key).status == STATUS_HASH

    verdict = json.loads(zipfile.ZipFile(io.BytesIO(blob)).read(VERDICT_NAME))
    verdict["recount_status"] = "FAILED" if verdict["recount_status"] == "VERIFIED" else "VERIFIED"
    # Re-sign with wrong content but keep old sig → signature/hash fail
    flipped_verdict = _rewrite_zip(
        blob, {VERDICT_NAME: json.dumps(verdict, indent=2).encode() + b"\n"}
    )
    st = verify_evidence_bundle(flipped_verdict, signer.public_key).status
    assert st in (STATUS_HASH, STATUS_SIGNATURE, STATUS_SCHEMA)


def test_tamper_receipt_signature_and_reorder(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        names = [n for n in zf.namelist() if n.startswith("receipts/")]
        assert len(names) >= 2
        a, b = names[0], names[1]
        ra, rb = zf.read(a), zf.read(b)
    # Swap two receipt file bodies under the original names → hash / task binding fail
    swapped = _rewrite_zip(blob, {a: rb, b: ra})
    assert verify_evidence_bundle(swapped, signer.public_key).status in (
        STATUS_HASH,
        STATUS_BUNDLE,
        STATUS_SCHEMA,
        STATUS_SIGNATURE,
    )
    # Flip one character inside a receipt
    tampered = ra.decode()
    tampered = (
        tampered.replace('"deny"', '"denx"', 1) if '"deny"' in tampered else tampered[:-2] + "x"
    )
    flipped = _rewrite_zip(blob, {a: tampered.encode()})
    assert verify_evidence_bundle(flipped, signer.public_key).status in (
        STATUS_HASH,
        STATUS_SIGNATURE,
        STATUS_SCHEMA,
    )


def test_missing_duplicate_cross_task_and_attacker_key(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])

    missing = _rewrite_zip(blob, {}, drop={REPORT_NAME})
    # Also strip report from verdict would be needed; missing file vs manifest
    st = verify_evidence_bundle(missing, signer.public_key).status
    assert st in (STATUS_BUNDLE, STATUS_HASH, STATUS_SCHEMA)

    attacker = ReceiptSigner()
    assert verify_evidence_bundle(blob, attacker.public_key).status == STATUS_SIGNATURE

    # Absent key path via CLI
    from airlock.cli import verify_bundle

    assert verify_bundle(tmp_path / "nope.zip", tmp_path / "missing.pem") == 15


def test_unsupported_verifier_version_rejected(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        verdict = json.loads(zf.read(VERDICT_NAME))
    verdict["verifier"] = {
        "id": "airlock.counts.error_warn",
        "version": "999",
        "code_hash": verifier_code_hash(),
    }
    # Must re-sign so crypto passes and version check fires
    unsigned = {k: v for k, v in verdict.items() if k not in ("hash", "sig_ed25519")}
    resigned = sign_task_verdict(signer, unsigned)
    flipped = _rewrite_zip(
        blob, {VERDICT_NAME: json.dumps(resigned, indent=2, sort_keys=True).encode() + b"\n"}
    )
    assert verify_evidence_bundle(flipped, signer.public_key).status == STATUS_UNSUPPORTED_VERIFIER


def _chain_get(data_dir: Path):
    def get_text(rid: str):
        matches = list((data_dir / "receipts").glob(f"*_{rid}.json"))
        return matches[0].read_text() if len(matches) == 1 else None

    return get_text


def test_failed_recount_is_authentic_not_success(tmp_path):
    """Valid signed FAILED recount is integrity-OK and distinct from VERIFIED."""
    client, app_signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    out2 = dict(out)
    out2["report"] = dict(out["report"])
    # Injected fixture is ERROR:31 WARN:8 — wrong ERROR yields FAILED.
    out2["report"]["text"] = format_counts_block(99, 8)
    out2["report"]["sha256"] = hash_data(out2["report"]["text"].encode())
    blob = build_evidence_bundle(
        signer=app_signer,
        chain_get_text=_chain_get(data_dir),
        task_result=out2,
        input_log=tasks.sample_log(True),
    )
    result = verify_evidence_bundle(blob, app_signer.public_key)
    assert result.status == STATUS_OK_FAILED_RECOUNT
    assert result.recount_status == "FAILED"


def test_archive_traversal_and_symlink_rejected(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        with zipfile.ZipFile(io.BytesIO(blob), "r") as zin:
            for info in zin.infolist():
                zf.writestr(info, zin.read(info))
        zf.writestr("../evil.txt", b"nope")
    assert verify_evidence_bundle(buf.getvalue(), signer.public_key).status == STATUS_BUNDLE


def test_export_rejects_non_fixture_log(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    with pytest.raises(EvidenceBundleError):
        build_evidence_bundle(
            signer=signer,
            chain_get_text=lambda rid: None,
            task_result=out,
            input_log=b"not an authorized fixture\n",
        )


def test_offline_verifier_makes_no_network_calls(tmp_path, monkeypatch):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])

    def _blocked(*_a, **_k):
        raise AssertionError("network call during offline verify")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    result = verify_evidence_bundle(blob, signer.public_key)
    assert result.status == STATUS_OK_VERIFIED


def test_old_action_receipt_wire_format_unchanged(tmp_path):
    """Evidence work must not alter ActionReceipt schema / verify path."""
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    rid = out["steps"][0]["receipt_id"]
    text = client.get(f"/api/receipt/{rid}").text
    from airlock.receipt import load_receipt

    rec = load_receipt(text, signer.public_key)
    assert rec.receipt_v == 1
    assert rec.task_id == out["task_id"]
    dumped = json.loads(text)
    assert "hash" in dumped and "sig_ed25519" in dumped
    assert "domain" not in dumped  # receipts are not task verdicts


def test_nested_counts_in_bundle_report_inconclusive(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    nested = "````\n```airlock-counts\nERROR: 31\nWARN: 8\n```\n````\n"
    out2 = dict(out)
    out2["report"] = dict(out["report"])
    out2["report"]["text"] = nested
    out2["report"]["sha256"] = hash_data(nested.encode())

    def get_text(rid: str):
        matches = list((data_dir / "receipts").glob(f"*_{rid}.json"))
        return matches[0].read_text() if matches else None

    blob = build_evidence_bundle(
        signer=signer,
        chain_get_text=get_text,
        task_result=out2,
        input_log=tasks.sample_log(True),
    )
    result = verify_evidence_bundle(blob, signer.public_key)
    assert result.status == STATUS_OK_INCONCLUSIVE
    assert result.recount_status == "INCONCLUSIVE"


def test_materialize_fixture_bundle_for_parent_review(tmp_path):
    """Write a runnable sample bundle + trusted pubkey under tests/fixtures/."""
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    (FIXTURE_DIR / "sample-evidence-bundle.zip").write_bytes(blob)
    (FIXTURE_DIR / "auditor-trusted.pem").write_text(signer.export_public_key())
    (FIXTURE_DIR / "README.md").write_text(
        "# Evidence Bundle v1 fixture\n\n"
        "Offline verify (no server/network):\n\n"
        "```bash\n"
        "airlock verify-bundle tests/fixtures/evidence_bundle/sample-evidence-bundle.zip \\\n"
        "  --pubkey tests/fixtures/evidence_bundle/auditor-trusted.pem\n"
        "```\n\n"
        "Exit 0 = authentic + recount VERIFIED. Exit 1 = authentic + recount FAILED. "
        "Exit 2 = authentic but incomplete/inconclusive. "
        "The PEM here is the out-of-band trust anchor for this fixture only; "
        "bundled signing.pub inside the zip is convenience, not trust.\n"
    )
    assert verify_evidence_bundle(blob, signer.public_key).status == STATUS_OK_VERIFIED
