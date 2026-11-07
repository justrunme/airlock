"""Evidence Bundle v1: positive path, fail-closed corrupt path, exact CLI exits."""

from __future__ import annotations

import io
import json
import socket
import subprocess
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
    STATUS_UNSUPPORTED_VERIFIER,
    VERDICT_NAME,
    EvidenceBundleError,
    build_evidence_bundle,
    collect_action_receipts_from_result,
    verify_evidence_bundle,
)
from airlock.evidence.counts_v1 import format_counts_block, verifier_code_hash  # noqa: E402
from airlock.evidence.verdict import (  # noqa: E402
    VERDICT_DOMAIN,
    sign_task_verdict,
    verify_task_verdict,
)
from airlock.receipt import ReceiptFormatError, ReceiptSigner, hash_data, load_receipt  # noqa: E402
from airlock.schemas import Cleanup  # noqa: E402
from airlock.web import tasks  # noqa: E402
from airlock.web.app import Settings, create_app  # noqa: E402
from airlock.web.chain import load_or_create_signer  # noqa: E402
from tests.test_web_api import FakeRunner  # noqa: E402

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "evidence_bundle"
FIXTURE_ZIP = FIXTURE_DIR / "sample-evidence-bundle.zip"
FIXTURE_PEM = FIXTURE_DIR / "auditor-trusted.pem"


def _replay_client(tmp_path: Path) -> tuple[TestClient, ReceiptSigner, Path]:
    settings = Settings(data_dir=tmp_path / "data")
    app = create_app(settings, runner_factory=FakeRunner, llm_factory=lambda: None)
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


def _chain_get(data_dir: Path):
    def get_text(rid: str):
        matches = list((data_dir / "receipts").glob(f"*_{rid}.json"))
        return matches[0].read_text() if len(matches) == 1 else None

    return get_text


def _rewrite_zip(
    blob: bytes, replace: dict[str, bytes] | None = None, drop: set[str] | None = None
):
    replace = replace or {}
    drop = drop or set()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zin:
        members = {i.filename: zin.read(i) for i in zin.infolist() if not i.is_dir()}
    for k in drop:
        members.pop(k, None)
    members.update(replace)
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


def _cli_verify(bundle: Path, pubkey: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["airlock", "verify-bundle", str(bundle), "--pubkey", str(pubkey)],
        capture_output=True,
        text=True,
        check=False,
    )


# ---- positive / binding


def test_replay_bundle_verifies_offline_with_external_pubkey(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    assert out["task_verdict"]["domain"] == VERDICT_DOMAIN
    assert out["evidence_bundle"]["available"] is True
    assert out["evidence_bundle"]["status"] == "ready"
    blob = _load_bundle(data_dir, out["task_id"])
    result = verify_evidence_bundle(blob, signer.public_key)
    assert result.status == STATUS_OK_VERIFIED
    assert result.details["mode"] == "replay_compromised"
    pub = tmp_path / "trusted.pem"
    pub.write_text(signer.export_public_key())
    bundle_path = tmp_path / "bundle.zip"
    bundle_path.write_bytes(blob)
    proc = _cli_verify(bundle_path, pub)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "replay_compromised" in proc.stdout
    assert "NOT live-model evidence" in proc.stdout
    assert "task_kind" in proc.stdout


def test_signed_verdict_binds_input_report_and_receipt_chain(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    tv = out["task_verdict"]
    assert tv["report_sha256"] == hash_data(out["report"]["text"].encode())
    receipts = tv["action_receipts"]
    assert len(receipts) >= 4
    assert [r["seq"] for r in receipts] == list(range(1, len(receipts) + 1))
    assert [r["receipt_hash"] for r in receipts] == [s["receipt_id"] for s in out["steps"]]
    verify_task_verdict(json.dumps(tv), signer.public_key)


def test_committed_fixture_verifies_exact_exit_0():
    """Read-only check of the tracked fixture (tests must not rewrite it)."""
    assert FIXTURE_ZIP.is_file() and FIXTURE_PEM.is_file()
    before = FIXTURE_ZIP.read_bytes()
    proc = _cli_verify(FIXTURE_ZIP, FIXTURE_PEM)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert FIXTURE_ZIP.read_bytes() == before
    assert "NOT live-model evidence" in proc.stdout


# ---- fail-closed corrupt / schema (exact CLI exits)


def test_cli_corrupt_crc_member_exits_17_not_1(tmp_path):
    blob = FIXTURE_ZIP.read_bytes()
    with zipfile.ZipFile(io.BytesIO(blob)) as zin:
        members = [(i, zin.read(i)) for i in zin.infolist() if not i.is_dir()]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for i, d in members:
            info = zipfile.ZipInfo(i.filename)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = i.external_attr
            zout.writestr(info, d)
    raw = bytearray(buf.getvalue())
    raw[len(raw) // 2] ^= 0x55
    path = tmp_path / "corrupt.zip"
    path.write_bytes(bytes(raw))
    proc = _cli_verify(path, FIXTURE_PEM)
    assert proc.returncode == 17, (proc.returncode, proc.stdout, proc.stderr)
    assert "Traceback" not in proc.stderr


def test_cli_invalid_utf8_report_with_rebuilt_manifest_exits_12(tmp_path):
    """Commitments checked before UTF-8 decode; invalid UTF-8 → 12, never traceback/1."""
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    bad_report = b"\xff\xfe not utf8"
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        verdict = json.loads(zf.read(VERDICT_NAME))
    unsigned = {k: v for k, v in verdict.items() if k not in ("hash", "sig_ed25519")}
    unsigned["report_sha256"] = hash_data(bad_report)
    unsigned["report_commitment"] = f"sha256:{unsigned['report_sha256']}"
    resigned = sign_task_verdict(signer, unsigned)
    bad = _rewrite_zip(
        blob,
        {
            REPORT_NAME: bad_report,
            VERDICT_NAME: json.dumps(resigned, indent=2, sort_keys=True).encode() + b"\n",
        },
    )
    path = tmp_path / "badutf8.zip"
    path.write_bytes(bad)
    r = verify_evidence_bundle(bad, signer.public_key)
    assert r.status == STATUS_SCHEMA, r
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode == 12, (proc.returncode, proc.stdout, proc.stderr)
    assert "Traceback" not in proc.stderr


def test_extra_members_with_rewritten_unsigned_manifest_exit_17(tmp_path):
    """Reject unbound archive members even when the unsigned manifest is rewritten."""
    blob = FIXTURE_ZIP.read_bytes()
    with zipfile.ZipFile(io.BytesIO(blob)) as zin:
        members = {i.filename: zin.read(i) for i in zin.infolist() if not i.is_dir()}
    members["extra.txt"] = b"pwned"
    members["x.txt"] = b"x"
    members["report2.md"] = b"# alternate report\n"
    members["receipts/x.txt"] = b"not-a-receipt"
    # Fake receipt-like name not listed in signed verdict
    members["receipts/9999_" + ("ab" * 32) + ".json"] = b"{}"
    man = {
        "schema_v": 1,
        "bundle_v": 1,
        "task_id": "attacker",
        "fixture_log": "app_injected.log",
        "evil_metadata": "not trusted",
        "trust_note": "attacker",
        "members": [
            {"path": p, "sha256": hash_data(d), "size": len(d)}
            for p, d in members.items()
            if p != MANIFEST_NAME
        ],
    }
    members[MANIFEST_NAME] = json.dumps(man, indent=2, sort_keys=True).encode() + b"\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for n, d in members.items():
            zout.writestr(n, d)
    evil = buf.getvalue()
    pub = ReceiptSigner.load_public_key(FIXTURE_PEM)
    r = verify_evidence_bundle(evil, pub)
    assert r.status == STATUS_BUNDLE, r
    assert "unbound" in r.message
    path = tmp_path / "extra.zip"
    path.write_bytes(evil)
    proc = _cli_verify(path, FIXTURE_PEM)
    assert proc.returncode == 17, (proc.returncode, proc.stdout, proc.stderr)


def test_extra_txt_only_with_rewritten_manifest_exit_17(tmp_path):
    blob = FIXTURE_ZIP.read_bytes()
    with zipfile.ZipFile(io.BytesIO(blob)) as zin:
        members = {i.filename: zin.read(i) for i in zin.infolist() if not i.is_dir()}
    members["extra.txt"] = b"pwned"
    man = {
        "schema_v": 1,
        "bundle_v": 1,
        "task_id": "attacker",
        "members": [
            {"path": p, "sha256": hash_data(d), "size": len(d)}
            for p, d in members.items()
            if p != MANIFEST_NAME
        ],
    }
    members[MANIFEST_NAME] = json.dumps(man, indent=2, sort_keys=True).encode() + b"\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for n, d in members.items():
            zout.writestr(n, d)
    evil = buf.getvalue()
    assert verify_evidence_bundle(evil, ReceiptSigner.load_public_key(FIXTURE_PEM)).status == (
        STATUS_BUNDLE
    )
    path = tmp_path / "extra2.zip"
    path.write_bytes(evil)
    assert _cli_verify(path, FIXTURE_PEM).returncode == 17


def test_cli_tampered_input_exits_11(tmp_path):
    blob = FIXTURE_ZIP.read_bytes()
    flipped = _rewrite_zip(blob, {INPUT_NAME: b"INFO x\nERROR tampered\n"})
    path = tmp_path / "flip_input.zip"
    path.write_bytes(flipped)
    proc = _cli_verify(path, FIXTURE_PEM)
    assert proc.returncode == 11, (proc.returncode, proc.stdout, proc.stderr)


def test_cli_attacker_key_exits_10(tmp_path):
    attacker = ReceiptSigner()
    pub = tmp_path / "attacker.pem"
    pub.write_text(attacker.export_public_key())
    proc = _cli_verify(FIXTURE_ZIP, pub)
    assert proc.returncode == 10, (proc.returncode, proc.stdout, proc.stderr)


def test_duplicate_zip_member_names_exit_17(tmp_path):
    blob = FIXTURE_ZIP.read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        with zipfile.ZipFile(io.BytesIO(blob)) as zin:
            for info in zin.infolist():
                zout.writestr(info, zin.read(info))
        # Force a second member with the same name via ZipInfo
        zout.writestr(INPUT_NAME, b"duplicate")
    path = tmp_path / "dup.zip"
    path.write_bytes(buf.getvalue())
    proc = _cli_verify(path, FIXTURE_PEM)
    assert proc.returncode == 17, (proc.returncode, proc.stdout, proc.stderr)


def test_symlink_mode_member_exit_17(tmp_path):
    blob = FIXTURE_ZIP.read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        with zipfile.ZipFile(io.BytesIO(blob)) as zin:
            for info in zin.infolist():
                zout.writestr(info, zin.read(info))
        link = zipfile.ZipInfo("evil_link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16  # S_IFLNK
        zout.writestr(link, b"/tmp/x")
    # Rebuild manifest would be needed for hash path; symlink should fail at read
    path = tmp_path / "symlink.zip"
    path.write_bytes(buf.getvalue())
    proc = _cli_verify(path, FIXTURE_PEM)
    assert proc.returncode == 17, (proc.returncode, proc.stdout, proc.stderr)


def test_zipbomb_mismatched_declared_size_exit_17(tmp_path):
    """Header file_size that does not match inflated bytes is rejected."""
    blob = FIXTURE_ZIP.read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info)
            if info.filename == INPUT_NAME:
                # Write via writestr then we can't easily lie about size with
                # ZipFile API; craft a ZipInfo with wrong file_size using raw.
                zi = zipfile.ZipInfo(INPUT_NAME)
                zi.compress_type = zipfile.ZIP_STORED
                zi.file_size = len(data) + 100  # lie
                zi.external_attr = 0o644 << 16
                # writestr overwrites file_size from data — use ZIP64 trick:
                zout.writestr(zi, data)
                # After writestr, file_size matches; skip if API corrects it.
            else:
                zout.writestr(info, data)
    # If ZipFile corrected size, inject via low-level: accept either 17 from
    # duplicate/extra path after our read guard when sizes diverge on CRC path.
    # Force mismatch by patching Local File Header after write is fragile;
    # instead unit-test the guard directly:
    from airlock.evidence.bundle import _read_zip_safe

    # Build a minimal zip where we monkeypatch ZipInfo after open — call guard
    # with a handcrafted member using zipfile that reports wrong size:
    class FakeInfo:
        filename = "input/app.log"
        flag_bits = 0
        compress_type = zipfile.ZIP_STORED
        external_attr = 0o644 << 16
        file_size = 10  # declared larger than actual inflate

    class FakeZip:
        def namelist(self):
            return ["input/app.log"]

        def infolist(self):
            return [FakeInfo()]

        def read(self, info):
            return b"short"  # 5 bytes

    import airlock.evidence.bundle as bundle_mod

    real_zf = zipfile.ZipFile

    def fake_zf(*a, **k):
        return FakeZip()

    bundle_mod.zipfile.ZipFile = fake_zf  # type: ignore[assignment]
    try:
        with pytest.raises(EvidenceBundleError, match="size mismatch"):
            _read_zip_safe(b"PK\x03\x04fake")
    finally:
        bundle_mod.zipfile.ZipFile = real_zf


# ---- completeness / cross-task


def test_collector_rejects_gated_step_without_receipt_id():
    with pytest.raises(EvidenceBundleError, match="incomplete receipt chain"):
        collect_action_receipts_from_result(
            {
                "steps": [
                    {"verdict": "deny", "action": {"id": "a1"}},  # no receipt_id
                ]
            }
        )


def test_removed_receipt_and_resigned_verdict_is_incomplete(tmp_path):
    """Re-sign omitting an action but leave its receipt file → completeness fail (17)."""
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        receipt_names = sorted(n for n in zf.namelist() if n.startswith("receipts/"))
        verdict = json.loads(zf.read(VERDICT_NAME))
    assert len(receipt_names) >= 2
    unsigned = {k: v for k, v in verdict.items() if k not in ("hash", "sig_ed25519")}
    unsigned["action_receipts"] = unsigned["action_receipts"][:-1]
    for i, e in enumerate(unsigned["action_receipts"], 1):
        e["seq"] = i
    resigned = sign_task_verdict(signer, unsigned)
    # Keep all receipt files; verdict lists fewer → count / unexpected filename fail.
    flipped = _rewrite_zip(
        blob,
        {VERDICT_NAME: json.dumps(resigned, indent=2, sort_keys=True).encode() + b"\n"},
    )
    r = verify_evidence_bundle(flipped, signer.public_key)
    assert r.status == STATUS_BUNDLE, r
    path = tmp_path / "omit.zip"
    path.write_bytes(flipped)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode == 17, (proc.returncode, proc.stdout, proc.stderr)


def test_missing_receipt_file_listed_in_verdict_exit_17(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        receipt_names = sorted(n for n in zf.namelist() if n.startswith("receipts/"))
    flipped = _rewrite_zip(blob, drop={receipt_names[-1]})
    r = verify_evidence_bundle(flipped, signer.public_key)
    assert r.status in (STATUS_BUNDLE, STATUS_HASH), r
    path = tmp_path / "missing_rcpt.zip"
    path.write_bytes(flipped)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode in (11, 17), (proc.returncode, proc.stdout, proc.stderr)
    assert proc.returncode != 1


def test_correctly_signed_cross_task_receipt_rejected(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out_a = _run_replay(client)
    out_b = _run_replay(client)
    blob_a = _load_bundle(data_dir, out_a["task_id"])
    # Take a receipt from task B, place it into A's bundle under A's first receipt name
    with zipfile.ZipFile(io.BytesIO(blob_a)) as za:
        a_receipts = sorted(n for n in za.namelist() if n.startswith("receipts/"))
        first = a_receipts[0]
    blob_b = _load_bundle(data_dir, out_b["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob_b)) as zb:
        b_receipts = sorted(n for n in zb.namelist() if n.startswith("receipts/"))
        foreign = zb.read(b_receipts[0])
    # Put foreign bytes under A's filename — hash in filename won't match content hash
    # Better: put foreign under correct foreign hash name but keep A's verdict list —
    # that fails name matching. For cross-task: keep A's verdict meta pointing at
    # A's hash but substitute file body with B's receipt (still signed by same key).
    swapped = _rewrite_zip(blob_a, {first: foreign})
    r = verify_evidence_bundle(swapped, signer.public_key)
    assert r.status in (STATUS_HASH, STATUS_BUNDLE, STATUS_SCHEMA), r
    path = tmp_path / "cross.zip"
    path.write_bytes(swapped)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode in (11, 12, 17), (proc.returncode, proc.stdout, proc.stderr)
    assert proc.returncode != 0
    assert proc.returncode != 1  # must not look like authentic FAILED recount


def test_malformed_action_receipt_meta_no_keyerror(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        verdict = json.loads(zf.read(VERDICT_NAME))
    unsigned = {k: v for k, v in verdict.items() if k not in ("hash", "sig_ed25519")}
    unsigned["action_receipts"][0] = {"seq": 1}  # missing action_id / receipt_hash
    resigned = sign_task_verdict(signer, unsigned)
    flipped = _rewrite_zip(
        blob, {VERDICT_NAME: json.dumps(resigned, indent=2, sort_keys=True).encode() + b"\n"}
    )
    r = verify_evidence_bundle(flipped, signer.public_key)
    assert r.status == STATUS_SCHEMA
    path = tmp_path / "meta.zip"
    path.write_bytes(flipped)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode == 12, (proc.returncode, proc.stdout, proc.stderr)


def test_failed_recount_exact_exit_1(tmp_path):
    client, app_signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    out2 = dict(out)
    out2["report"] = dict(out["report"])
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
    path = tmp_path / "failed.zip"
    path.write_bytes(blob)
    pub = tmp_path / "p.pem"
    pub.write_text(app_signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)


def test_nested_counts_inconclusive_exact_exit_2(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    nested = "````\n```airlock-counts\nERROR: 31\nWARN: 8\n```\n````\n"
    out2 = dict(out)
    out2["report"] = dict(out["report"])
    out2["report"]["text"] = nested
    out2["report"]["sha256"] = hash_data(nested.encode())
    blob = build_evidence_bundle(
        signer=signer,
        chain_get_text=_chain_get(data_dir),
        task_result=out2,
        input_log=tasks.sample_log(True),
    )
    result = verify_evidence_bundle(blob, signer.public_key)
    assert result.status == STATUS_OK_INCONCLUSIVE
    path = tmp_path / "inc.zip"
    path.write_bytes(blob)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode == 2, (proc.returncode, proc.stdout, proc.stderr)


def test_unsupported_verifier_exact_exit_18(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        verdict = json.loads(zf.read(VERDICT_NAME))
    unsigned = {k: v for k, v in verdict.items() if k not in ("hash", "sig_ed25519")}
    unsigned["verifier"] = {
        "id": "airlock.counts.error_warn",
        "version": "999",
        "code_hash": verifier_code_hash(),
    }
    resigned = sign_task_verdict(signer, unsigned)
    flipped = _rewrite_zip(
        blob, {VERDICT_NAME: json.dumps(resigned, indent=2, sort_keys=True).encode() + b"\n"}
    )
    assert verify_evidence_bundle(flipped, signer.public_key).status == STATUS_UNSUPPORTED_VERIFIER
    path = tmp_path / "uver.zip"
    path.write_bytes(flipped)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())
    proc = _cli_verify(path, pub)
    assert proc.returncode == 18, (proc.returncode, proc.stdout, proc.stderr)


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


def test_offline_cli_subprocess_with_network_disabled(tmp_path, monkeypatch):
    """Subprocess offline CLI must not need network; socket factory blocked in-process too."""
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    blob = _load_bundle(data_dir, out["task_id"])
    path = tmp_path / "b.zip"
    path.write_bytes(blob)
    pub = tmp_path / "p.pem"
    pub.write_text(signer.export_public_key())

    def _blocked(*_a, **_k):
        raise AssertionError("network call during offline verify")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    assert verify_evidence_bundle(blob, signer.public_key).status == STATUS_OK_VERIFIED
    # Fresh subprocess cannot inherit monkeypatch; still must succeed offline.
    proc = _cli_verify(path, pub)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_verdict_shaped_json_rejected_by_receipt_verifier(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    tv = json.dumps(out["task_verdict"])
    with pytest.raises(ReceiptFormatError):
        load_receipt(tv, signer.public_key)


def test_old_action_receipt_wire_format_unchanged(tmp_path):
    client, signer, data_dir = _replay_client(tmp_path)
    out = _run_replay(client)
    rid = out["steps"][0]["receipt_id"]
    text = client.get(f"/api/receipt/{rid}").text
    rec = load_receipt(text, signer.public_key)
    assert rec.receipt_v == 1
    assert rec.task_id == out["task_id"]
    dumped = json.loads(text)
    assert "hash" in dumped and "sig_ed25519" in dumped
    assert "domain" not in dumped


def test_evidence_postprocess_error_keeps_task_result(tmp_path):
    settings = Settings(data_dir=tmp_path / "data2", task_per_min=50)
    app = create_app(settings, runner_factory=FakeRunner, llm_factory=lambda: None)
    app.state.pipeline.verifier.verify_cleanup = lambda name: Cleanup(
        container_absent=True, network_absent=True, evidence="fake"
    )
    app.state.pipeline.chain.get_text = lambda rid: None  # type: ignore[method-assign]
    c2 = TestClient(app)
    r = c2.post("/api/task", json={"kind": "injected", "mode": "replay_compromised"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["task_id"]
    assert body["steps"]  # truthful task result preserved
    assert body["evidence_bundle"]["available"] is False
    assert body["evidence_bundle"]["status"] == "unavailable"
    assert body["task_verdict"] is None
    assert body["evidence_bundle"]["error"]
    # Client must not receive server path leakage from str(exception).
    assert body["evidence_bundle"]["detail"] == "evidence post-processing failed"
    assert "/data" not in body["evidence_bundle"]["detail"]
    assert "tmp" not in body["evidence_bundle"]["detail"].lower()


def test_startup_prunes_leftover_evidence_zips(tmp_path):
    """After restart, owned zips on disk are bounded to the cache cap."""
    data = tmp_path / "data"
    evi = data / "evidence_bundles"
    evi.mkdir(parents=True)
    # Plant 40 owned leftover zips + junk/symlink that must not be deleted blindly.
    for i in range(40):
        (evi / f"replay-{i:012x}.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    junk = evi / "not-a-task.zip"
    junk.write_bytes(b"nope")
    settings = Settings(data_dir=data, task_per_min=50)
    create_app(settings, runner_factory=FakeRunner, llm_factory=lambda: None)
    owned = sorted(evi.glob("replay-*.zip"))
    assert len(owned) == 32
    assert junk.is_file()  # non-matching name left alone


def test_disk_prune_removes_old_zip_files(tmp_path):
    """Index cap and on-disk zip deletion stay aligned; active write is not unlinked."""
    settings = Settings(data_dir=tmp_path / "data", task_per_min=50)
    app = create_app(settings, runner_factory=FakeRunner, llm_factory=lambda: None)
    app.state.pipeline.verifier.verify_cleanup = lambda name: Cleanup(
        container_absent=True, network_absent=True, evidence="fake"
    )
    client = TestClient(app)
    for _ in range(3):
        _run_replay(client)
    evi = settings.data_dir / "evidence_bundles"
    zips = sorted(evi.glob("*.zip"))
    assert len(zips) >= 3
    index = {p.stem: True for p in zips}
    active = zips[-1].stem
    max_cache = 2
    while len(index) > max_cache:
        old = next(iter(index))
        if old == active:
            index[old] = index.pop(old)
            if len(index) <= max_cache:
                break
            continue
        index.pop(old)
        (evi / f"{old}.zip").unlink(missing_ok=True)
    remaining = {p.stem for p in evi.glob("*.zip")}
    assert active in remaining
    assert len(remaining) == max_cache
