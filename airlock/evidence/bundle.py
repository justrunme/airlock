"""Evidence Bundle v1 — authorized export and offline verification.

Contains ONLY: fixture input log, report.md (when present), task_verdict.json,
ordered action receipts, minimal versioned manifest, and an optional bundled
public key (convenience, NOT the trust anchor).

Archive bytes are untrusted: bounded sizes/counts; reject traversal, absolute
paths, symlinks, and duplicate members. No server import side effects.
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from airlock.evidence.counts_v1 import (
    VERIFIER_ID,
    VERIFIER_VERSION,
    outcome_check,
    verifier_code_hash,
)
from airlock.evidence.verdict import (
    VERDICT_DOMAIN,
    VerdictFormatError,
    build_task_verdict,
    sign_task_verdict,
    verify_task_verdict,
)
from airlock.receipt import (
    HASH_RE,
    ReceiptFormatError,
    ReceiptHashError,
    ReceiptSignatureError,
    ReceiptSigner,
    hash_data,
    load_receipt,
    parse_strict_json,
)

BUNDLE_V = 1
BUNDLE_SCHEMA_V = 1
MANIFEST_NAME = "manifest.json"
VERDICT_NAME = "task_verdict.json"
REPORT_NAME = "report.md"
INPUT_NAME = "input/app.log"
PUBKEY_NAME = "signing.pub"
RECEIPTS_DIR = "receipts/"

# Hard bounds for untrusted archives and exports.
MAX_MEMBERS = 48
MAX_RECEIPTS = 24
MAX_UNCOMPRESSED = 2_000_000
MAX_SINGLE_FILE = 512_000
MAX_MANIFEST = 64_000

# Exit-style status codes used by the CLI (and tests).
STATUS_OK_VERIFIED = 0  # crypto OK + recount VERIFIED + execution complete
STATUS_OK_FAILED_RECOUNT = 1  # crypto OK + recount FAILED (signed mismatch evidence)
STATUS_OK_INCONCLUSIVE = 2  # crypto OK but incomplete/inconclusive/non-success
STATUS_SIGNATURE = 10
STATUS_HASH = 11
STATUS_SCHEMA = 12
STATUS_KEY = 15
STATUS_IO = 16
STATUS_BUNDLE = 17
STATUS_UNSUPPORTED_VERIFIER = 18


class EvidenceBundleError(ValueError):
    """Bundle structure, authz, or archive-safety failure."""


@dataclass
class BundleVerifyResult:
    status: int
    message: str
    recount_status: str | None = None
    task_id: str | None = None
    details: dict[str, Any] | None = None


def _member_sha(data: bytes) -> str:
    return hash_data(data)


def _check_member_name(name: str) -> None:
    if not name or name.endswith("/"):
        raise EvidenceBundleError(f"illegal member name: {name!r}")
    if name.startswith("/") or name.startswith("\\") or ":" in name[:3]:
        raise EvidenceBundleError(f"absolute member path rejected: {name!r}")
    parts = name.replace("\\", "/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise EvidenceBundleError(f"traversal or empty segment rejected: {name!r}")
    if any(p.startswith("/") for p in parts):
        raise EvidenceBundleError(f"absolute segment rejected: {name!r}")


def authorized_fixture_logs() -> dict[str, bytes]:
    """Only these sample logs may be exported in an Evidence Bundle."""
    from airlock.web.tasks import sample_log

    return {
        "app.log": sample_log(False),
        "app_injected.log": sample_log(True),
    }


def resolve_fixture_name(log_bytes: bytes) -> str:
    for name, data in authorized_fixture_logs().items():
        if data == log_bytes:
            return name
    raise EvidenceBundleError("export refused: input log is not an authorized fixture sample")


def collect_action_receipts_from_result(result: dict[str, Any]) -> list[dict[str, str]]:
    """Ordered action_id + receipt_hash from a live or replay task result."""
    out: list[dict[str, str]] = []
    if "steps" in result:
        for step in result["steps"]:
            rid = step.get("receipt_id")
            aid = (step.get("action") or {}).get("id") or step.get("action_id")
            if rid and aid:
                out.append({"action_id": aid, "receipt_hash": rid})
        return out
    for turn in result.get("turns") or []:
        for step in turn.get("actions") or []:
            rid = step.get("receipt_id")
            aid = (step.get("action") or {}).get("id") or step.get("action_id")
            if rid and aid:
                out.append({"action_id": aid, "receipt_hash": rid})
    return out


def build_evidence_bundle(
    *,
    signer: ReceiptSigner,
    chain_get_text,
    task_result: dict[str, Any],
    input_log: bytes,
    include_bundled_pubkey: bool = True,
) -> bytes:
    """Build a zip Evidence Bundle for an authorized fixture task result.

    ``chain_get_text(receipt_id) -> str | None`` loads receipt JSON by hash.
    """
    fixture = resolve_fixture_name(input_log)
    report = task_result.get("report") or {}
    report_text = report.get("text")
    report_sha = report.get("sha256")
    actions = collect_action_receipts_from_result(task_result)
    if len(actions) > MAX_RECEIPTS:
        raise EvidenceBundleError("too many action receipts for export")

    receipt_files: list[tuple[str, bytes, dict[str, str]]] = []
    enriched: list[dict[str, str]] = []
    for i, a in enumerate(actions, 1):
        text = chain_get_text(a["receipt_hash"])
        if text is None:
            raise EvidenceBundleError(f"missing receipt {a['receipt_hash']}")
        raw = text.encode("utf-8")
        if len(raw) > MAX_SINGLE_FILE:
            raise EvidenceBundleError("receipt too large")
        digest = _member_sha(raw)
        name = f"{RECEIPTS_DIR}{i:04d}_{a['receipt_hash']}.json"
        _check_member_name(name)
        receipt_files.append((name, raw, a))
        enriched.append(
            {
                "action_id": a["action_id"],
                "receipt_hash": a["receipt_hash"],
                "receipt_sha256": digest,
            }
        )

    outcome = task_result.get("outcome")
    steps_ok = True
    if task_result.get("mode") == "replay_compromised":
        steps_ok = bool(task_result.get("steps"))
    elif "turns" in task_result:
        steps_ok = not any(t.get("error") for t in task_result.get("turns") or [])

    unsigned = build_task_verdict(
        task_id=task_result["task_id"],
        task_kind=task_result.get("kind") or "real",
        mode=task_result.get("mode") or "live",
        input_log=input_log,
        report_text=report_text,
        report_sha256_claimed=report_sha,
        action_receipts=enriched,
        outcome=outcome,
        steps_ok=steps_ok,
    )
    verdict = sign_task_verdict(signer, unsigned)
    verdict_bytes = json.dumps(verdict, indent=2, sort_keys=True).encode("utf-8") + b"\n"

    members: list[tuple[str, bytes]] = []
    members.append((INPUT_NAME, input_log))
    if report_text is not None:
        report_bytes = report_text.encode("utf-8")
        if len(report_bytes) > MAX_SINGLE_FILE:
            raise EvidenceBundleError("report too large")
        members.append((REPORT_NAME, report_bytes))
    members.append((VERDICT_NAME, verdict_bytes))
    for name, raw, _ in receipt_files:
        members.append((name, raw))
    if include_bundled_pubkey:
        pub = signer.export_public_key().encode("utf-8")
        members.append((PUBKEY_NAME, pub))

    manifest = {
        "schema_v": BUNDLE_SCHEMA_V,
        "bundle_v": BUNDLE_V,
        "task_id": task_result["task_id"],
        "fixture_log": fixture,
        "trust_note": (
            "signing.pub inside this archive is a convenience copy only. "
            "The auditor must supply the trusted public key out of band; "
            "do not treat the bundled key as a trust anchor. "
            "Verifier code_hash identifies the supported recount implementation; "
            "it does not prove that verifier is trusted."
        ),
        "members": [
            {"path": name, "sha256": _member_sha(data), "size": len(data)} for name, data in members
        ],
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    all_members = [(MANIFEST_NAME, manifest_bytes), *members]

    total = sum(len(d) for _, d in all_members)
    if total > MAX_UNCOMPRESSED:
        raise EvidenceBundleError("bundle uncompressed size exceeds limit")
    if len(all_members) > MAX_MEMBERS:
        raise EvidenceBundleError("too many bundle members")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in all_members:
            _check_member_name(name)
            info = zipfile.ZipInfo(filename=name)
            info.external_attr = 0o644 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _read_zip_safe(blob: bytes) -> dict[str, bytes]:
    """Open an untrusted zip with hard bounds; no filesystem extraction."""
    if len(blob) > MAX_UNCOMPRESSED * 2:
        raise EvidenceBundleError("archive too large on disk")
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob), "r")
    except zipfile.BadZipFile as e:
        raise EvidenceBundleError("not a valid zip archive") from e
    names = zf.namelist()
    if len(names) > MAX_MEMBERS:
        raise EvidenceBundleError("too many zip members")
    if len(set(names)) != len(names):
        raise EvidenceBundleError("duplicate zip member names")
    out: dict[str, bytes] = {}
    total = 0
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        _check_member_name(name)
        # Symlink / absolute tricks via flag bits or external attr.
        if info.external_attr & 0x20000000:  # symlink bit (Unix)
            raise EvidenceBundleError(f"symlink member rejected: {name}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:  # S_IFLNK
            raise EvidenceBundleError(f"symlink member rejected: {name}")
        if info.file_size > MAX_SINGLE_FILE:
            raise EvidenceBundleError(f"member too large: {name}")
        data = zf.read(info)
        if len(data) != info.file_size and info.file_size:
            # Deflated size checked via actual read length.
            pass
        if len(data) > MAX_SINGLE_FILE:
            raise EvidenceBundleError(f"member too large after inflate: {name}")
        total += len(data)
        if total > MAX_UNCOMPRESSED:
            raise EvidenceBundleError("uncompressed size exceeds limit")
        out[name] = data
    return out


def verify_evidence_bundle(
    blob: bytes,
    trusted_pubkey: Ed25519PublicKey,
    *,
    allow_bundled_key_for_display: bool = True,
) -> BundleVerifyResult:
    """Verify an Evidence Bundle offline against an auditor-supplied trusted key.

    Distinguishes cryptographic integrity failures from a valid signed FAILED
    recount. Does not contact the network or an Airlock server.
    """
    del allow_bundled_key_for_display  # reserved; bundled key is never the trust anchor
    try:
        files = _read_zip_safe(blob)
    except EvidenceBundleError as e:
        return BundleVerifyResult(STATUS_BUNDLE, str(e))

    if MANIFEST_NAME not in files:
        return BundleVerifyResult(STATUS_BUNDLE, "missing manifest.json")
    if VERDICT_NAME not in files:
        return BundleVerifyResult(STATUS_BUNDLE, "missing task_verdict.json")
    if INPUT_NAME not in files:
        return BundleVerifyResult(STATUS_BUNDLE, "missing input/app.log")

    try:
        manifest = parse_strict_json(files[MANIFEST_NAME].decode("utf-8"))
    except (ReceiptFormatError, UnicodeDecodeError) as e:
        return BundleVerifyResult(STATUS_SCHEMA, f"manifest: {e}")
    if not isinstance(manifest, dict):
        return BundleVerifyResult(STATUS_SCHEMA, "manifest must be an object")
    if manifest.get("schema_v") != BUNDLE_SCHEMA_V or manifest.get("bundle_v") != BUNDLE_V:
        return BundleVerifyResult(STATUS_BUNDLE, "unsupported bundle version")

    expected_members = manifest.get("members")
    if not isinstance(expected_members, list):
        return BundleVerifyResult(STATUS_SCHEMA, "manifest.members must be a list")

    # Manifest lists every non-manifest file; reject extras / missing / hash drift.
    listed = {}
    for entry in expected_members:
        if not isinstance(entry, dict):
            return BundleVerifyResult(STATUS_SCHEMA, "bad manifest member entry")
        path = entry.get("path")
        sha = entry.get("sha256")
        size = entry.get("size")
        if not isinstance(path, str) or not isinstance(sha, str) or not isinstance(size, int):
            return BundleVerifyResult(STATUS_SCHEMA, "manifest member fields invalid")
        if path in listed:
            return BundleVerifyResult(STATUS_BUNDLE, f"duplicate manifest path {path}")
        listed[path] = (sha, size)

    file_keys = set(files) - {MANIFEST_NAME}
    if set(listed) != file_keys:
        return BundleVerifyResult(
            STATUS_BUNDLE,
            f"manifest members mismatch files: listed={sorted(listed)} files={sorted(file_keys)}",
        )
    for path, (sha, size) in listed.items():
        data = files[path]
        if len(data) != size or _member_sha(data) != sha:
            return BundleVerifyResult(STATUS_HASH, f"member hash/size mismatch: {path}")
        if not HASH_RE.fullmatch(sha):
            return BundleVerifyResult(STATUS_SCHEMA, f"bad sha256 in manifest for {path}")

    # Extra unrecognized top-level entries already caught by set inequality.

    try:
        verdict = verify_task_verdict(files[VERDICT_NAME].decode("utf-8"), trusted_pubkey)
    except ReceiptHashError as e:
        return BundleVerifyResult(STATUS_HASH, str(e))
    except ReceiptSignatureError as e:
        return BundleVerifyResult(STATUS_SIGNATURE, str(e))
    except VerdictFormatError as e:
        return BundleVerifyResult(STATUS_SCHEMA, f"task verdict: {e}")
    except (ReceiptFormatError, UnicodeDecodeError) as e:
        return BundleVerifyResult(STATUS_SCHEMA, f"task verdict: {e}")

    if verdict.get("domain") != VERDICT_DOMAIN:
        return BundleVerifyResult(STATUS_SCHEMA, "task verdict domain mismatch")

    ver = verdict.get("verifier") or {}
    if ver.get("id") != VERIFIER_ID or ver.get("version") != VERIFIER_VERSION:
        return BundleVerifyResult(
            STATUS_UNSUPPORTED_VERIFIER,
            f"unsupported verifier id/version: {ver.get('id')}/{ver.get('version')}",
        )
    if ver.get("code_hash") != verifier_code_hash():
        return BundleVerifyResult(
            STATUS_UNSUPPORTED_VERIFIER,
            "verifier code_hash does not match this airlock.counts.error_warn v1",
        )

    input_log = files[INPUT_NAME]
    if hash_data(input_log) != verdict["input_log_sha256"]:
        return BundleVerifyResult(STATUS_HASH, "input log hash does not match task verdict")

    report_text = None
    if REPORT_NAME in files:
        report_text = files[REPORT_NAME].decode("utf-8")
        if hash_data(files[REPORT_NAME]) != verdict.get("report_sha256"):
            return BundleVerifyResult(STATUS_HASH, "report.md hash does not match task verdict")
        if verdict.get("report_commitment") != f"sha256:{verdict['report_sha256']}":
            return BundleVerifyResult(STATUS_SCHEMA, "report_commitment mismatch")
    else:
        if verdict.get("report_sha256") is not None or verdict.get("report_commitment") != "absent":
            return BundleVerifyResult(STATUS_BUNDLE, "verdict claims report but report.md missing")

    # Independently recompute supported ERROR/WARN rule + fence semantics.
    check = outcome_check(input_log, report_text)
    if check["state"] != verdict["recount_status"]:
        return BundleVerifyResult(
            STATUS_HASH,
            f"recount_status drift: verdict={verdict['recount_status']} recomputed={check['state']}",
        )
    if check["expected"] != verdict["recount_expected"]:
        return BundleVerifyResult(STATUS_HASH, "recount_expected does not match recomputation")
    if check["reported"] != verdict["recount_reported"]:
        return BundleVerifyResult(STATUS_HASH, "recount_reported does not match recomputation")

    # Receipts: order, completeness, signatures, task binding.
    ar = verdict.get("action_receipts")
    if not isinstance(ar, list):
        return BundleVerifyResult(STATUS_SCHEMA, "action_receipts must be a list")
    receipt_files = sorted(
        (n for n in files if n.startswith(RECEIPTS_DIR) and n.endswith(".json")),
    )
    if len(receipt_files) != len(ar):
        return BundleVerifyResult(
            STATUS_BUNDLE,
            f"receipt count mismatch: files={len(receipt_files)} verdict={len(ar)}",
        )

    for i, meta in enumerate(ar):
        if not isinstance(meta, dict):
            return BundleVerifyResult(STATUS_SCHEMA, "bad action_receipts entry")
        seq = meta.get("seq")
        if seq != i + 1:
            return BundleVerifyResult(STATUS_BUNDLE, f"action_receipts seq out of order at {i}")
        expected_name = f"{RECEIPTS_DIR}{seq:04d}_{meta['receipt_hash']}.json"
        if expected_name not in files:
            return BundleVerifyResult(STATUS_BUNDLE, f"missing ordered receipt {expected_name}")
        raw = files[expected_name]
        if meta.get("receipt_sha256") and _member_sha(raw) != meta["receipt_sha256"]:
            return BundleVerifyResult(
                STATUS_HASH, f"receipt bytes digest mismatch: {expected_name}"
            )
        try:
            receipt = load_receipt(raw.decode("utf-8"), trusted_pubkey)
        except ReceiptHashError as e:
            return BundleVerifyResult(STATUS_HASH, f"{expected_name}: {e}")
        except ReceiptSignatureError as e:
            return BundleVerifyResult(STATUS_SIGNATURE, f"{expected_name}: {e}")
        except (ReceiptFormatError, UnicodeDecodeError) as e:
            return BundleVerifyResult(STATUS_SCHEMA, f"{expected_name}: {e}")
        if receipt.hash != meta["receipt_hash"]:
            return BundleVerifyResult(STATUS_HASH, f"{expected_name}: receipt hash field mismatch")
        if receipt.task_id != verdict["task_id"]:
            return BundleVerifyResult(
                STATUS_BUNDLE,
                f"{expected_name}: receipt task_id {receipt.task_id} != verdict {verdict['task_id']}",
            )
        if receipt.action_id != meta["action_id"]:
            return BundleVerifyResult(
                STATUS_BUNDLE,
                f"{expected_name}: action_id mismatch",
            )

    # No leftover receipt files with wrong names.
    if set(receipt_files) != {f"{RECEIPTS_DIR}{m['seq']:04d}_{m['receipt_hash']}.json" for m in ar}:
        return BundleVerifyResult(STATUS_BUNDLE, "unexpected receipt filenames")

    recount = verdict["recount_status"]
    exec_status = verdict["execution_status"]
    details = {
        "recount_status": recount,
        "execution_status": exec_status,
        "task_id": verdict["task_id"],
        "fixture_log": manifest.get("fixture_log"),
        "receipts": len(ar),
    }
    if exec_status != "complete" or recount == "INCONCLUSIVE":
        return BundleVerifyResult(
            STATUS_OK_INCONCLUSIVE,
            "bundle authentic; execution incomplete or recount inconclusive (not a success claim)",
            recount_status=recount,
            task_id=verdict["task_id"],
            details=details,
        )
    if recount == "FAILED":
        return BundleVerifyResult(
            STATUS_OK_FAILED_RECOUNT,
            "bundle authentic; signed recount FAILED "
            "(report counts disagree with independent recount — integrity OK)",
            recount_status=recount,
            task_id=verdict["task_id"],
            details=details,
        )
    if recount == "VERIFIED":
        return BundleVerifyResult(
            STATUS_OK_VERIFIED,
            "bundle authentic; recount VERIFIED on this corpus under airlock.counts.error_warn v1",
            recount_status=recount,
            task_id=verdict["task_id"],
            details=details,
        )
    return BundleVerifyResult(
        STATUS_OK_INCONCLUSIVE,
        f"bundle authentic; recount status {recount}",
        recount_status=recount,
        task_id=verdict["task_id"],
        details=details,
    )


# Avoid circular import noise for type checkers; re-export for tests.
__all__ = [
    "BUNDLE_V",
    "BundleVerifyResult",
    "EvidenceBundleError",
    "STATUS_BUNDLE",
    "STATUS_HASH",
    "STATUS_IO",
    "STATUS_KEY",
    "STATUS_OK_FAILED_RECOUNT",
    "STATUS_OK_INCONCLUSIVE",
    "STATUS_OK_VERIFIED",
    "STATUS_SCHEMA",
    "STATUS_SIGNATURE",
    "STATUS_UNSUPPORTED_VERIFIER",
    "authorized_fixture_logs",
    "build_evidence_bundle",
    "resolve_fixture_name",
    "verify_evidence_bundle",
]
