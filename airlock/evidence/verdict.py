"""Signed Task Verdict — domain-separated from ActionReceipts.

A Task Verdict binds input-log hash, report-hash, the supported counts verifier
identity, recount status/counts, ordered action-receipt hashes, and task
identity. It is signed with the same Ed25519 key facility as receipts, but the
``domain`` field and schema keep it from being confused with an ActionReceipt.
An ActionReceipt signature does **not** sign this verdict.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from airlock.evidence.counts_v1 import outcome_check, verifier_identity
from airlock.receipt import (
    HASH_RE,
    SIG_RE,
    ReceiptFormatError,
    ReceiptHashError,
    ReceiptSignatureError,
    ReceiptSigner,
    canonical_json,
    hash_data,
    parse_strict_json,
)

VERDICT_DOMAIN = "airlock.task_verdict.v1"
VERDICT_SCHEMA_V = 1
VERDICT_V = 1
SIGNED_OUT = frozenset({"hash", "sig_ed25519"})


class VerdictFormatError(ReceiptFormatError):
    """Task Verdict document is not strictly well-formed."""


def _execution_status(
    *,
    mode: str,
    outcome: dict[str, Any] | None,
    report_text: str | None,
    steps_or_turns_ok: bool,
) -> str:
    """Honest completion label — never upgrade failure into success."""
    if mode == "replay_compromised":
        # Replay always finishes its scripted steps; report may still be absent.
        return "complete" if steps_or_turns_ok else "failed"
    if not outcome:
        return "incomplete"
    state = outcome.get("state")
    if state in ("completed", "all_blocked", "no_actions"):
        return "complete"
    if state == "failed":
        return "failed"
    return "incomplete"


def build_task_verdict(
    *,
    task_id: str,
    task_kind: str,
    mode: str,
    input_log: bytes,
    report_text: str | None,
    report_sha256_claimed: str | None,
    action_receipts: list[dict[str, str]],
    outcome: dict[str, Any] | None = None,
    steps_ok: bool = True,
) -> dict[str, Any]:
    """Build an unsigned Task Verdict payload (no hash/sig yet)."""
    input_hash = hash_data(input_log)
    if report_text is None:
        report_hash = None
        report_commitment = "absent"
    else:
        report_bytes = report_text.encode("utf-8")
        report_hash = hash_data(report_bytes)
        report_commitment = f"sha256:{report_hash}"
        if report_sha256_claimed and report_sha256_claimed != report_hash:
            # Bind real bytes only — refuse to claim a mismatched artifact digest.
            raise VerdictFormatError(
                "report_sha256 does not match the report bytes being committed"
            )

    check = outcome_check(input_log, report_text)
    exec_status = _execution_status(
        mode=mode,
        outcome=outcome,
        report_text=report_text,
        steps_or_turns_ok=steps_ok,
    )
    # Never present missing evidence as VERIFIED at the task layer.
    recount_status = check["state"]
    if exec_status != "complete" and recount_status == "VERIFIED" and report_text is None:
        recount_status = "INCONCLUSIVE"

    ordered = []
    seen_hashes: set[str] = set()
    for i, item in enumerate(action_receipts, 1):
        action_id = item["action_id"]
        receipt_hash = item["receipt_hash"]
        if not HASH_RE.fullmatch(receipt_hash):
            raise VerdictFormatError(f"receipt_hash[{i}] must be 64 lowercase hex")
        if receipt_hash in seen_hashes:
            raise VerdictFormatError(f"duplicate receipt_hash {receipt_hash}")
        seen_hashes.add(receipt_hash)
        entry = {
            "seq": i,
            "action_id": action_id,
            "receipt_hash": receipt_hash,
        }
        if "receipt_sha256" in item:
            # Digest of the exact receipt document bytes (file content).
            if not HASH_RE.fullmatch(item["receipt_sha256"]):
                raise VerdictFormatError(f"receipt_sha256[{i}] must be 64 lowercase hex")
            entry["receipt_sha256"] = item["receipt_sha256"]
        ordered.append(entry)

    return {
        "schema_v": VERDICT_SCHEMA_V,
        "verdict_v": VERDICT_V,
        "domain": VERDICT_DOMAIN,
        "task_id": task_id,
        "task_kind": task_kind,
        "mode": mode,
        "input_log_sha256": input_hash,
        "report_sha256": report_hash,
        "report_commitment": report_commitment,
        "verifier": verifier_identity(),
        "recount_status": recount_status,
        "recount_expected": dict(check["expected"]),
        "recount_reported": dict(check["reported"]),
        "recount_detail": dict(check["detail"]),
        "execution_status": exec_status,
        "task_outcome_state": (outcome or {}).get("state"),
        "action_receipts": ordered,
        "notes": (
            "Task Verdict is separate from ActionReceipts. A valid ActionReceipt "
            "signature does not sign this verdict. Bundled signing.pub is convenience "
            "only — the auditor's out-of-band trusted key is the trust anchor. "
            "Verifier id/version/code_hash identify the supported recount rule; they "
            "do not by themselves prove that verifier is trusted."
        ),
    }


def signed_verdict_payload(verdict: dict[str, Any]) -> bytes:
    return canonical_json({k: v for k, v in verdict.items() if k not in SIGNED_OUT})


def sign_task_verdict(signer: ReceiptSigner, payload: dict[str, Any]) -> dict[str, Any]:
    """Sign a Task Verdict with the existing Ed25519 signing key (unchanged key handling)."""
    data = {k: v for k, v in payload.items() if k not in SIGNED_OUT}
    if data.get("domain") != VERDICT_DOMAIN:
        raise VerdictFormatError("missing or wrong domain separation field")
    if data.get("schema_v") != VERDICT_SCHEMA_V or data.get("verdict_v") != VERDICT_V:
        raise VerdictFormatError("unsupported task verdict version")
    canonical = signed_verdict_payload(data)
    digest = hash_data(canonical)
    sig = signer.private_key.sign(canonical).hex()
    out = dict(data)
    out["hash"] = digest
    out["sig_ed25519"] = sig
    return out


def parse_task_verdict_unchecked(text: str) -> dict[str, Any]:
    """Strict-parse a Task Verdict without checking crypto."""
    raw = parse_strict_json(text)
    if not isinstance(raw, dict):
        raise VerdictFormatError("task verdict must be a JSON object")
    required = {
        "schema_v",
        "verdict_v",
        "domain",
        "task_id",
        "task_kind",
        "mode",
        "input_log_sha256",
        "report_commitment",
        "verifier",
        "recount_status",
        "recount_expected",
        "recount_reported",
        "recount_detail",
        "execution_status",
        "action_receipts",
        "hash",
        "sig_ed25519",
    }
    missing = required - set(raw)
    if missing:
        raise VerdictFormatError(f"missing fields: {sorted(missing)}")
    if raw.get("domain") != VERDICT_DOMAIN:
        raise VerdictFormatError("wrong domain")
    if raw.get("schema_v") != VERDICT_SCHEMA_V or raw.get("verdict_v") != VERDICT_V:
        raise VerdictFormatError("unsupported task verdict version")
    if not HASH_RE.fullmatch(raw["hash"]):
        raise VerdictFormatError("hash must be 64 lowercase hex")
    if not SIG_RE.fullmatch(raw["sig_ed25519"]):
        raise VerdictFormatError("sig_ed25519 must be 128 lowercase hex")
    if not HASH_RE.fullmatch(raw["input_log_sha256"]):
        raise VerdictFormatError("input_log_sha256 must be 64 lowercase hex")
    if raw.get("report_sha256") is not None and not HASH_RE.fullmatch(raw["report_sha256"]):
        raise VerdictFormatError("report_sha256 must be null or 64 lowercase hex")
    return raw


def verify_task_verdict(text: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Parse and verify hash + Ed25519 signature of a Task Verdict."""
    verdict = parse_task_verdict_unchecked(text)
    canonical = signed_verdict_payload(verdict)
    if hash_data(canonical) != verdict["hash"]:
        raise ReceiptHashError("task verdict hash does not match the signed payload")
    try:
        public_key.verify(bytes.fromhex(verdict["sig_ed25519"]), canonical)
    except Exception as e:
        raise ReceiptSignatureError("task verdict signature does not verify") from e
    return verdict
