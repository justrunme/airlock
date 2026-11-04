"""Receipt signing and verification."""

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from airlock.schemas import Receipt

MAX_SAFE_INT = 2**53
HASH_RE = re.compile(r"[0-9a-f]{64}")
SIG_RE = re.compile(r"[0-9a-f]{128}")
SIGNED_OUT = frozenset({"hash", "sig_ed25519"})


class ReceiptFormatError(ValueError):
    """The receipt bytes are not a strictly valid receipt document."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptFormatError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ReceiptFormatError(f"non-finite number {name}")


def _check_ints(value: Any, where: str = "$") -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
        raise ReceiptFormatError(f"integer out of range at {where}")
    if isinstance(value, dict):
        for k, v in value.items():
            _check_ints(v, f"{where}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check_ints(v, f"{where}[{i}]")


def parse_strict_json(text: str) -> Any:
    """Parse JSON rejecting duplicate keys, NaN/Infinity and unsafe integers."""
    try:
        data = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except ReceiptFormatError:
        raise
    except ValueError as e:
        raise ReceiptFormatError(f"invalid JSON: {e}") from e
    _check_ints(data)
    return data


def signed_payload(receipt_dict: dict[str, Any]) -> bytes:
    """Canonical bytes covered by the hash and signature."""
    return canonical_json({k: v for k, v in receipt_dict.items() if k not in SIGNED_OUT})


def load_receipt(text: str) -> Receipt:
    """Load a receipt from JSON text, accepting exactly one encoding of each value.

    The document must have no duplicate keys, every schema field present with
    its exact JSON type (no "0" or 0.0 for an integer), integers within
    +/-2**53, lowercase hex for hash and signature, and its canonical form
    must equal the canonical form of the validated model, so the bytes that
    are verified are the bytes that were signed.
    """
    raw = parse_strict_json(text)
    if not isinstance(raw, dict):
        raise ReceiptFormatError("receipt must be a JSON object")
    try:
        receipt = Receipt.model_validate(raw, strict=True)
    except ValidationError as e:
        raise ReceiptFormatError(f"schema: {e}") from e
    if not HASH_RE.fullmatch(receipt.hash):
        raise ReceiptFormatError("hash must be 64 lowercase hex characters")
    if not SIG_RE.fullmatch(receipt.sig_ed25519):
        raise ReceiptFormatError("sig_ed25519 must be 128 lowercase hex characters")
    if receipt.prev_hash is not None and not HASH_RE.fullmatch(receipt.prev_hash):
        raise ReceiptFormatError("prev_hash must be null or 64 lowercase hex characters")
    if signed_payload(raw) != signed_payload(receipt.model_dump(by_alias=True)):
        raise ReceiptFormatError("document is not the canonical encoding of the receipt")
    return receipt


def load_chain_head(text: str) -> dict[str, str]:
    """Load a chain-head document: exactly head_hash and sig_ed25519, lowercase hex."""
    raw = parse_strict_json(text)
    if not isinstance(raw, dict) or set(raw) != {"head_hash", "sig_ed25519"}:
        raise ReceiptFormatError("chain head must have exactly head_hash and sig_ed25519")
    if not isinstance(raw["head_hash"], str) or not HASH_RE.fullmatch(raw["head_hash"]):
        raise ReceiptFormatError("head_hash must be 64 lowercase hex characters")
    if not isinstance(raw["sig_ed25519"], str) or not SIG_RE.fullmatch(raw["sig_ed25519"]):
        raise ReceiptFormatError("sig_ed25519 must be 128 lowercase hex characters")
    return raw


def canonical_json(data: dict[str, Any]) -> bytes:
    """Produce RFC 8785 JCS canonical JSON."""
    return jcs.canonicalize(data)


def hash_data(data: bytes) -> str:
    """Hash data with SHA-256."""
    return sha256(data).hexdigest()


class ReceiptSigner:
    """Signs and verifies receipts."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        """Initialize signer with private key."""
        self.private_key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def sign(self, receipt_data: dict[str, Any], prev_hash: str | None = None) -> Receipt:
        """Sign a receipt."""
        receipt_data["prev_hash"] = prev_hash
        _check_ints(receipt_data)

        # Create receipt object first to get proper serialization
        temp_receipt = Receipt(**{**receipt_data, "hash": "", "sig_ed25519": ""})
        receipt_dict = temp_receipt.model_dump(by_alias=True)

        _check_ints(receipt_dict)
        canonical = signed_payload(receipt_dict)
        receipt_hash = hash_data(canonical)

        signature = self.private_key.sign(canonical)

        receipt_data["hash"] = receipt_hash
        receipt_data["sig_ed25519"] = signature.hex()

        return Receipt(**receipt_data)

    def verify(self, receipt: Receipt, public_key: Ed25519PublicKey | None = None) -> bool:
        """Verify receipt signature."""
        if public_key is None:
            public_key = self.public_key

        receipt_dict = receipt.model_dump(by_alias=True)
        try:
            _check_ints(receipt_dict)
        except ReceiptFormatError:
            return False
        if not HASH_RE.fullmatch(receipt.hash) or not SIG_RE.fullmatch(receipt.sig_ed25519):
            return False
        canonical = signed_payload(receipt_dict)

        computed_hash = hash_data(canonical)
        if computed_hash != receipt.hash:
            return False

        try:
            signature = bytes.fromhex(receipt.sig_ed25519)
            public_key.verify(signature, canonical)
            return True
        except Exception:
            return False

    @classmethod
    def load_private_key(cls, path: Path | str) -> Ed25519PrivateKey:
        """Load private key from file."""
        key_path = Path(path)
        key_data = key_path.read_bytes()
        return serialization.load_pem_private_key(key_data, password=None)

    @classmethod
    def load_public_key(cls, path: Path | str) -> Ed25519PublicKey:
        """Load public key from file."""
        key_path = Path(path)
        key_data = key_path.read_bytes()
        return serialization.load_pem_public_key(key_data)

    def export_private_key(self) -> str:
        """Export private key as PEM string."""
        priv_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return priv_pem.decode("utf-8")

    def export_public_key(self) -> str:
        """Export public key as PEM string."""
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pub_pem.decode("utf-8")

    def save_keys(self, private_path: Path | str, public_path: Path | str) -> None:
        """Save keys to files."""
        Path(private_path).write_text(self.export_private_key())
        Path(public_path).write_text(self.export_public_key())


class ReceiptStore:
    """Stores receipts."""

    def __init__(self, store_dir: Path | str):
        """Initialize store."""
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def save(self, receipt: Receipt) -> None:
        """Save receipt to store."""
        filename = f"{receipt.task_id}_{receipt.action_id}.json"
        path = self.store_dir / filename
        path.write_text(receipt.model_dump_json(by_alias=True, indent=2))

    def load(self, task_id: str, action_id: str) -> Receipt:
        """Load receipt from store."""
        filename = f"{task_id}_{action_id}.json"
        path = self.store_dir / filename
        return Receipt.model_validate_json(path.read_text())

    def get_last_hash(self) -> str | None:
        """Get hash of most recent receipt."""
        receipts = sorted(self.store_dir.glob("*.json"))
        if not receipts:
            return None

        last_receipt = Receipt.model_validate_json(receipts[-1].read_text())
        return last_receipt.hash

    def verify_chain(self, signer: ReceiptSigner) -> tuple[bool, list[str]]:
        """Verify the entire receipt chain."""
        receipts = sorted(self.store_dir.glob("*.json"))
        if not receipts:
            return True, []

        errors = []
        prev_hash = None

        for receipt_path in receipts:
            receipt = Receipt.model_validate_json(receipt_path.read_text())

            if not signer.verify(receipt):
                errors.append(f"{receipt_path.name}: Invalid signature")

            if receipt.prev_hash != prev_hash:
                errors.append(
                    f"{receipt_path.name}: Chain broken (expected {prev_hash}, got {receipt.prev_hash})"
                )

            prev_hash = receipt.hash

        return len(errors) == 0, errors
