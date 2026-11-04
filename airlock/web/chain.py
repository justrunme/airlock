"""Append-only receipt chain on disk.

Each receipt is one file, ``<seq>_<hash>.json``, holding the signed receipt as
JSON. ``prev_hash`` links every receipt to the one before it, so the directory
can be checked offline with ``airlock verify-chain``.
"""

import fcntl
import os
import re
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airlock.receipt import ReceiptSigner, load_receipt
from airlock.schemas import Receipt

RECEIPT_ID_RE = re.compile(r"[0-9a-f]{64}")
_NAME_RE = re.compile(r"(\d{8})_([0-9a-f]{64})\.json")


def load_or_create_signer(key_dir: Path) -> ReceiptSigner:
    """Load the Ed25519 signing key, creating it (mode 600) on first start."""
    key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    priv = key_dir / "signing.key"
    pub = key_dir / "signing.pub"
    if priv.exists():
        signer = ReceiptSigner(ReceiptSigner.load_private_key(priv))
    else:
        signer = ReceiptSigner(Ed25519PrivateKey.generate())
        fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(signer.export_private_key())
    if not pub.exists() or pub.read_text() != signer.export_public_key():
        pub.write_text(signer.export_public_key())
    return signer


def public_key_hex(signer: ReceiptSigner) -> str:
    return signer.public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


class ReceiptChain:
    """Signs receipts and appends them to a linear hash chain on disk."""

    def __init__(self, directory: Path, signer: ReceiptSigner):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self._lock = threading.Lock()
        self._lock_file = self.dir / ".lock"

    @contextmanager
    def _locked(self):
        # Thread lock for this process, flock for other processes on the host.
        with self._lock, open(self._lock_file, "a") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def _entries(self) -> list[tuple[int, str, Path]]:
        out = []
        for p in self.dir.iterdir():
            m = _NAME_RE.fullmatch(p.name)
            if m:
                out.append((int(m.group(1)), m.group(2), p))
        return sorted(out)

    def append(self, receipt_data: dict[str, Any]) -> Receipt:
        """Sign ``receipt_data`` linked to the current head and store it."""
        with self._locked():
            entries = self._entries()
            seq = entries[-1][0] + 1 if entries else 1
            prev = entries[-1][1] if entries else None
            receipt = self.signer.sign(dict(receipt_data), prev_hash=prev)
            path = self.dir / f"{seq:08d}_{receipt.hash}.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(receipt.model_dump_json(by_alias=True, indent=2))
            os.replace(tmp, path)
            return receipt

    def get_text(self, receipt_id: str) -> str | None:
        """Return the stored JSON of a receipt by its hash, or None."""
        if not RECEIPT_ID_RE.fullmatch(receipt_id):
            return None
        matches = list(self.dir.glob(f"*_{receipt_id}.json"))
        if len(matches) != 1:
            return None
        text = matches[0].read_text()
        load_receipt(text)  # never serve a file that is not a strict receipt
        return text

    def count(self) -> int:
        return len(self._entries())

    def head(self) -> str | None:
        entries = self._entries()
        return entries[-1][1] if entries else None
