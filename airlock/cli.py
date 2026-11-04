"""Command-line interface for Airlock.

Exit codes of verify, verify-chain and chain-head:
  0  success
  10 signature invalid (receipt or chain head)
  11 receipt hash does not match its canonical content
  12 schema error: not strict JSON, duplicate keys, wrong types, missing or
     extra fields, non-canonical hex, integers beyond +/-2**53, malformed head
  13 chain link broken: no genesis, or the signed head is not the chain's end
  14 chain gap, fork or duplicate receipt
  15 public or private key missing or invalid
  16 I/O error: receipt, directory or head file missing or unreadable
"""

import argparse
import json
import sys
from pathlib import Path

from airlock.receipt import (
    ReceiptFormatError,
    ReceiptSigner,
    canonical_json,
    hash_data,
    load_chain_head,
    parse_receipt_unchecked,
    signed_payload,
)
from airlock.schemas import Receipt

# Exit codes
EXIT_SUCCESS = 0
EXIT_SIGNATURE_INVALID = 10
EXIT_HASH_MISMATCH = 11
EXIT_SCHEMA_ERROR = 12
EXIT_CHAIN_LINK_BROKEN = 13
EXIT_CHAIN_GAP_FORK_DUP = 14
EXIT_KEY_MISSING_INVALID = 15
EXIT_IO_ERROR = 16


def _load_public_key(pubkey_path: Path):
    try:
        return ReceiptSigner.load_public_key(pubkey_path)
    except FileNotFoundError:
        print(f"✗ Public key file not found: {pubkey_path}")
    except Exception as e:
        print(f"✗ Error loading public key: {e}")
    return None


def _read_receipt(path: Path) -> tuple[int, Receipt | None]:
    """Read and strictly parse one receipt file: (exit code, receipt).

    The crypto is checked by _check_receipt so each failure gets its exit code.
    """
    try:
        text = path.read_text()
    except FileNotFoundError:
        print(f"✗ Receipt file not found: {path}")
        return EXIT_IO_ERROR, None
    except Exception as e:
        print(f"✗ Error reading receipt {path}: {e}")
        return EXIT_IO_ERROR, None
    try:
        return EXIT_SUCCESS, parse_receipt_unchecked(text)
    except ReceiptFormatError as e:
        print(f"✗ Receipt {path.name} rejected: {e}")
        return EXIT_SCHEMA_ERROR, None


def _check_receipt(receipt: Receipt, public_key, label: str) -> int:
    """Check hash and signature of a strictly parsed receipt."""
    canonical = signed_payload(receipt.model_dump(by_alias=True))
    if hash_data(canonical) != receipt.hash:
        print(f"✗ Receipt {label} hash mismatch")
        return EXIT_HASH_MISMATCH
    try:
        public_key.verify(bytes.fromhex(receipt.sig_ed25519), canonical)
    except Exception:
        print(f"✗ Receipt {label} signature verification failed")
        return EXIT_SIGNATURE_INVALID
    return EXIT_SUCCESS


def verify_receipt(receipt_path: Path, pubkey_path: Path) -> int:
    """Verify one receipt. Returns an exit code (see module docstring)."""
    rc, receipt = _read_receipt(receipt_path)
    if receipt is None:
        return rc
    public_key = _load_public_key(pubkey_path)
    if public_key is None:
        return EXIT_KEY_MISSING_INVALID
    rc = _check_receipt(receipt, public_key, receipt_path.name)
    if rc == EXIT_SUCCESS:
        print(f"✓ Receipt {receipt_path.name} is valid")
        print(f"  Task: {receipt.task_id}")
        print(f"  Action: {receipt.action_id}")
        print(f"  Verdict: {receipt.decision.verdict}")
        print(f"  Hash: {receipt.hash}")
    return rc


def verify_chain(chain_dir: Path, pubkey_path: Path, chain_head_path: Path | None = None) -> int:
    """Verify a directory of receipts as one linear chain. Returns an exit code.

    Without --chain-head, dropping receipts from the end of the chain cannot be
    detected; use a signed chain head for that.
    """
    public_key = _load_public_key(pubkey_path)
    if public_key is None:
        return EXIT_KEY_MISSING_INVALID
    if not chain_dir.is_dir():
        print(f"✗ Not a directory: {chain_dir}")
        return EXIT_IO_ERROR

    head_doc = None
    if chain_head_path is not None:
        try:
            head_text = chain_head_path.read_text()
        except Exception as e:
            print(f"✗ Cannot read chain head {chain_head_path}: {e}")
            return EXIT_IO_ERROR
        try:
            head_doc = load_chain_head(head_text)
        except ReceiptFormatError as e:
            print(f"✗ Chain head rejected: {e}")
            return EXIT_SCHEMA_ERROR

    excluded = chain_head_path.resolve() if chain_head_path is not None else None
    receipt_files = [f for f in sorted(chain_dir.glob("*.json")) if f.resolve() != excluded]
    if not receipt_files:
        print(f"✗ No receipts found in {chain_dir}")
        return EXIT_IO_ERROR

    receipts: list[tuple[Path, Receipt]] = []
    for path in receipt_files:
        rc, receipt = _read_receipt(path)
        if receipt is None:
            return rc
        receipts.append((path, receipt))

    # Every receipt must be authentic before its links are trusted.
    for path, receipt in receipts:
        rc = _check_receipt(receipt, public_key, path.name)
        if rc != EXIT_SUCCESS:
            return rc

    hashes = [r.hash for _, r in receipts]
    if len(set(hashes)) != len(hashes):
        print("✗ Duplicate receipt in chain")
        return EXIT_CHAIN_GAP_FORK_DUP
    geneses = [(p, r) for p, r in receipts if r.prev_hash is None]
    if not geneses:
        print("✗ No genesis receipt found (prev_hash=null)")
        return EXIT_CHAIN_LINK_BROKEN
    if len(geneses) > 1:
        print("✗ Multiple genesis receipts found (chain fork)")
        return EXIT_CHAIN_GAP_FORK_DUP
    children: dict[str, list[tuple[Path, Receipt]]] = {}
    for path, receipt in receipts:
        if receipt.prev_hash is not None:
            children.setdefault(receipt.prev_hash, []).append((path, receipt))

    chain = [geneses[0]]
    while True:
        nxt = children.get(chain[-1][1].hash, [])
        if len(nxt) > 1:
            print(f"✗ Chain fork detected after {chain[-1][0].name}")
            return EXIT_CHAIN_GAP_FORK_DUP
        if not nxt:
            break
        chain.append(nxt[0])
    if len(chain) != len(receipts):
        linked = {id(r) for _, r in chain}
        orphans = [p.name for p, r in receipts if id(r) not in linked]
        print(f"✗ Chain incomplete: {len(chain)}/{len(receipts)} receipts linked")
        print(f"  Orphaned receipts: {', '.join(orphans)}")
        return EXIT_CHAIN_GAP_FORK_DUP

    for i, (_, receipt) in enumerate(chain):
        print(f"  ✓ Receipt {i + 1}: {receipt.task_id}/{receipt.action_id}")

    if head_doc is not None:
        expected = chain[-1][1].hash
        try:
            public_key.verify(
                bytes.fromhex(head_doc["sig_ed25519"]),
                canonical_json({"head_hash": head_doc["head_hash"]}),
            )
        except Exception:
            print("✗ Chain head signature verification failed")
            return EXIT_SIGNATURE_INVALID
        if head_doc["head_hash"] != expected:
            print(f"✗ Chain head mismatch: chain ends at {expected[:16]}...")
            return EXIT_CHAIN_LINK_BROKEN
        print(f"\n✓ Chain head verified: {expected[:16]}...")

    print(f"\n✓ Chain verified: all {len(chain)} receipts valid and linked")
    return EXIT_SUCCESS


def sign_chain_head(chain_dir: Path, privkey_path: Path, output_path: Path) -> int:
    """Sign the head of a receipt chain."""
    try:
        private_key = ReceiptSigner.load_private_key(privkey_path)
        signer = ReceiptSigner(private_key)

        # Find the last receipt in chain (exclude chain_head.json if present)
        out = output_path.resolve()
        receipt_files = [
            f
            for f in sorted(chain_dir.glob("*.json"))
            if f.name != "chain_head.json" and f.resolve() != out
        ]
        if not receipt_files:
            print(f"✗ No receipts found in {chain_dir}")
            return EXIT_IO_ERROR

        # Find the receipt with no successors
        receipts = []
        for path in receipt_files:
            rc, receipt = _read_receipt(path)
            if receipt is None:
                return rc
            receipts.append(receipt)

        # Find head (no other receipt has this as prev_hash)
        all_prev_hashes = {r.prev_hash for r in receipts if r.prev_hash}
        head_candidates = [r for r in receipts if r.hash not in all_prev_hashes]

        if len(head_candidates) > 1:
            print("✗ Multiple chain heads found (chain fork)")
            return EXIT_CHAIN_GAP_FORK_DUP
        elif len(head_candidates) == 0:
            print("✗ No chain head found (circular chain?)")
            return EXIT_CHAIN_LINK_BROKEN

        head = head_candidates[0]

        head_data = {"head_hash": head.hash}
        head_canonical = canonical_json(head_data)
        signature = signer.private_key.sign(head_canonical)

        chain_head = {
            "head_hash": head.hash,
            "sig_ed25519": signature.hex(),
        }

        output_path.write_text(json.dumps(chain_head, indent=2))
        print(f"✓ Chain head signed: {head.hash[:16]}...")
        print(f"  Output: {output_path}")
        return EXIT_SUCCESS

    except FileNotFoundError as e:
        print(f"✗ File not found: {e}")
        return EXIT_IO_ERROR
    except Exception as e:
        print(f"✗ Error: {e}")
        return EXIT_IO_ERROR


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Airlock verification tools",
        epilog="""
Exit codes:
  0  - Success
  10 - Signature invalid
  11 - Hash mismatch
  12 - Schema/unknown field error
  13 - Chain link broken
  14 - Chain gap/fork/duplicate
  15 - Missing/invalid key
  16 - I/O error
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")

    verify_parser = subparsers.add_parser("verify", help="Verify a receipt")
    verify_parser.add_argument("receipt", type=Path, help="Receipt JSON file")
    verify_parser.add_argument("--pubkey", type=Path, required=True, help="Public key file")

    chain_parser = subparsers.add_parser("verify-chain", help="Verify a chain of receipts")
    chain_parser.add_argument("directory", type=Path, help="Directory containing receipts")
    chain_parser.add_argument("--pubkey", type=Path, required=True, help="Public key file")
    chain_parser.add_argument(
        "--chain-head", type=Path, help="Optional chain head file to verify against"
    )

    head_sign_parser = subparsers.add_parser("chain-head", help="Sign a chain head")
    head_sign_subparsers = head_sign_parser.add_subparsers(dest="head_command")

    sign_parser = head_sign_subparsers.add_parser("sign", help="Sign chain head")
    sign_parser.add_argument("directory", type=Path, help="Directory containing receipts")
    sign_parser.add_argument("--privkey", type=Path, required=True, help="Private key file")
    sign_parser.add_argument(
        "--output", type=Path, required=True, help="Output file for chain head"
    )

    verify_head_parser = head_sign_subparsers.add_parser("verify", help="Verify chain head")
    verify_head_parser.add_argument("directory", type=Path, help="Directory containing receipts")
    verify_head_parser.add_argument("--pubkey", type=Path, required=True, help="Public key file")
    verify_head_parser.add_argument(
        "--chain-head", type=Path, required=True, help="Chain head file"
    )

    args = parser.parse_args()

    if args.command == "verify":
        exit_code = verify_receipt(args.receipt, args.pubkey)
        sys.exit(exit_code)
    elif args.command == "verify-chain":
        exit_code = verify_chain(
            args.directory, args.pubkey, args.chain_head if hasattr(args, "chain_head") else None
        )
        sys.exit(exit_code)
    elif args.command == "chain-head":
        if args.head_command == "sign":
            exit_code = sign_chain_head(args.directory, args.privkey, args.output)
            sys.exit(exit_code)
        elif args.head_command == "verify":
            exit_code = verify_chain(args.directory, args.pubkey, args.chain_head)
            sys.exit(exit_code)
        else:
            head_sign_parser.print_help()
            sys.exit(EXIT_IO_ERROR)
    else:
        parser.print_help()
        sys.exit(EXIT_IO_ERROR)


if __name__ == "__main__":
    main()
