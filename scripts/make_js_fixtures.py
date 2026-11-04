"""Write tests/vectors/receipt_fixture.json for the JS verifier tests.

Uses a fixed, test-only Ed25519 seed so the output is deterministic. This key
signs nothing outside the test suite.
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from airlock.receipt import ReceiptSigner

OUT = Path(__file__).resolve().parent.parent / "tests" / "vectors" / "receipt_fixture.json"
TEST_SEED = bytes(range(32))


def build() -> dict:
    key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    signer = ReceiptSigner(key)
    data = {
        "task_id": "fixture-task",
        "action_id": "fixture-action",
        "decision": {
            "schema_v": 1,
            "action_id": "fixture-action",
            "verdict": "deny",
            "rules_fired": ["NET_EXFIL"],
            "blast_radius": {
                "score": 80,
                "factors": {"fs_write": "none", "net": "egress", "procs": "1"},
            },
            "caps": {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32},
            "policy_sha256": "0" * 64,
            "reason": "piping a download into a shell: curl ... | sh \u2014 blocked",
        },
        "model": {"provider": "vultr-inference", "id": "fixture"},
    }
    first = signer.sign(data, None)
    first_text = first.model_dump_json(by_alias=True)
    second = signer.sign({**data, "action_id": "fixture-action-2"}, first.hash)
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {
        "pubkey_hex": pub,
        "receipts": [first_text, second.model_dump_json(by_alias=True)],
    }


def main() -> None:
    OUT.write_text(json.dumps(build(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
