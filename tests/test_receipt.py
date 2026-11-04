"""Tests for receipt signing and verification (R35-R39)."""

import tempfile
from pathlib import Path

from airlock.receipt import ReceiptSigner, ReceiptStore, canonical_json
from airlock.schemas import (
    BlastRadius,
    BlastRadiusFactor,
    Cleanup,
    Decision,
    Execution,
    Model,
    Verification,
    VerificationCheck,
)


class TestReceipt:
    """Test receipt checks R35-R39."""

    def test_r35_valid_signature_verifies(self):
        """R35: Valid signature verifies."""
        signer = ReceiptSigner()

        receipt_data = {
            "receipt_v": 1,
            "task_id": "task_01",
            "action_id": "act_01",
            "decision": Decision(
                action_id="act_01",
                verdict="allow",
                blast_radius=BlastRadius(
                    score=10, factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1")
                ),
                caps={"timeout_s": 30},
                policy_sha256="abc123",
            ).model_dump(by_alias=True),
            "execution": Execution(
                container_name="airlock-test123",
                image_digest="sha256:test",
                runtime="runc",
                started="2026-11-03T12:00:00Z",
                ended="2026-11-03T12:00:05Z",
                exit_code=0,
                stdout_sha256="def456",
            ).model_dump(by_alias=True),
            "verification": Verification(
                checks=[VerificationCheck(id="V-TEST", pass_=True)], secret_scan="clean"
            ).model_dump(by_alias=True),
            "cleanup": Cleanup(
                container_absent=True, network_absent=True, evidence="Verified"
            ).model_dump(by_alias=True),
            "model": Model(provider="vultr-inference", id="qwen3.8-27b").model_dump(by_alias=True),
        }

        receipt = signer.sign(receipt_data)

        assert signer.verify(receipt)

    def test_r36_tampered_field_fails(self):
        """R36: Tampered field → fails."""
        signer = ReceiptSigner()

        receipt_data = {
            "receipt_v": 1,
            "task_id": "task_01",
            "action_id": "act_01",
            "decision": Decision(
                action_id="act_01",
                verdict="allow",
                blast_radius=BlastRadius(
                    score=10, factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1")
                ),
                caps={"timeout_s": 30},
                policy_sha256="abc123",
            ).model_dump(by_alias=True),
            "model": Model(provider="vultr-inference", id="qwen3.8-27b").model_dump(by_alias=True),
        }

        receipt = signer.sign(receipt_data)

        tampered_dict = receipt.model_dump(by_alias=True)
        tampered_dict["task_id"] = "tampered_task"

        from airlock.schemas import Receipt

        tampered_receipt = Receipt(**tampered_dict)

        assert not signer.verify(tampered_receipt)

    def test_r37_broken_chain_detected(self):
        """R37: Broken chain detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = ReceiptStore(tmpdir)
            signer = ReceiptSigner()

            receipt1_data = {
                "receipt_v": 1,
                "task_id": "task_01",
                "action_id": "act_01",
                "decision": Decision(
                    action_id="act_01",
                    verdict="allow",
                    blast_radius=BlastRadius(
                        score=10,
                        factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1"),
                    ),
                    caps={"timeout_s": 30},
                    policy_sha256="abc123",
                ).model_dump(by_alias=True),
                "model": Model(provider="vultr-inference", id="qwen3.8-27b").model_dump(
                    by_alias=True
                ),
            }

            receipt1 = signer.sign(receipt1_data, prev_hash=None)
            store.save(receipt1)

            receipt2_data = {
                "receipt_v": 1,
                "task_id": "task_01",
                "action_id": "act_02",
                "decision": Decision(
                    action_id="act_02",
                    verdict="allow",
                    blast_radius=BlastRadius(
                        score=10,
                        factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1"),
                    ),
                    caps={"timeout_s": 30},
                    policy_sha256="abc123",
                ).model_dump(by_alias=True),
                "model": Model(provider="vultr-inference", id="qwen3.8-27b").model_dump(
                    by_alias=True
                ),
            }

            receipt2 = signer.sign(receipt2_data, prev_hash="wrong_hash")
            store.save(receipt2)

            is_valid, errors = store.verify_chain(signer)
            assert not is_valid
            assert len(errors) > 0

    def test_r38_canonicalization_stable(self):
        """R38: Canonicalization is stable."""
        data = {"z": 1, "a": 2, "m": [3, 2, 1]}

        canon1 = canonical_json(data)
        canon2 = canonical_json(data)

        assert canon1 == canon2

        expected = b'{"a":2,"m":[3,2,1],"z":1}'
        assert canon1 == expected

    def test_r39_offline_verify_cli(self):
        """R39: Offline verify CLI works with only public key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)

            signer = ReceiptSigner()
            signer.save_keys(tmpdir_path / "private.pem", tmpdir_path / "public.pem")

            receipt_data = {
                "receipt_v": 1,
                "task_id": "task_01",
                "action_id": "act_01",
                "decision": Decision(
                    action_id="act_01",
                    verdict="allow",
                    blast_radius=BlastRadius(
                        score=10,
                        factors=BlastRadiusFactor(fs_write="tmpfs", net="none", procs="1"),
                    ),
                    caps={"timeout_s": 30},
                    policy_sha256="abc123",
                ).model_dump(by_alias=True),
                "model": Model(provider="vultr-inference", id="qwen3.8-27b").model_dump(
                    by_alias=True
                ),
            }

            receipt = signer.sign(receipt_data)
            receipt_path = tmpdir_path / "receipt.json"
            receipt_path.write_text(receipt.model_dump_json(by_alias=True, indent=2))

            from airlock.cli import EXIT_SUCCESS, verify_receipt

            exit_code = verify_receipt(receipt_path, tmpdir_path / "public.pem")
            assert exit_code == EXIT_SUCCESS

    def test_receipt_exit_codes(self, tmpdir):
        """Test distinct exit codes for different failure modes."""
        from airlock.cli import (
            EXIT_HASH_MISMATCH,
            EXIT_IO_ERROR,
            EXIT_KEY_MISSING_INVALID,
            EXIT_SCHEMA_ERROR,
            EXIT_SIGNATURE_INVALID,
            verify_receipt,
        )

        tmpdir_path = Path(tmpdir)

        signer = ReceiptSigner()
        pubkey_file = tmpdir_path / "public.pem"
        pubkey_file.write_text(signer.export_public_key())

        # Create a valid receipt structure for tests
        receipt_data = {
            "receipt_v": 1,
            "schema_v": 1,
            "task_id": "task_01",
            "action_id": "act_01",
            "decision": Decision(
                action_id="act_01",
                verdict="allow",
                rules_fired=[],
                blast_radius=BlastRadius(
                    score=10,
                    factors=BlastRadiusFactor(fs_write="none", net="none", procs="low"),
                ),
                caps={},
                policy_sha256="abc123",
                reason="Safe",
            ).model_dump(by_alias=True),
        }

        # Test missing receipt file (IO error)
        exit_code = verify_receipt(tmpdir_path / "missing.json", pubkey_file)
        assert exit_code == EXIT_IO_ERROR

        # Test missing key file (with valid receipt structure)
        valid_receipt_for_key_test = signer.sign(receipt_data)
        key_test_file = tmpdir_path / "for_key_test.json"
        key_test_file.write_text(valid_receipt_for_key_test.model_dump_json(by_alias=True))
        exit_code = verify_receipt(key_test_file, tmpdir_path / "missing_key.pem")
        assert exit_code == EXIT_KEY_MISSING_INVALID

        # Test schema error (extra field)
        bad_receipt = tmpdir_path / "bad_schema.json"
        bad_receipt.write_text(
            '{"receipt_v": 1, "schema_v": 1, "task_id": "x", "action_id": "y", "extra_field": "bad", "decision": {}, "hash": "x", "sig_ed25519": "x"}'
        )
        exit_code = verify_receipt(bad_receipt, pubkey_file)
        assert exit_code == EXIT_SCHEMA_ERROR

        # Test hash mismatch
        receipt = signer.sign(receipt_data)
        receipt.hash = "0" * 64  # well-formed but wrong
        tampered_file = tmpdir_path / "tampered.json"
        tampered_file.write_text(receipt.model_dump_json(by_alias=True))
        exit_code = verify_receipt(tampered_file, pubkey_file)
        assert exit_code == EXIT_HASH_MISMATCH

        # Test signature invalid (use different key)
        other_signer = ReceiptSigner()
        receipt = signer.sign(receipt_data)
        wrong_pubkey = tmpdir_path / "wrong_key.pem"
        wrong_pubkey.write_text(other_signer.export_public_key())
        valid_receipt = tmpdir_path / "valid.json"
        valid_receipt.write_text(receipt.model_dump_json(by_alias=True))
        exit_code = verify_receipt(valid_receipt, wrong_pubkey)
        assert exit_code == EXIT_SIGNATURE_INVALID

    def test_chain_head_sign_verify(self, tmpdir):
        """Test chain head signing and verification."""
        from airlock.cli import EXIT_SUCCESS, sign_chain_head, verify_chain

        tmpdir_path = Path(tmpdir)

        signer = ReceiptSigner()

        # Create a chain of 3 receipts
        prev_hash = None
        for i in range(3):
            receipt_data = {
                "receipt_v": 1,
                "schema_v": 1,
                "task_id": f"task_{i}",
                "action_id": f"act_{i}",
                "decision": Decision(
                    action_id=f"act_{i}",
                    verdict="allow",
                    rules_fired=[],
                    blast_radius=BlastRadius(
                        score=10,
                        factors=BlastRadiusFactor(fs_write="none", net="none", procs="low"),
                    ),
                    caps={},
                    policy_sha256="abc123",
                    reason="Safe",
                ).model_dump(by_alias=True),
            }
            receipt = signer.sign(receipt_data, prev_hash)
            prev_hash = receipt.hash

            receipt_file = tmpdir_path / f"receipt_{i}.json"
            receipt_file.write_text(receipt.model_dump_json(by_alias=True, indent=2))

        # Sign chain head
        privkey_file = tmpdir_path / "private.pem"
        privkey_file.write_text(signer.export_private_key())
        head_file = tmpdir_path / "chain_head.json"

        exit_code = sign_chain_head(tmpdir_path, privkey_file, head_file)
        assert exit_code == EXIT_SUCCESS
        assert head_file.exists()

        # Verify chain with head
        pubkey_file = tmpdir_path / "public.pem"
        pubkey_file.write_text(signer.export_public_key())

        exit_code = verify_chain(tmpdir_path, pubkey_file, head_file)
        assert exit_code == EXIT_SUCCESS
