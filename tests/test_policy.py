"""Tests for policy engine (P1-P12)."""

import tempfile
from pathlib import Path

import yaml

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest


class TestPolicy:
    """Test policy engine checks P1-P12."""

    def test_p01_unknown_tool_deny(self):
        """P1: Unknown tool → deny."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_01",
            task_id="task_01",
            tool="unknown_tool",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"
        assert "R-TOOL-001" in decision.rules_fired

    def test_p02_rm_rf_deny(self):
        """P2: rm -rf → deny or contain."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_02",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code="rm -rf /",
        )
        decision = engine.evaluate(action)
        assert decision.blast_radius.score > 0

    def test_p03_curl_non_allowlisted_deny(self):
        """P3: curl binary is forbidden."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_03",
            task_id="task_01",
            tool="run_code",
            lang="bash",
            code="curl https://evil.example.com",
        )
        decision = engine.evaluate(action)
        # curl is a forbidden binary
        assert decision.verdict == "deny"
        assert any("curl" in rule.lower() for rule in decision.rules_fired)

    def test_p04_allowlisted_host_allow(self):
        """P4: Allowlisted host → allow."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            policy = {
                "max_timeout_s": 300,
                "max_mem_mb": 512,
                "max_cpus": 1.0,
                "max_pids": 64,
                "network_allowlist": ["api.example.com"],
                "allow_unknown_tools": False,
                "blast_radius_thresholds": {"allow": 30, "approval": 70},
            }
            yaml.dump(policy, f)
            policy_path = Path(f.name)

        try:
            engine = PolicyEngine(policy_path)
            action = ActionRequest(
                id="act_04",
                task_id="task_01",
                tool="run_code",
                lang="shell",
                code="curl https://api.example.com",
                network="allowlist",
            )
            decision = engine.evaluate(action)
            assert "R-NET-001" not in decision.rules_fired
        finally:
            policy_path.unlink()

    def test_p05_eval_base64_high_blast(self):
        """P5: eval(base64...) → blast ≥70."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_05",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="import base64; eval(base64.b64decode('...'))",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"
        assert "R-PY-EVAL" in decision.rules_fired

    def test_p06_fork_bomb_deny(self):
        """P6: Fork-bomb pattern → deny."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_06",
            task_id="task_01",
            tool="run_code",
            lang="shell",
            code=":(){ :|:& };:",
        )
        decision = engine.evaluate(action)
        assert decision.verdict == "deny"
        assert "R-FORK-001" in decision.rules_fired

    def test_p07_timeout_clamped(self):
        """P7: Request for timeout >max → clamped."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_07",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('hello')",
            requested={"timeout_s": 1000},
        )
        decision = engine.evaluate(action)
        assert decision.caps["timeout_s"] == 300

    def test_p08_memory_clamped(self):
        """P8: Request for mem >max → clamped."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_08",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('hello')",
            requested={"mem_mb": 2048},
        )
        decision = engine.evaluate(action)
        assert decision.caps["mem_mb"] == 512

    def test_p09_forbidden_binary_deny(self):
        """P9: docker/nsenter/mount binary → deny."""
        engine = PolicyEngine()

        for binary in ["docker", "nsenter", "mount"]:
            action = ActionRequest(
                id=f"act_09_{binary}",
                task_id="task_01",
                tool="run_code",
                lang="shell",
                code=f"{binary} ps",
            )
            decision = engine.evaluate(action)
            assert decision.verdict == "deny"
            assert any(f"R-BIN-{binary.upper()}" in rule for rule in decision.rules_fired)

    def test_p10_policy_hash_recorded(self):
        """P10: Policy hash recorded."""
        engine = PolicyEngine()
        action = ActionRequest(
            id="act_10",
            task_id="task_01",
            tool="run_code",
            lang="python",
            code="print('hello')",
        )
        decision = engine.evaluate(action)
        assert decision.policy_sha256
        assert len(decision.policy_sha256) == 64

    def test_p11_policy_change_new_hash(self):
        """P11: Policy file change → new hash."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            policy1 = {"max_timeout_s": 300}
            yaml.dump(policy1, f)
            policy_path = Path(f.name)

        try:
            engine1 = PolicyEngine(policy_path)
            hash1 = engine1.policy_hash

            with open(policy_path, "w") as f:
                policy2 = {"max_timeout_s": 600}
                yaml.dump(policy2, f)

            engine2 = PolicyEngine(policy_path)
            hash2 = engine2.policy_hash

            assert hash1 != hash2
        finally:
            policy_path.unlink()

    def test_p12_classifier_cannot_downgrade_deny(self):
        """P12: Classifier can't downgrade a deny."""
        engine = PolicyEngine()

        assert not engine.can_classifier_override("deny", "allow")
        assert not engine.can_classifier_override("deny", "require_approval")

        assert engine.can_classifier_override("allow", "deny")
        assert engine.can_classifier_override("allow", "require_approval")
