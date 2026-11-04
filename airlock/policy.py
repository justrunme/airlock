"""Policy engine for action authorization."""

import hashlib
from pathlib import Path
from typing import Any

import yaml

from airlock import policy_python, policy_shell
from airlock.schemas import ActionRequest, BlastRadius, Decision


class PolicyEngine:
    """Policy engine that evaluates actions against rules."""

    FORBIDDEN_BINARIES = policy_shell.FORBIDDEN_BINARIES
    SAFE_SHELL_BINARIES = policy_shell.SAFE_BINARIES
    DANGEROUS_PYTHON_MODULES = policy_python.DANGEROUS_MODULES
    SAFE_PYTHON_MODULES = policy_python.SAFE_MODULES

    def __init__(self, policy_path: Path | str | None = None):
        """Initialize policy engine."""
        self.policy_path = Path(policy_path) if policy_path else None
        self.policy_data = self._load_policy()
        self.policy_hash = self._compute_policy_hash()

    def _load_policy(self) -> dict[str, Any]:
        """Load policy from YAML file."""
        if not self.policy_path or not self.policy_path.exists():
            return self._default_policy()

        with open(self.policy_path) as f:
            return yaml.safe_load(f)

    def _default_policy(self) -> dict[str, Any]:
        """Default policy configuration."""
        return {
            "max_timeout_s": 300,
            "max_mem_mb": 512,
            "max_cpus": 1.0,
            "max_pids": 64,
            "network_allowlist": [],
            "allow_unknown_tools": False,
            "allowed_languages": ["python", "bash", "sh"],
            "blast_radius_thresholds": {"allow": 30, "approval": 70},
        }

    def _compute_policy_hash(self) -> str:
        """Compute SHA-256 hash of policy."""
        policy_str = yaml.dump(self.policy_data, sort_keys=True)
        return hashlib.sha256(policy_str.encode()).hexdigest()

    def evaluate(self, action: ActionRequest) -> Decision:
        """Evaluate an action and return a decision."""
        rules_fired = []
        verdict = "deny"  # Default deny (fail closed)
        reason = "Default deny"
        code_checks = {"forbidden": [], "suspicious": [], "rules": []}

        # Check tool
        if action.tool not in {"run_code", "read_artifact"}:
            rules_fired.append("R-TOOL-001")
            reason = "Unknown tool"
            blast = BlastRadius(
                score=100,
                factors={
                    "fs_write": "unknown",
                    "net": "unknown",
                    "procs": "unknown",
                    "duration": "unknown",
                },
            )
            return Decision(
                action_id=action.id,
                verdict=verdict,
                rules_fired=rules_fired,
                blast_radius=blast,
                caps={},
                policy_sha256=self.policy_hash,
                reason=reason,
            )

        # read_artifact is safe
        if action.tool == "read_artifact":
            verdict = "allow"
            reason = "read_artifact safe"
            blast = self._estimate_blast_radius(action)
            caps = self._apply_caps(action.requested)
            return Decision(
                action_id=action.id,
                verdict=verdict,
                rules_fired=rules_fired,
                blast_radius=blast,
                caps=caps,
                policy_sha256=self.policy_hash,
                reason=reason,
            )

        # Check language
        lang = action.lang or "bash"
        if lang in ("shell", "sh"):
            lang = "bash"
        allowed_langs = self.policy_data.get("allowed_languages", [])
        if lang not in allowed_langs:
            rules_fired.append("R-LANG-001")
            reason = "Language not allowlisted"
            blast = self._estimate_blast_radius(action)
            caps = self._apply_caps(action.requested)
            return Decision(
                action_id=action.id,
                verdict="deny",
                rules_fired=rules_fired,
                blast_radius=blast,
                caps=caps,
                policy_sha256=self.policy_hash,
                reason=reason,
            )

        # Analyze code
        if action.code:
            analyze_lang = action.lang or "bash"
            if analyze_lang in ("shell", "sh"):
                analyze_lang = "bash"
            code_checks = self._analyze_code(action.code, analyze_lang)
            if code_checks["forbidden"]:
                rules_fired.extend(code_checks["rules"])
                verdict = "deny"
                reason = code_checks["forbidden"][0]
            elif code_checks["suspicious"]:
                rules_fired.extend(code_checks["rules"])
                verdict = "require_approval"
                reason = code_checks["suspicious"][0]
            elif code_checks["safe"]:
                verdict = "allow"
                reason = "Safe pattern"
            else:
                verdict = "require_approval"
                reason = "Pattern not recognized"

        blast = self._estimate_blast_radius(action)

        # High blast radius escalates
        if (
            blast.score >= self.policy_data["blast_radius_thresholds"]["approval"]
            and verdict == "allow"
        ):
            verdict = "require_approval"
            reason = "High blast radius"
            rules_fired.append("R-BLAST-001")

        caps = self._apply_caps(action.requested)

        return Decision(
            action_id=action.id,
            verdict=verdict,
            rules_fired=rules_fired,
            blast_radius=blast,
            caps=caps,
            policy_sha256=self.policy_hash,
            reason=reason,
        )

    def _analyze_code(self, code: str, lang: str) -> dict[str, Any]:
        """Analyze code for dangerous patterns."""
        return self._analyze_python(code) if lang == "python" else self._analyze_shell(code)

    # Language checks live in policy_python / policy_shell.

    def _analyze_python(self, code: str) -> dict[str, Any]:
        return policy_python.analyze(code)

    def _analyze_shell(self, code: str) -> dict[str, Any]:
        return policy_shell.analyze(code)

    def _estimate_blast_radius(self, action: ActionRequest) -> BlastRadius:
        """Estimate blast radius of an action."""
        from airlock.blast_radius import BlastRadiusEstimator

        estimator = BlastRadiusEstimator(self.policy_data)
        return estimator.estimate(action)

    def _apply_caps(self, requested: dict[str, Any]) -> dict[str, Any]:
        """Apply resource caps."""
        caps = {}
        caps["timeout_s"] = min(requested.get("timeout_s", 30), self.policy_data["max_timeout_s"])
        caps["mem_mb"] = min(requested.get("mem_mb", 256), self.policy_data["max_mem_mb"])
        caps["cpus"] = min(requested.get("cpus", 0.5), self.policy_data["max_cpus"])
        caps["pids"] = min(requested.get("pids", 64), self.policy_data["max_pids"])
        return caps

    def can_classifier_override(self, current_verdict: str, classifier_result: str) -> bool:
        """Check if classifier can override current verdict."""
        if current_verdict == "deny":
            return False
        return classifier_result in {"require_approval", "deny"}
