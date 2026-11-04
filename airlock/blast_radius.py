"""Blast radius estimation."""

import re
from typing import Any

from airlock.schemas import ActionRequest, BlastRadius, BlastRadiusFactor


class BlastRadiusEstimator:
    """Estimates the potential blast radius of an action."""

    def __init__(self, policy: dict[str, Any]):
        """Initialize estimator with policy."""
        self.policy = policy

    def estimate(self, action: ActionRequest) -> BlastRadius:
        """Estimate blast radius and return score with factors."""
        score = 0
        factors = {}

        if action.tool == "read_artifact":
            factors["fs_write"] = "none"
            factors["net"] = "none"
            factors["procs"] = "1"
            factors["duration"] = "instant"
            return BlastRadius(score=5, factors=BlastRadiusFactor(**factors))

        factors["fs_write"] = "tmpfs"
        score += 5

        if action.network == "allowlist":
            factors["net"] = "allowlist"
            score += 15
        else:
            factors["net"] = "none"
            score += 0

        timeout = action.requested.get("timeout_s", 30)
        if timeout > 60:
            factors["duration"] = f"{timeout}s-long"
            score += 20
        else:
            factors["duration"] = f"{timeout}s"
            score += 5

        pids_limit = action.requested.get("pids", 32)
        factors["procs"] = f"<={pids_limit}"
        if pids_limit > 32:
            score += 15
        else:
            score += 5

        if action.code:
            code_factors = self._analyze_code_complexity(action.code, action.lang or "shell")
            score += code_factors["score"]

        return BlastRadius(score=min(score, 100), factors=BlastRadiusFactor(**factors))

    def _analyze_code_complexity(self, code: str, lang: str) -> dict[str, Any]:
        """Analyze code complexity for blast radius."""
        result = {"score": 0, "reasons": []}

        if "base64" in code.lower():
            result["score"] += 30
            result["reasons"].append("base64 encoding detected")

        if lang == "python" and ("eval(" in code or "exec(" in code):
            result["score"] += 40
            result["reasons"].append("dynamic execution")

        dangerous_patterns = [
            r"rm\s+-rf",
            r"dd\s+if=",
            r"mkfs",
            r":(){ :|:& };:",
            r"while\s+true",
            r"while\s+:",
            r"fork\(",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                result["score"] += 20
                result["reasons"].append(f"dangerous pattern: {pattern}")
                break

        if len(code) > 1000:
            result["score"] += 10
            result["reasons"].append("large code block")

        return result
