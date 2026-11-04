"""One execution path for agent tasks and arena submissions.

policy -> (sandbox if allowed) -> verifier -> cleanup check -> signed receipt.
Nothing here reads the inference key; the sandbox gets only the job code and
its input files.
"""

import logging
import shutil
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from airlock.policy import PolicyEngine
from airlock.schemas import ActionRequest, Model
from airlock.verifier import Verifier
from airlock.web.chain import ReceiptChain
from airlock.web.limits import BusyError, Gate

log = logging.getLogger("airlock.web")

STDOUT_PREVIEW = 4096
STDERR_PREVIEW = 2048
ARTIFACT_PREVIEW = 2048


def _preview(data: bytes, limit: int) -> str:
    text = data[:limit].decode("utf-8", errors="replace")
    return text + ("\n…[truncated]" if len(data) > limit else "")


class Pipeline:
    def __init__(
        self,
        policy: PolicyEngine,
        runner_factory: Callable[[], Any],
        chain: ReceiptChain,
        work_root: Path,
        gate: Gate,
        verifier: Verifier | None = None,
    ):
        self.policy = policy
        self._runner_factory = runner_factory
        self._runner = None
        self.chain = chain
        self.work_root = work_root
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.gate = gate
        self.verifier = verifier or Verifier()

    @property
    def runner(self):
        if self._runner is None:
            self._runner = self._runner_factory()
        return self._runner

    def run_action(
        self,
        action: ActionRequest,
        input_files: dict[str, bytes] | None = None,
        model: Model | None = None,
    ) -> dict[str, Any]:
        """Decide, maybe execute, verify and sign one action. Never raises for job errors."""
        decision = self.policy.evaluate(action)
        result: dict[str, Any] = {
            "action": {"id": action.id, "lang": action.lang, "code": action.code},
            "verdict": decision.verdict,
            "rules_fired": decision.rules_fired,
            "reason": decision.reason,
            "caps": decision.caps,
            "status": "blocked",
        }
        receipt_data: dict[str, Any] = {
            "receipt_v": 1,
            "task_id": action.task_id,
            "action_id": action.id,
            "decision": decision.model_dump(by_alias=True),
            "model": model.model_dump(by_alias=True) if model else None,
        }
        if decision.verdict == "allow" and action.tool != "run_code":
            result["status"] = "not_executed"
        elif decision.verdict == "allow":
            work = self.work_root / uuid.uuid4().hex
            try:
                with self.gate.slot():
                    execution = self.runner.run(action, decision.caps, work, input_files)
                out_dir = work / "output"
                stdout = (out_dir / "stdout.txt").read_bytes()
                stderr_path = out_dir / "stderr.txt"
                stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
                verification = self.verifier.verify(
                    execution, decision.caps, stdout.decode("utf-8", errors="replace")
                )
                cleanup = self.verifier.verify_cleanup(execution.container_name)
                artifacts = []
                for a in execution.artifacts:
                    p = out_dir / "out" / a.name
                    data = p.read_bytes() if p.is_file() else b""
                    artifacts.append(
                        {
                            "name": a.name,
                            "sha256": a.sha256,
                            "size": len(data),
                            "preview": _preview(data, ARTIFACT_PREVIEW),
                        }
                    )
                receipt_data.update(
                    execution=execution.model_dump(by_alias=True),
                    verification=verification.model_dump(by_alias=True),
                    cleanup=cleanup.model_dump(by_alias=True),
                )
                result.update(
                    status="executed",
                    execution={
                        "runtime": execution.runtime,
                        "exit_code": execution.exit_code,
                        "killed_by": execution.killed_by,
                        "report_invalid": execution.report_invalid,
                        "stdout": _preview(stdout, STDOUT_PREVIEW),
                        "stderr": _preview(stderr, STDERR_PREVIEW),
                        "artifacts": artifacts,
                        "artifacts_dropped": [d.model_dump() for d in execution.artifacts_dropped],
                        "notes": execution.notes,
                    },
                    verification=verification.model_dump(by_alias=True),
                    cleanup=cleanup.model_dump(by_alias=True),
                )
            except BusyError:
                raise
            except Exception as e:  # fail closed: no output is returned
                log.exception("sandbox run failed for %s", action.id)
                result.update(status="error", error=type(e).__name__)
            finally:
                shutil.rmtree(work, ignore_errors=True)
        receipt = self.chain.append(receipt_data)
        result["receipt_id"] = receipt.hash
        result["receipt"] = receipt.model_dump(by_alias=True)
        return result
