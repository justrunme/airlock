"""Data schemas for Airlock."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ActionRequest(BaseModel):
    """Request to execute an action."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    schema_version: int = Field(default=1, alias="schema_v")
    id: str
    task_id: str
    tool: str
    lang: str | None = None
    code: str | None = None
    files_in: list[str] = Field(default_factory=list)
    network: Literal["none", "allowlist"] = "none"
    requested: dict[str, Any] = Field(default_factory=dict)


class BlastRadiusFactor(BaseModel):
    """Factors contributing to blast radius score."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    fs_write: str
    net: str
    procs: str
    duration: str | None = None


class BlastRadius(BaseModel):
    """Blast radius assessment."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    score: int = Field(ge=0, le=100)
    factors: BlastRadiusFactor


class Decision(BaseModel):
    """Policy decision for an action."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    schema_version: int = Field(default=1, alias="schema_v")
    action_id: str
    verdict: Literal["allow", "deny", "require_approval"]
    rules_fired: list[str] = Field(default_factory=list)
    blast_radius: BlastRadius
    caps: dict[str, Any]
    policy_sha256: str
    reason: str | None = None


class Artifact(BaseModel):
    """Execution artifact."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str
    sha256: str


class DroppedArtifact(BaseModel):
    """A file in /work/out that was not returned, and why."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    path: str
    size: int
    reason: str


class Execution(BaseModel):
    """Execution record."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    container_name: str
    image_digest: str
    runtime: Literal["runsc", "runc"]
    started: str
    ended: str
    exit_code: int
    killed_by: str | None = None
    peak_mem_mb: int | None = None
    stdout_sha256: str
    stderr_sha256: str | None = None
    artifacts: list[Artifact] = Field(default_factory=list)
    # True when the bootstrap's report was missing, malformed, had the wrong
    # nonce, or the container did not end normally. stdout, stderr and
    # artifacts are then empty and exit_code comes from docker inspect.
    report_invalid: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    artifacts_dropped: list[DroppedArtifact] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class VerificationCheck(BaseModel):
    """Individual verification check result."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    id: str
    pass_: bool = Field(alias="pass")
    detail: str | None = None


class Verification(BaseModel):
    """Post-execution verification."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    checks: list[VerificationCheck]
    secret_scan: Literal["clean", "flagged"]
    flagged_patterns: list[str] = Field(default_factory=list)


class Cleanup(BaseModel):
    """Cleanup verification."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    container_absent: bool
    network_absent: bool
    evidence: str


class Model(BaseModel):
    """Model information."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    provider: str
    id: str


class Receipt(BaseModel):
    """Signed execution receipt."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    schema_version: int = Field(default=1, alias="schema_v")
    receipt_v: int = 1
    task_id: str
    action_id: str
    decision: Decision
    execution: Execution | None = None
    verification: Verification | None = None
    cleanup: Cleanup | None = None
    model: Model | None = None
    prev_hash: str | None = None
    hash: str
    sig_ed25519: str

    @classmethod
    def compute_hash(cls, data: dict[str, Any]) -> str:
        """Compute canonical hash of receipt data."""
        from airlock.receipt import canonical_json, hash_data

        canonical = canonical_json(data)
        return hash_data(canonical)
