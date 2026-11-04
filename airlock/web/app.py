"""FastAPI application: tasks, arena, receipts, policy and the static UI."""

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from airlock.policy import PolicyEngine
from airlock.receipt import ReceiptFormatError
from airlock.schemas import ActionRequest
from airlock.web import tasks
from airlock.web.chain import ReceiptChain, load_or_create_signer, public_key_hex
from airlock.web.limits import BusyError, Gate, RateLimitedError, RateLimiter, Stats
from airlock.web.pipeline import Pipeline

log = logging.getLogger("airlock.web")
STATIC = Path(__file__).parent / "static"
POLICY_FILES = ["policy.py", "policy_python.py", "policy_shell.py"]

ARENA_CAPS = {"timeout_s": 10, "mem_mb": 128, "cpus": 0.5, "pids": 32}
MAX_BODY = 96 * 1024
MAX_CODE = 8 * 1024
MAX_INPUT = 32 * 1024
MAX_LOG = 32 * 1024


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass
class Settings:
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("AIRLOCK_DATA_DIR", "./airlock-data"))
    )
    arena_per_min: int = field(default_factory=lambda: _env_int("AIRLOCK_ARENA_PER_MIN", 6))
    arena_per_day: int = field(default_factory=lambda: _env_int("AIRLOCK_ARENA_PER_DAY", 100))
    task_per_min: int = field(default_factory=lambda: _env_int("AIRLOCK_TASK_PER_MIN", 2))
    task_per_day: int = field(default_factory=lambda: _env_int("AIRLOCK_TASK_PER_DAY", 20))
    llm_global_per_day: int = field(
        default_factory=lambda: _env_int("AIRLOCK_LLM_GLOBAL_PER_DAY", 400)
    )
    max_concurrent: int = field(default_factory=lambda: _env_int("AIRLOCK_MAX_CONCURRENT", 2))
    max_concurrent_tasks: int = field(
        default_factory=lambda: _env_int("AIRLOCK_MAX_CONCURRENT_TASKS", 2)
    )
    trust_proxy: bool = field(default_factory=lambda: os.environ.get("AIRLOCK_TRUST_PROXY") == "1")


class ArenaCode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["code"] = "code"
    lang: Literal["python", "bash"]
    code: str = Field(min_length=1, max_length=MAX_CODE)
    input_text: str = Field(default="", max_length=MAX_INPUT)


class ArenaInject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["inject"]
    log_text: str = Field(min_length=1, max_length=MAX_LOG)


class TaskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["real", "injected"] = "real"


def _rule_codes() -> list[str]:
    src = "".join((Path(__file__).parent.parent / f).read_text() for f in POLICY_FILES)
    return sorted(set(re.findall(r"R-[A-Z0-9]+(?:-[A-Z0-9]+)*", src)))


def _err(status: int, code: str, detail: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": code, "detail": detail, **extra}, status_code=status)


def create_app(
    settings: Settings | None = None,
    runner_factory=None,
    llm_factory=None,
) -> FastAPI:
    """Build the app. Factories are injectable so tests need neither Docker nor an LLM."""
    s = settings or Settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    signer = load_or_create_signer(s.data_dir / "keys")
    chain = ReceiptChain(s.data_dir / "receipts", signer)
    policy = PolicyEngine()
    if runner_factory is None:
        from airlock.sandbox import SandboxRunner

        runner_factory = SandboxRunner
    custom_llm = llm_factory is not None
    if llm_factory is None:

        def llm_factory():
            from airlock.agent import AgentLoop

            return AgentLoop()  # reads VULTR_INFERENCE_API_KEY from this process only

    gate = Gate(s.max_concurrent)
    task_gate = Gate(s.max_concurrent_tasks)
    pipeline = Pipeline(policy, runner_factory, chain, s.data_dir / "work", gate)
    stats = Stats(s.data_dir / "arena_stats.json")
    limits = {
        "arena_min": RateLimiter(s.arena_per_min, 60),
        "arena_day": RateLimiter(s.arena_per_day, 86400),
        "task_min": RateLimiter(s.task_per_min, 60),
        "task_day": RateLimiter(s.task_per_day, 86400),
        "llm_global": RateLimiter(s.llm_global_per_day, 86400),
    }
    rule_codes = _rule_codes()
    pub_hex = public_key_hex(signer)
    llm_lock = threading.Lock()
    llm_holder: dict[str, Any] = {}

    def get_llm():
        with llm_lock:
            if "llm" not in llm_holder:
                llm_holder["llm"] = llm_factory()
            return llm_holder["llm"]

    app = FastAPI(title="Airlock", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = s
    app.state.chain = chain
    app.state.stats = stats
    app.state.pipeline = pipeline

    @app.middleware("http")
    async def guard(request: Request, call_next):
        length = request.headers.get("content-length")
        if request.method == "POST":
            if length is None or not length.isdigit():
                return _err(411, "length_required", "Content-Length is required")
            if int(length) > MAX_BODY:
                return _err(413, "too_large", f"request body over {MAX_BODY} bytes")
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        return response

    def client_ip(request: Request) -> str:
        peer = request.client.host if request.client else "unknown"
        if s.trust_proxy and peer in ("127.0.0.1", "::1"):
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                return fwd.split(",")[-1].strip()
        return peer

    async def read_json(request: Request) -> Any:
        body = await request.body()
        if len(body) > MAX_BODY:
            raise ValueError("too large")
        return json.loads(body)

    @app.get("/healthz")
    def healthz():
        return {
            "ok": True,
            "receipts": chain.count(),
            "chain_head": chain.head(),
            "runtime_env": os.environ.get("AIRLOCK_RUNTIME", "auto"),
            "llm_configured": bool(os.environ.get("VULTR_INFERENCE_API_KEY")),
        }

    @app.get("/api/pubkey")
    def pubkey():
        return {
            "alg": "Ed25519",
            "public_key_hex": pub_hex,
            "public_key_pem": signer.export_public_key(),
            "fingerprint_sha256": hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest(),
        }

    @app.get("/api/policy")
    def get_policy():
        flags = None
        try:
            probe = ActionRequest(id="policy", task_id="policy", tool="run_code", lang="bash")
            cmd = pipeline.runner._build_docker_create_command(probe, ARENA_CAPS, "airlock-<id>")
            flags = cmd[: cmd.index("python3")] + ["python3", "-c", "<bootstrap>"]
            runtime = pipeline.runner.runtime
        except Exception:
            runtime = None
        return {
            "policy_sha256": policy.policy_hash,
            "policy": policy.policy_data,
            "arena_caps": ARENA_CAPS,
            "task_caps": tasks.TASK_CAPS,
            "runtime": runtime,
            "docker_create": flags,
            "size_limits": {
                "body_bytes": MAX_BODY,
                "code_bytes": MAX_CODE,
                "input_bytes": MAX_INPUT,
                "log_bytes": MAX_LOG,
            },
            "rate_limits": {
                "arena_per_ip_per_min": s.arena_per_min,
                "arena_per_ip_per_day": s.arena_per_day,
                "task_per_ip_per_min": s.task_per_min,
                "task_per_ip_per_day": s.task_per_day,
                "llm_tasks_global_per_day": s.llm_global_per_day,
                "concurrent_sandboxes": s.max_concurrent,
            },
            "rule_codes": rule_codes,
            "verifier_checks": ["V-EXIT-OK", "secret scan of stdout", "container/network removed"],
            "default": "deny: anything the allow-lists do not understand",
        }

    @app.get("/api/samples")
    def samples():
        real = tasks.sample_log(False).decode()
        injected = tasks.sample_log(True).decode().splitlines()
        extra = [line for line in injected if line not in set(real.splitlines())]
        return {"task_prompt": tasks.TASK_PROMPT, "log": real, "injected_line": "\n".join(extra)}

    @app.get("/api/receipt/{receipt_id}")
    def get_receipt(receipt_id: str):
        try:
            text = chain.get_text(receipt_id)
        except (OSError, ReceiptFormatError):
            return _err(500, "corrupt", "stored receipt failed strict parsing")
        if text is None:
            return _err(404, "not_found", "no receipt with that hash")
        return PlainTextResponse(text, media_type="application/json")

    @app.get("/api/arena/stats")
    def arena_stats():
        return stats.snapshot()

    def limited(request: Request, *names: str) -> JSONResponse | None:
        ip = client_ip(request)
        try:
            for n in names:
                limits[n].hit("global" if n == "llm_global" else ip)
        except RateLimitedError as e:
            return JSONResponse(
                {"error": "rate_limited", "detail": str(e)},
                status_code=429,
                headers={"Retry-After": str(e.retry_after)},
            )
        return None

    def agent_run(log_bytes: bytes, kind: str) -> JSONResponse | dict:
        if not custom_llm and not os.environ.get("VULTR_INFERENCE_API_KEY"):
            return _err(503, "llm_unavailable", "inference key not configured")
        try:
            with task_gate.slot():
                llm = get_llm()
                return tasks.run_agent_task(llm, pipeline, log_bytes, kind)
        except BusyError:
            return _err(503, "busy", "too many runs in progress, retry shortly")
        except Exception as e:
            log.exception("agent task failed")
            return _err(502, "llm_error", f"agent loop failed: {type(e).__name__}")

    @app.post("/api/task")
    async def post_task(request: Request):
        try:
            req = TaskRequest.model_validate(await read_json(request))
        except Exception:
            return _err(422, "bad_request", 'body must be {"kind": "real"|"injected"}')
        if r := limited(request, "task_min", "task_day", "llm_global"):
            return r
        t0 = time.monotonic()
        out = await run_in_threadpool(agent_run, tasks.sample_log(req.kind == "injected"), req.kind)
        if isinstance(out, dict):
            out["elapsed_s"] = round(time.monotonic() - t0, 2)
        return out

    @app.post("/api/arena")
    async def post_arena(request: Request):
        if r := limited(request, "arena_min", "arena_day"):
            return r
        try:
            raw = await read_json(request)
            if not isinstance(raw, dict):
                raise ValueError("not an object")
            req = (ArenaInject if raw.get("mode") == "inject" else ArenaCode).model_validate(raw)
        except Exception as e:
            stats.bump("attempts", "rejected")
            detail = str(e).splitlines()[0][:300] if str(e) else "invalid request"
            return _err(422, "bad_request", detail)
        if isinstance(req, ArenaInject) and (
            r := limited(request, "task_min", "task_day", "llm_global")
        ):
            return r
        if isinstance(req, ArenaInject):
            out = await run_in_threadpool(agent_run, req.log_text.encode(), "arena-inject")
            if isinstance(out, dict):
                steps = [a for t in out["turns"] for a in t.get("actions", []) if "verdict" in a]
                blocked = any(a["verdict"] != "allow" for a in steps)
                stats.bump("attempts", "blocked_by_policy" if blocked else "ran_in_sandbox")
            return out

        action = ActionRequest(
            id=f"arena-{uuid.uuid4().hex[:12]}",
            task_id="arena",
            tool="run_code",
            lang=req.lang,
            code=req.code,
            network="none",
            requested=dict(ARENA_CAPS),
        )
        inputs = {"input.txt": req.input_text.encode()} if req.input_text else None
        try:
            step = await run_in_threadpool(pipeline.run_action, action, inputs, None)
        except BusyError:
            return _err(503, "busy", "too many sandboxes running, retry shortly")
        stats.bump(
            "attempts", "blocked_by_policy" if step["verdict"] != "allow" else "ran_in_sandbox"
        )
        step["stats"] = stats.snapshot()
        return step

    if STATIC.is_dir():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/")
        def index():
            return FileResponse(STATIC / "index.html")

    return app


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    host = os.environ.get("AIRLOCK_HOST", "127.0.0.1")
    port = int(os.environ.get("AIRLOCK_PORT", "8080"))
    uvicorn.run(create_app(), host=host, port=port, proxy_headers=False, access_log=True)


if __name__ == "__main__":
    main()
