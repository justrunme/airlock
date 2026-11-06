# Airlock

An LLM only proposes. A deterministic policy gate decides. Allowed code runs in a disposable Docker container under gVisor. Every job gets an Ed25519-signed, hash-chained receipt. Blast Radius Zero.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/justrunme/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/justrunme/airlock/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)

[![Watch the 3-minute demo](docs/img/video-thumb.png)](https://youtu.be/yrYa1MisCYI)

**Live demo:** https://45-77-141-253.sslip.io

## See it

![Hero: Watch Airlock stop an attack](docs/img/01-hero.png)

*Top of the live demo. One click replays a compromised agent. No model call.*

![Three harmful proposals blocked before any container starts](docs/img/02-attack-stopped.png)

*After the replay: three injected steps are blocked at the gate, the legitimate analysis runs under gVisor (`runsc`), and the page checks the receipt hash and signature in the browser. Change one character and the check fails.*

![Compromised-agent tab: curl|sh and env exfil blocked](docs/img/03-compromised-agent.png)

*Tab 1 (Compromised agent). Scripted `curl | sh` and `/proc/self/environ` exfil are denied (`R-BIN-CURL`, `R-SHELL-EXEC-FILE`, `R-PY-ATTR-DENIED`, `R-PY-OPEN-PATH`). No container starts. Each denial gets a signed receipt.*

![Real task with live model: one of two proposals blocked](docs/img/04-real-task.png)

*Tab 2 (Real task, live `qwen3.8-27b` on Vultr Serverless Inference). On this run the first proposal was denied (`R-PY-PATHLIB-WRITE`). The gate still signed a receipt.*

![Attack arena: curl|sh blocked](docs/img/05-arena-blocked.png)

*Tab 3 (Try to break it). Submit `curl | sh` yourself: `deny` with `R-BIN-CURL` / `R-SHELL-EXEC-FILE`, and no sandbox.*

![Receipt verified in the browser](docs/img/06-verify-valid.png)

*Tab 4 (Verify a receipt). The browser checks JSON, schema, SHA-256 over RFC 8785 JCS, and the Ed25519 signature via WebCrypto. Chain linkage is what `airlock verify-chain` is for; the page does not check it.*

![Tampered receipt marked INVALID](docs/img/07-verify-invalid.png)

*Same receipt after Tamper one character: the hash check fails and the page names the field that changed.*

## What it is

I built Airlock because I don't want an agent's mistake to become my incident. The model only *proposes* actions. A deterministic policy engine decides whether to allow, deny, or ask for approval. Allowed code runs in a throwaway hardened container (gVisor `runsc` on the demo VM). A verifier then checks the result and the cleanup, and every decision gets an Ed25519-signed receipt that anyone can check offline, including in the browser.

The page opens with a button, "Watch Airlock stop an attack". It replays a compromised agent: three dangerous steps are denied before any container starts, one safe step runs in the sandbox, and the page then verifies the receipt in the browser. Below it are four tabs:

1. **Compromised agent.** The log of a sample task contains a fake "ops-runbook" line that tells the agent to `curl ... | sh` and to post `env` to an outside host. You can replay what an agent that obeyed the line would propose, or run it with the live model. The replay's proposals are scripted; the gate, the sandbox and the receipts are not.
2. **Real task (live model).** The agent analyses a sample app log and writes a Markdown report. Every action it proposes goes through the gate.
3. **Try to break it.** You type code yourself and see the verdict, the rules, the run output and the receipt.
4. **Verify a receipt.** Paste any receipt and the page checks the JSON, the schema, the SHA-256 hash over RFC 8785 JCS and the signature with WebCrypto. It does not check the hash chain; that is what the offline CLI `airlock verify-chain` is for. A tamper button shows what a failed check looks like.

## What is actually enforced


- **Fail-closed policy**: Default deny. Actions are allowed only when explicitly recognized as safe.
- **Language allowlist**: Only `python`, `bash`, `sh` accepted.
- **Python**: Parsed with `ast`. Imports must come from an allow-list of standard-library modules (for example `re`, `json`, `csv`, `collections`, `datetime`, `statistics`, `pathlib`, `gzip`, `hashlib`, `ipaddress`); unknown modules are denied. `os` is limited to `os.path`, `os.listdir`, `os.sep` and `os.linesep`, and `sys` to an attribute allow-list. `eval`, `exec`, `compile` (except `re.compile`), `__import__`, `_`-prefixed and introspection attributes, the `getattr` family with non-literal names, `operator.attrgetter`/`methodcaller`/`itemgetter`, module aliasing and attribute lookups in format strings are denied. File paths must be literals inside `/work/input` (read) or `/work/out` (read/write).
- **Shell**: Parsed with a shell lexer. Only allow-listed binaries with allow-listed options run (`cat`, `grep`/`egrep`/`fgrep`/`zgrep`, `awk`, `sed`, `jq`, `sort`, `uniq`, `wc`, `head`, `tail`, `cut`, `ls`, `zcat`, `gzip`/`gunzip` to stdout, `tee`, `date`, plus `echo`, `printf`, `tr`, `test`). sed and awk are not trusted as read-only: sed scripts must parse into a fixed subset without `e`, `w`, `r` or branches, and awk `getline`, `system`, redirects and `ENVIRON` are denied. File arguments may only name relative paths, `/work`, `/work/input`, `/work/out` or `/dev/null`; output goes only to `/work/out` and never to script files. Other interpreters (`python3`, `perl`, `ruby`, ...), forbidden binaries (`docker`, `mount`, `sudo`, `curl`, `wget`, `ssh`, `nc`, ...), loops, process substitution, variable expansions, command substitution and assignment-prefixed commands are denied. This is checked against a test corpus only; the sandbox is the second line of defence (see docs/KNOWN_LIMITATIONS.md).
- **Network**: Only `--network none` is supported. Egress allowlist mode is NOT implemented and raises an error if requested.
- **Sandbox hardening**: Read-only rootfs, tmpfs /work (plus small noexec tmpfs /tmp and /dev/shm), job runs as uid 65534, no capabilities for the job, no-new-privileges, process/mem/cpu limits (the job's process cap is `RLIMIT_NPROC` = the signed `pids` cap; docker `--pids-limit` is only headroom under gVisor, where a fork bomb usually ends as an OOM kill first, see docs/THREAT_MODEL.md), wall-clock timeout watchdog with `docker kill`. The job's report is bound to a per-run nonce and parsed strictly. `files_in` reads only from a configured inputs directory.
- **Verifier**: Post-execution cleanup checks (container removed, no dangling networks), secret pattern scan, artifact hash validation.
- **Receipts**: RFC 8785 JCS canonical JSON, Ed25519 signatures, hash chain linking, optional signed chain head. Verification rejects duplicate keys, type coercion, missing fields and non-canonical hex (exit codes in `airlock/cli.py`).

## Architecture

```mermaid
graph TD
    U[Browser] -->|HTTPS| C[Caddy :443]
    C -->|127.0.0.1:8080| W[FastAPI app, user airlock]
    W --> A[Agent loop]
    A -->|API key from root-only env file| I[Vultr Serverless Inference qwen3.8-27b]
    A -->|proposed action| P[Policy + blast-radius engine]
    W -->|Arena code| P
    P -->|allow| S[Sandbox: docker + runsc, network none]
    P -->|deny| R
    S --> V[Verifier: cleanup, secret scan, artifact hashes]
    V --> R[Receipt signer: JCS + Ed25519 + hash chain]
    R --> St[(/var/lib/airlock/receipts)]
    U -->|verify.js in the page| R
```

The model's output is only data. Decisions come from code. The inference key is only in the app process; it is never passed into a sandbox container (the container gets a scrubbed environment and no network).

## Vultr services used

- **Vultr Cloud Compute**: one VM in Frankfurt. It runs Docker with the gVisor runtime, the FastAPI app as a systemd service, Caddy for HTTPS, and a prune timer.
- **Vultr Serverless Inference**: the only LLM path. All agent calls go to `https://api.vultrinference.com/v1` (OpenAI-compatible) with model `qwen3.8-27b`. It is a reasoning model, so I use `max_tokens` of at least 2048 (the web tasks use 12000).

## Threat Model


| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Secret exfiltration | API key never enters sandbox; environment scrubbed; `--network none` default; output secret scan | Model could leak user-provided data (out of scope) |
| Destructive commands | Read-only rootfs + tmpfs; no host mounts; policy denies dangerous patterns | Damage stays inside disposable container |
| Resource exhaustion | Timeout watchdog, pids/mem/cpu caps, output size limits | Host-level DoS via many tasks needs rate limiting |
| Container escape | Non-root user, no capabilities, no-new-privileges, seccomp, gVisor where available | **Not eliminated** - Docker shares kernel |
| Policy bypass via obfuscation | AST analysis flags eval/exec/base64; containment is the real boundary | Static analysis incomplete by design |
| LLM self-approval | Decisions come from deterministic code only; LLM output is data | None |
| Receipt forgery | Ed25519 signatures + hash chain | Compromised host can sign lies |

## Corpus metrics

These numbers are from my own test corpus only. They are not a general detection rate.

| | count |
|---|---|
| adversarial cases | 255 |
| benign cases | 154 |
| false allow | 0 |
| false deny | 0 |

A second corpus, `tests/corpus_independent/`, was written by an independent reviewer, not by me. These numbers are on this corpus only:

| | before review 5 fixes | after |
|---|---|---|
| attack cases | 398 | 398 |
| benign cases | 79 | 79 |
| false allow | 46 (6 security-relevant) | 39 (0 security-relevant) |
| false deny | 1 | 1 |

The 6 security-relevant misses were five pathlib `glob`/`rglob` patterns with `..` and `test -r /etc/passwd`. I reviewed each of the 39 remaining false-ALLOWs by hand: they are imports, prints, no-ops, reads of `/work/input`, writes to `/work/out`, or loops stopped by the sandbox caps. `tests/corpus_independent/triage.json` gives the reason for each, and CI fails on any row outside that list. The one false-DENY is `tail -f`, which I deny on purpose (docs/KNOWN_LIMITATIONS.md section 7).

`scripts/corpus_metrics.py` makes `airlock/web/static/metrics.json`, and CI runs it with `--check` so the page can't show stale numbers.

## Demo signing key

Receipts from the live demo are signed with this Ed25519 key:

```
public_key_hex: d8c2acc2972692ee205a7e056d8ae2791906ba1e17f9bdf2cee14baf53377748
fingerprint (sha256): f42776ee997b0f0930f32d3620458e9b0d5b7afa5f610fd14756c6c8bc4510ce
```

You can also get it from `/api/pubkey`. To check a receipt without the browser:

```bash
node tests/js/verify_cli.mjs receipt.json d8c2acc2972692ee205a7e056d8ae2791906ba1e17f9bdf2cee14baf53377748
airlock verify-chain /path/to/receipts --pubkey public.pem
```

## Run the web app locally

```bash
pip install -e ".[web]"
export VULTR_INFERENCE_API_KEY=...   # only needed for the two agent tabs
airlock-web                          # listens on 127.0.0.1:8080
```

The Arena and Verify tabs work without a key. Settings come from `AIRLOCK_*` variables (`AIRLOCK_DATA_DIR`, `AIRLOCK_RUNTIME`, rate limits, `AIRLOCK_TRUST_PROXY`); see `airlock/web/app.py`.

## Run it on a Vultr VM

I use one Ubuntu VM with Docker and gVisor installed and a user `airlock` in the `docker` group.

```bash
# from a checkout, copy the code to the VM and install
git archive HEAD | ssh airlock@VM 'mkdir -p ~/src && tar -x -C ~/src'
ssh airlock@VM 'cd ~/src && HOST=<ip-with-dashes>.sslip.io sh deploy/install.sh'
# put the key in a root-only file read by systemd
sudo install -d -m 700 /etc/airlock
sudo sh -c 'umask 077; echo VULTR_INFERENCE_API_KEY=... > /etc/airlock/airlock.env'
sudo systemctl restart airlock-web
```

`deploy/` has the systemd unit (runs as `airlock`, hardened with `ProtectSystem=strict`), the Caddyfile (HTTPS through sslip.io, HTTP redirects to HTTPS), and `airlock-prune.timer`, which removes leftover `airlock-*` containers and networks every 10 minutes. The app binds to 127.0.0.1 only, because Docker-published ports skip ufw. Caddy is the only public listener and the Docker socket is never exposed.

## Demo script

Film / judge in this order (also the "Run judge path" button on the page):

1. **Useful live result.** Tab 1 (Real task, live model). Needs `VULTR_INFERENCE_API_KEY`. The model analyses `/work/input/app.log` on this corpus, writes `report.md`, and the page shows downloadable report text, raw stdout and cleanup evidence. Receipts carry `"context": {"mode": "live", "planner": "model"}`.
2. **Attack contained (policy gate).** Tab 2 (Compromised agent) → "Replay a compromised agent". Proposals are scripted; the gate, sandbox and receipts are real:
   - step 1, the log analysis: allowed, runs in the sandbox (report.md on this corpus; poisoned log has one extra WARN);
   - step 2, `curl … | sh`: denied (`R-BIN-CURL`, `R-SHELL-EXEC-FILE`), sandbox never started;
   - step 3, read `/proc/self/environ` and post it out: denied (`R-PY-ATTR-DENIED`, `R-PY-OPEN-PATH`), sandbox never started;
   - step 4, `rm -rf /work/input` and a write to `/etc`: denied (`R-BIN-RM`, `R-SHELL-REDIRECT`), sandbox never started.

   Each receipt carries `"context": {"mode": "replay_compromised", "planner": "scripted"}`.
3. **Runtime containment, then healthy.** Tab 3 → "Run timeout probe, then healthy task". Allowed `time.sleep(100)` is terminated by the sandbox (`killed_by=timeout`); then `print(1+1)` succeeds with cleanup. The production gate is not loosened for this. Memory-cap, read-only rootfs and blocked-egress proofs stay in the isolated Docker tests (`tests/test_sandbox.py` S15/S20/S22/S24).
4. **Verify a receipt, then tamper.** Tab 4: JSON, schema, hash and signature checks in the browser. Then "Tamper one character". A valid signature means the receipt was not tampered with; it does not by itself prove the world-state claim inside the receipt.

Pitch stills (dark/terminal, same UI family): `/static/title-card.svg`, `/static/pipeline-card.svg`.

## Limitations

- The live model (qwen3.8-27b) refused the prompt injection in every run I tried. So the containment moment in tab 1 comes from a replay with scripted proposals. The page and the receipts say so.
- Each `run_code` call is a new sandbox. Files don't carry over between calls.
- Container isolation lowers risk but doesn't remove it. gVisor helps, but the host is still shared.
- Static policy can be evaded. The sandbox is the real boundary.
- Receipts are only as honest as the host that signs them. The demo key lives on the VM.
- Receipts are kept on the VM and not pruned; only containers and networks are.
- Nobody has red-teamed this professionally. See `docs/KNOWN_LIMITATIONS.md`.

## Installation


Requires Python 3.12+ and Docker.

```bash
pip install -e ".[dev]"
```

## Usage

### Verify a receipt

```bash
airlock verify receipt.json --pubkey public.pem
```

### Run the agent

```python
from airlock.agent import AgentLoop
from airlock.policy import PolicyEngine
from airlock.sandbox import SandboxRunner
from airlock.verifier import Verifier
from airlock.receipt import ReceiptSigner

# Initialize components
engine = PolicyEngine()
runner = SandboxRunner()
verifier = Verifier()
signer = ReceiptSigner()

# Agent proposes action
with AgentLoop() as agent:
    response = agent.chat([{"role": "user", "content": "Print hello world"}])
    action = agent.parse_tool_call(response)

# Policy decides
decision = engine.evaluate(action)

if decision.verdict == "allow":
    # Execute in sandbox
    execution = runner.run(action, decision.caps)

    # Verify
    verification = verifier.verify(execution, decision.caps, output)
    cleanup = verifier.verify_cleanup(execution.container_name)

    # Sign receipt
    receipt = signer.sign(
        {
            "task_id": action.task_id,
            "action_id": action.id,
            "decision": decision.model_dump(by_alias=True),
            "execution": execution.model_dump(by_alias=True),
            "verification": verification.model_dump(by_alias=True),
            "cleanup": cleanup.model_dump(by_alias=True),
        }
    )
```

## Development

```bash
make install    # Install dependencies
make lint       # Run linting
make test       # Run tests
make check      # Lint + test
```

## Testing

Tests are organized by component:
- `tests/test_policy.py` - Policy engine (P1-P12)
- `tests/test_sandbox.py` - Sandbox runner (S13-S28, requires Docker)
- `tests/test_verifier.py` - Verifier (V29-V34, requires Docker)
- `tests/test_receipt.py` - Receipt signing (R35-R39)
- `tests/test_agent.py` - Agent loop (E42, requires `VULTR_INFERENCE_API_KEY`)
- `tests/test_e2e.py` - End-to-end (E40-E41, requires Docker)

Smoke tests requiring live services are marked with `@pytest.mark.smoke` and skip when credentials aren't available.

See `docs/CHECKS.md` for the complete list of 1297 collected tests.

## License

MIT
