# Airlock Threat Model

This document describes the assets, adversaries, threats, and mitigations for Airlock.

## Assets

1. **Vultr Inference API key** - Authenticates agent to the LLM service
2. **Host VM** - Runs the control plane and Docker
3. **Other tenants' runs** - Isolated executions that must not be compromised
4. **Receipt integrity** - Trust in the audit trail
5. **Compute budget** - Protection against runaway costs

## Adversaries

- **Prompt-injected or misaligned model** - LLM that generates malicious actions
- **Malicious task input** - User-provided data (logs, configs) containing exploits
- **Execution payloads** - Code attempting to escape, exfiltrate, or exhaust resources

## Threats and Mitigations

### 1. Secret Exfiltration

**Threat**: Code in the sandbox attempts to steal the Vultr Inference API key or other secrets.

**Mitigations**:
- API key lives only in the agent loop process, never passed to sandbox
- Environment variables scrubbed before execution (filter `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `VULTR`)
- `--network none` by default (DNS and TCP fail)
- Optional allowlist-only egress proxy for permitted hosts
- Post-execution secret pattern scan of stdout/stderr

**Residual risk**: The model could leak data the user provided to it (e.g., credentials in logs being analyzed). This is out of scope - trust boundaries don't extend to user-provided secrets.

### 2. Destructive Commands

**Threat**: Code attempts `rm -rf /`, filesystem corruption, or host damage.

**Mitigations**:
- Read-only rootfs (`--read-only`)
- Writable workspace is tmpfs, destroyed after each run
- No host bind mounts and no `docker cp`: the job and its inputs are streamed as a tar archive over stdin to a fixed bootstrap program, which rejects absolute paths, `..`, links and devices
- Policy engine denies obvious destructive patterns
- The job runs as `nobody` (uid 65534) with no supplementary groups and cannot modify container config

**Residual risk**: Damage stays inside the disposable container by design. Container is removed after execution.

### 3. Resource Exhaustion and Denial of Service

**Threat**: Infinite loops, fork bombs, memory exhaustion, runaway costs.

**Mitigations**:
- Wall-clock timeout watchdog kills the container at the cap
- The bootstrap sets `RLIMIT_NPROC` for the job uid to exactly the `pids` value in the signed decision caps (32 for the Arena, 64 for tasks; no floor). I call this `job_nproc`. A fork past it fails with EAGAIN, which the job sees and the bootstrap records as an `nproc_limit_reached` note
- `--pids-limit` (`cgroup_pids_headroom` in `/api/policy`) equals `job_nproc` under runc. Under runsc the cgroup counts the sandbox kernel's host threads, not job processes, and hitting it kills the whole sandbox (exit 2, no output); runsc therefore gets `max(4 x job_nproc, 512)`, so the Arena's `--pids-limit 512` under runsc is headroom, not the job's cap. The guest view of `pids.max` under runsc reads `max`
- Under runsc the practical fork ceiling is memory, not `RLIMIT_NPROC`: each forked Python process is charged against `--memory`, and the fifth review's fork bombs ended as an OOM kill (137, `killed_by=oom`, report discarded) before EAGAIN. Under runc the same jobs stop at about `job_nproc - 4` children with EAGAIN. Both outcomes are recorded and neither leaves the container
- `policy.max_pids` in `/api/policy` is only the ceiling a requested `pids` cap is clamped to; it is not what a given run gets
- `--memory` cap triggers OOM killer
- `--cpus` throttles CPU usage
- stdout and stderr capped at 1 MiB each (truncation is flagged); `/work/out` artifacts capped at 64 files / 8 MiB total
- Tmpfs workspace size limited to 64 MB

**Residual risk**: Host-level DoS from many concurrent tasks requires per-user rate limiting (not yet implemented).

### 4. Container Escape

**Threat**: Kernel exploit allows sandbox escape to host.

**Mitigations**:
- The job runs as uid 65534 with no capabilities. The bootstrap (PID 1) starts as uid 0 with only `SETUID` and `SETGID` so it can drop the job to that uid; see section 8
- `--cap-drop ALL` removes every other capability
- `--security-opt no-new-privileges` prevents privilege escalation
- Default seccomp profile blocks dangerous syscalls
- gVisor `runsc` runtime where available (separate kernel emulation)
- Patched host kernel

**Residual risk**: **This is not eliminated.** Docker containers share the kernel. A kernel vulnerability or Docker escape could compromise the host. Container isolation reduces risk but is not absolute.

**Honest assessment**: I do not claim perfect isolation. gVisor helps but isn't always available. This is appropriate for hackathon/demo workloads, not for executing untrusted code from malicious actors at scale.

### 5. Policy Bypass via Obfuscation

**Threat**: Code uses `base64`, `eval`, or other obfuscation to hide malicious intent.

**Mitigations**:
- Python: module allow-list, per-module attribute allow-lists for `os` and `sys`, denial of introspection and `_`-prefixed attributes, of the `getattr` family with non-literal names, of `operator.attrgetter`/`methodcaller`/`itemgetter`, of module aliasing, of attribute traversal in format strings, and of non-literal or out-of-tree file paths
- Shell: binary and option allow-lists, a sed parser that accepts a fixed subset, file arguments limited to `/work`, `/work/input`, `/work/out` and `/dev/null`, writes limited to `/work/out` and never to script files
- Anything the checkers do not understand is denied

**Residual risk**: Static analysis is incomplete by design; the zero false-allow result applies to the test corpus only (see KNOWN_LIMITATIONS section 3). The sandbox is the real boundary. Policy improves decisions but doesn't prevent execution of all bad code - it contains it.

### 6. LLM Self-Approval

**Threat**: The model approves its own dangerous actions.

**Mitigations**:
- Policy decisions come from deterministic Python code only
- LLM output is treated as untrusted data
- No LLM in the authorization path
- Optional classifier (`nemotron-3.5-content-safety`) is advisory only and can escalate but never downgrade a deny

**Residual risk**: None. The LLM cannot override policy.

### 7. Receipt Forgery and Chain Tampering

**Threat**: Attacker modifies receipts or breaks the chain to hide malicious activity.

**Mitigations**:
- RFC 8785 canonical JSON (stable serialization)
- SHA-256 hashing of canonical form
- Ed25519 signature over canonical hash
- Previous receipt hash included in chain (`prev_hash`)
- Offline verification with public key only

**Residual risk**: A compromised host with access to the private key can sign forged receipts. Receipts are evidence that Airlock observed and recorded actions, not proof that the host is trustworthy.

**Honest assessment**: If the signing host is compromised, receipts can lie. They're an audit trail, not a guarantee of host integrity.

### 8. Forged Execution Report

**Threat**: The job writes a fake result document to the bootstrap's stdout (`/proc/1/fd/1`), kills or ptraces PID 1, or prints a second document, so the host records a false exit code, stdout or artifacts.

**Mitigations**:
- Privilege split. The container starts as uid 0 with `--cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges`. The bootstrap calls `prctl(PR_SET_DUMPABLE, 0)`, unpacks the inputs (root-owned, read-only for the job) and runs the job as uid/gid 65534 with `setgroups([])`, stdin `/dev/null`, `close_fds`. A different uid means the job cannot open `/proc/1/fd/*`, `/proc/1/mem` or `/proc/1/environ`, cannot `ptrace` PID 1 and cannot signal it. After the job exits, a child that switches to uid 65534 kills every remaining process of that uid, then collects `/work/out`, so a leftover process cannot change artifacts during collection or hold the output pipes open.
- Per-run nonce. The host sends a random 128-bit nonce as the first stdin line. It is never in argv, env or files and the job gets `/dev/null` as stdin. The report must carry it.
- Strict acceptance on the host. The report is used only if the container's stdout is exactly one JSON document with no duplicate keys, the exact key set, strict types and the right nonce, and the container exited 0 with no timeout or OOM. Otherwise the run is recorded with `report_invalid=true`, empty stdout/stderr/artifacts, and the exit code from `docker inspect` (never 0: 137 after a kill, 125 if the container somehow exited 0 without a valid report).
- Regression tests run on real Docker under runsc and runc (`tests/test_sandbox.py::TestReportForgery`) and with the fake Docker (`tests/test_sandbox_unit.py::TestReportForgeryUnit`).

**Tradeoff**: PID 1 runs as uid 0 inside the container, holding only SETUID/SETGID (no `CAP_DAC_OVERRIDE`, `CAP_KILL`, `CAP_SYS_PTRACE`, `CAP_CHOWN`). It is fixed repository code and never executes job code before dropping privileges. A bug in the bootstrap itself would run as uid 0 in the container, which with a read-only rootfs and those two caps is still weaker than the job but not equivalent to `--user 65534`. The job's `/work` is root-owned (0755); only `/work/out` (1777, sticky), `/tmp` and `/dev/shm` are writable to it.

**Residual risk**: A kernel or runtime bug that lets uid 65534 cross into uid 0 inside the container would defeat the split; the nonce and strict parsing still require the forger to read PID 1's memory.

## Out of Scope

- **User-provided secrets**: If the user gives the agent their AWS keys in a config file, the model can see and leak them. Trust boundaries don't extend to user data.
- **Model hallucination or incorrect code**: The agent might write buggy code. Airlock contains the blast radius; it doesn't guarantee correctness.
- **Side channels**: Timing attacks, speculative execution, CPU cache leaks are not addressed.
- **Physical access**: An attacker with access to the VM can read memory, including keys.

## Threat Model Summary

Airlock's security model is **defense in depth with honest limitations**:

1. **Policy layer** reduces bad decisions
2. **Sandbox layer** contains execution
3. **Verification layer** detects problems
4. **Receipt layer** provides audit trail

Each layer has weaknesses:
- Policy can be evaded
- Sandboxes can theoretically be escaped
- Verification depends on the host
- Receipts can be forged if the host is compromised

I built this for a hackathon to demonstrate verified execution, not as production-hardened infrastructure. Use it understanding these limits.
