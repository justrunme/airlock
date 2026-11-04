# Known Limitations

This document lists genuine limitations that remain after implementation.

## 1. Network Allowlist Not Implemented

**Status**: Fail-closed  
**Behavior**: Only `network=none` is supported. Requesting `network=allowlist` raises `ValueError`.

**Why**: Implementing a real egress allowlist requires:
- Dedicated Docker network
- Filtering proxy container
- Network routing configuration
- Testing infrastructure

**Security stance**: The code fails closed. Attempting to use allowlist mode returns an error rather than silently allowing all network access.

## 2. Docker Required for Sandbox Tests

**Status**: 23 tests skip without Docker  
**Tests**: S13-S28 (sandbox), V29-V32+V34 (verifier), E40-E41 (E2E)

**Reason**: These tests verify real Docker container behavior:
- UID/GID isolation
- Read-only rootfs
- Resource caps (pids, mem, cpu)
- Network isolation
- Container cleanup

**Environment note**: Docker-based tests require a running Docker daemon. When no daemon is reachable they are skipped with an explicit reason; they never pass without running.

**CI**: Separate Docker job on ubuntu-latest runs these tests.

## 3. Static Policy Is an Allow-List Checked Against One Corpus

**Status**: Known limitation
**Design**: The policy accepts only what it understands and denies everything else. Shell commands must use an allow-listed binary with allow-listed options, and file arguments may only name relative paths, `/work`, `/work/input`, `/work/out` or `/dev/null`. sed scripts are parsed into a fixed command subset (`airlock/sed_parser.py`; `e`, `w`, `W`, `r`, `R`, labels and branches are rejected). awk `getline`, file redirects and `ENVIRON` are denied. jq `env`, `$ENV`, `input_filename`, `--rawfile`, `--slurpfile` and module paths are denied. Python modules come from an allow-list; attribute access is checked against per-module allow-lists for `os` and `sys`, a deny-list of introspection names and any `_`-prefixed name. File paths must be literals that resolve inside the allowed directories. Shell loops (`while`, `for`, `case`), process substitution, unknown binaries and unparseable input are denied rather than sent for approval.

**Evidence**: `tests/test_policy_corpus_r4.py` pins 163 adversarial cases (every case from the round-4 policy probe plus 72 new ones) to `deny` with a reason code, and 101 benign cases (the probe's 50 plus 51 new SRE tasks) to `allow`. On that corpus the false-allow and false-deny counts are 0.

**Limitation**: Those counts hold for this corpus only. A static checker for Python and shell cannot be complete; new bypasses and new false denies are expected. The sandbox (read-only rootfs, no capabilities, uid 65534, network=none, gVisor where available) is the second line of defence and is what contains code the policy misjudges.

## 4. Container Isolation Not Absolute

**Status**: Inherent Docker limitation  
**Risk**: Docker shares the kernel with the host. A kernel exploit could escape the sandbox.

**Mitigations in place**:
- Read-only rootfs
- No capabilities
- no-new-privileges
- UID 65534 (nobody)
- Resource limits
- Network=none

**Future improvement**: gVisor runsc runtime provides stronger isolation via userspace kernel. Tests skip gVisor checks explicitly when unavailable.

## 5. Receipt Trust Anchored to Host

**Status**: Fundamental limitation of local execution  
**Risk**: If the host running Airlock is compromised, receipts can be forged.

**What receipts prove**: Receipts prove that *this instance of Airlock* observed and recorded what happened. They do not prove the host wasn't compromised.

**Context**: This is a hackathon project demonstrating verified execution patterns, not a production-hardened trusted execution environment.

## 6. Receipt Encoding and Chain Truncation

**Parsing**: `airlock verify` and `verify-chain` accept a receipt only if it is strict JSON with no duplicate keys and no NaN/Infinity, every schema field is present with its exact JSON type (`"0"`, `0.0` or `false` for an integer is rejected), integers are within +/-2**53, `hash` and `sig_ed25519` are lowercase hex of the right length, and the RFC 8785 canonical form of the document equals that of the validated model. Anything else exits 12. Encodings that JCS maps to the same bytes (key order, whitespace, `\u0074` for `t`, `5e-1` for `0.5`) verify, because the signature covers the canonical bytes, not the file bytes. The signer refuses integers beyond +/-2**53.

**Exit codes**: 0 ok, 10 signature, 11 hash, 12 schema or malformed chain head, 13 no genesis or head mismatch, 14 gap/fork/duplicate, 15 key, 16 I/O. The list lives in the `airlock/cli.py` docstring.

**Truncation**: Without `--chain-head`, deleting receipts from the end of a chain is not detectable (`verify-chain` returns 0 for the shorter chain). Sign the head with `airlock chain-head sign` and pass it to `verify-chain --chain-head` to detect this. The head file is excluded from the receipt set by resolved path, so it may live in the chain directory.

## 7. `tail -f` Is Denied on Purpose

**Status**: Deliberate false DENY
**Behavior**: `tail -f`, `tail -F` and `--follow` are refused (`R-SHELL-OPTION`). The fifth independent review counted `tail -f /work/input/app.log` as its one benign false DENY.

**Why I keep it**: inside the sandbox nothing appends to `/work/input`, so `tail -f` never ends. It would only hold a sandbox slot until the wall-clock watchdog kills it, and a killed run discards its report and output. `tail -n 100 /work/input/app.log` gives the same answer and terminates. I do not loosen the policy to cut false DENYs.

## Security Stance

All limitations follow fail-closed principles:
- Network allowlist → error, not bypass
- Missing Docker → tests skip honestly
- Unknown shell or Python constructs → denied by the policy; anything misjudged is contained in the sandbox
- Container escape risk → documented, mitigations applied

I do not claim absolute security. I state what is enforced and what remains vulnerable.

## Sandbox data path

The host sends a per-run nonce line followed by a tar archive with the job and its input files over stdin. A fixed bootstrap program (`airlock/bootstrap.py`, passed as `python3 -c`) unpacks it into the `/work` tmpfs, runs the job as uid 65534 (the bootstrap itself is uid 0 with only SETUID/SETGID/SETPCAP, see THREAT_MODEL section 8) and prints one JSON report with the nonce, the exit code, capped stdout/stderr, truncation flags, the files under `/work/out` and any dropped files with their size and reason. Inputs appear at `/work/input/`; only `/work/out/` is collected. The host recomputes every artifact sha256. Limits: 1 MiB per output stream, 64 artifacts and 8 MiB in total; anything beyond is dropped, and the Execution record and signed receipt carry `stdout_truncated`, `stderr_truncated` and `artifacts_dropped`.

The report is trusted only when it is exactly one strictly valid document with this run's nonce and the container exited 0 without a timeout or OOM kill. In every other case the Execution has `report_invalid=true`, stdout, stderr and artifacts are empty, and the exit code comes from `docker inspect` (never 0). When the container is killed (OOM or timeout) the report is therefore always discarded, even if one was printed.

Besides `/work`, the job can write to `/tmp` (16 MiB) and `/dev/shm` (8 MiB). Both are tmpfs mounted noexec, nosuid, nodev, are discarded with the container and are never collected.
