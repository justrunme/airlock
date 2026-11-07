# Evidence Bundle v1

Offline-verifiable export of one authorized fixture task run.

## Contents

- `manifest.json` — versioned member list with sizes and SHA-256 digests
- `input/app.log` — authorized sample fixture only (never arbitrary/user paths)
- `report.md` — when present; bytes match the Task Verdict commitment
- `task_verdict.json` — domain-separated signed Task Verdict (`airlock.task_verdict.v1`)
- `receipts/NNNN_<receipt_hash>.json` — ordered ActionReceipts for the task
- `signing.pub` — convenience copy only (**not** the trust anchor)

## Trust model

- The auditor supplies the Ed25519 public key **out of band** (`--pubkey`).
- Bundled `signing.pub` is a convenience copy and must not be treated as trust.
- A valid ActionReceipt signature does **not** sign the Task Verdict.
- Verifier `id` / `version` / `code_hash` identify the supported
  `airlock.counts.error_warn` v1 rule; they do not prove that verifier is trusted.
- Signed origin (this server's key) is not the same as an independently checked
  corpus claim.

## Offline verify

```bash
airlock verify-bundle path/to/bundle.zip --pubkey path/to/auditor-trusted.pem
```

No Airlock server, network, or inference is required.

| Exit | Meaning |
|------|---------|
| 0 | Authentic; recount **VERIFIED** |
| 1 | Authentic; recount **FAILED** (integrity OK — mismatch evidence) |
| 2 | Authentic; incomplete / inconclusive (not a success claim) |
| 10 | Signature invalid |
| 11 | Hash / binding mismatch |
| 12 | Schema error |
| 15 | Trusted key missing/invalid |
| 16 | I/O error |
| 17 | Bundle structure / archive safety / corrupt member |
| 18 | Unsupported verifier version |
| 19 | Unexpected/internal (fail-closed; never means authentic) |

## Limitations

- Export is limited to built-in fixture sample logs.
- Does not prove host honesty at signing time.
- Does not include runtime network/read-only probes.
- Feature set is frozen at v1.
