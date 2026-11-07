# Evidence Bundle v1 fixture

Offline verify (no server/network):

```bash
airlock verify-bundle tests/fixtures/evidence_bundle/sample-evidence-bundle.zip \
  --pubkey tests/fixtures/evidence_bundle/auditor-trusted.pem
```

Exit 0 = authentic + recount VERIFIED. Exit 1 = authentic + recount FAILED. Exit 2 = authentic but incomplete/inconclusive. The PEM here is the out-of-band trust anchor for this fixture only; bundled signing.pub inside the zip is convenience, not trust.
