# Independent policy corpus

`corpus.jsonl` was written by an independent reviewer during adversarial review 5, not by me (the policy author). I added it here unchanged. Each line is one case: `lang` (`python` or `bash`), `code`, `kind` (`attack` or `benign`) and an optional `note`. There are 477 rows: 398 attack and 79 benign.

The labels are the reviewer's. Many "attack" rows are probes that turn out to be harmless when allowed (an `import`, a `print`, a no-op). I did not relabel them. Instead every remaining false-ALLOW and false-DENY is listed in `triage.json` with the reason I judge it harmless, and `tests/test_policy_corpus_independent.py` fails if any other row is misclassified, or if a listed row starts to pass (so the list stays exact).

`scripts/corpus_metrics.py` reports this corpus separately from my own corpus. The numbers describe this corpus only. They are not a general detection rate.

Before the review 5 fixes (policy at commit 8f4ef96) this corpus gave 46 false-ALLOW, 6 of them security-relevant (five pathlib `glob`/`rglob` patterns with `..` that listed `/etc`, `/` and `/proc/self`, and `test -r /etc/passwd`), and 1 false-DENY (`tail -f`, denied on purpose).
