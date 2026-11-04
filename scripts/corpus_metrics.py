"""Run the policy over the test corpora and write false-ALLOW / false-DENY counts.

Labels come from the corpus itself (adversarial vs benign list or id prefix),
not from the pinned verdicts, so a regression shows up as a real miss.
The numbers describe this corpus only. They are not a general detection rate.

    python scripts/corpus_metrics.py          # write airlock/web/static/metrics.json
    python scripts/corpus_metrics.py --check  # fail if the file is stale
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from airlock.policy import PolicyEngine  # noqa: E402
from airlock.schemas import ActionRequest  # noqa: E402

OUT = ROOT / "airlock" / "web" / "static" / "metrics.json"


def load_cases() -> list[tuple[str, str, str, str, str]]:
    """Return (source, id, lang, code, label) with label 'adversarial' or 'benign'."""
    import test_policy_corpus_expanded as expanded
    import test_policy_corpus_r4 as r4

    out = []
    for cid, lang, code, *_ in r4.CASES:
        label = "adversarial" if "adv" in cid else "benign"
        out.append(("test_policy_corpus_r4.py", cid, lang, code, label))
    for cid, lang, code, *_ in expanded.ADVERSARIAL_CASES:
        out.append(("test_policy_corpus_expanded.py", cid, lang, code, "adversarial"))
    for cid, lang, code, *_ in expanded.BENIGN_CASES:
        out.append(("test_policy_corpus_expanded.py", cid, lang, code, "benign"))
    return out


def compute() -> dict:
    engine = PolicyEngine()
    cases = load_cases()
    adv = ben = false_allow = false_deny = 0
    misses = []
    digest = hashlib.sha256()
    for source, cid, lang, code, label in cases:
        digest.update(f"{cid}\0{lang}\0{code}\0{label}\n".encode())
        if lang == "tool":
            action = ActionRequest(id=cid, task_id="metrics", tool=code)
        else:
            action = ActionRequest(id=cid, task_id="metrics", tool="run_code", lang=lang, code=code)
        verdict = engine.evaluate(action).verdict
        if label == "adversarial":
            adv += 1
            if verdict == "allow":
                false_allow += 1
                misses.append({"id": cid, "kind": "false_allow", "source": source})
        else:
            ben += 1
            if verdict != "allow":
                false_deny += 1
                misses.append({"id": cid, "kind": "false_deny", "source": source})
    return {
        "scope": "on this corpus only; not a general detection rate",
        "sources": sorted({c[0] for c in cases}),
        "corpus_sha256": digest.hexdigest(),
        "policy_sha256": engine.policy_hash,
        "adversarial": adv,
        "benign": ben,
        "false_allow": false_allow,
        "false_deny": false_deny,
        "false_allow_rate": round(false_allow / adv, 4) if adv else None,
        "false_deny_rate": round(false_deny / ben, 4) if ben else None,
        "misses": misses,
    }


def main() -> int:
    text = json.dumps(compute(), indent=2) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            print("metrics.json is stale: run python scripts/corpus_metrics.py", file=sys.stderr)
            return 1
        print("metrics.json is up to date")
        return 0
    OUT.write_text(text)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
