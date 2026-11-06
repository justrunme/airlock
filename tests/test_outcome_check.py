"""Independent ERROR/WARN recount vs ```airlock-counts fence only."""

from airlock.web.tasks import format_counts_block, outcome_check, recount_levels, sample_log


def test_recount_levels_on_sample_corpus():
    assert recount_levels(sample_log(False)) == {"ERROR": 31, "WARN": 7}
    assert recount_levels(sample_log(True)) == {"ERROR": 31, "WARN": 8}


def test_outcome_check_verified_only_with_canonical_fence():
    log = sample_log(False)
    report = f"# app.log report\n\n{format_counts_block(31, 7)}\n\n## notes\n"
    out = outcome_check(log, report)
    assert out["state"] == "VERIFIED"
    assert out["expected"] == out["reported"] == {"ERROR": 31, "WARN": 7}
    assert "airlock-counts" in out["note"]


def test_prose_example_counts_are_not_verified():
    """Observation (a): scanning arbitrary prose falsely VERIFIED before the fence contract."""
    log = sample_log(False)
    adversarial = [
        "No analysis performed. Example: ERROR: 31 WARN: 7\n",
        "ERROR: 31 WARN: 7\nERROR:\n",
        'He said "ERROR: 31 WARN: 7" but did nothing\n',
        "```\nERROR: 31\nWARN: 7\n```\n",  # wrong fence tag
        "```airlock-counts\nERROR: 31\nWARN: 7\n```\n```airlock-counts\nERROR: 31\nWARN: 7\n```\n",
        "```airlock-counts\nERROR: 31\n```\n",  # incomplete
        "```airlock-counts\nERROR: 31.9\nWARN: 7\n```\n",
        "```airlock-counts\n# example\nERROR: 31\nWARN: 7\n```\n",
    ]
    for report in adversarial:
        out = outcome_check(log, report)
        assert out["state"] == "INCONCLUSIVE", repr(report)


def test_outcome_check_failed_on_unequivocal_fence_mismatch():
    log = sample_log(False)
    report = f"# report\n{format_counts_block(99, 7)}\n"
    out = outcome_check(log, report)
    assert out["state"] == "FAILED"
    assert out["reported"]["ERROR"] == 99


def test_outcome_check_inconclusive_without_fence():
    log = sample_log(False)
    assert outcome_check(log, None)["state"] == "INCONCLUSIVE"
    assert outcome_check(log, "# no fence\n")["state"] == "INCONCLUSIVE"


def test_prose_outside_fence_ignored_when_fence_ok():
    log = sample_log(False)
    report = (
        "Example: ERROR: 99 WARN: 99\n\n"
        f"{format_counts_block(31, 7)}\n\n"
        "Also ERROR: 0 WARN: 0 in narrative.\n"
    )
    assert outcome_check(log, report)["state"] == "VERIFIED"
