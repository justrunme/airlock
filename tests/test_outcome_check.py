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


def test_nested_in_four_backtick_example_is_inconclusive():
    """Valid ```airlock-counts inside a ```` markdown example is not authoritative."""
    log = sample_log(False)
    report = "````markdown\nExample report:\n```airlock-counts\nERROR: 31\nWARN: 7\n```\n````\n"
    assert outcome_check(log, report)["state"] == "INCONCLUSIVE"


def test_bare_four_backtick_wrapper_is_inconclusive():
    """Bare ```` (no language tag) still opens; nested counts must not VERIFIED."""
    log = sample_log(False)
    report = "````\n```airlock-counts\nERROR: 31\nWARN: 7\n```\n````\n"
    assert outcome_check(log, report)["state"] == "INCONCLUSIVE"


def test_wrapper_variants_do_not_count_as_authoritative():
    """Tagged/bare backtick and tilde wrappers of varying lengths keep examples out."""
    log = sample_log(False)
    inner = "```airlock-counts\nERROR: 31\nWARN: 7\n```\n"
    wrappers = [
        ("````\n", "````\n"),
        ("````markdown\n", "````\n"),
        ("```\n", "```\n"),
        ("```text\n", "```\n"),
        ("~~~~~\n", "~~~~~\n"),
        ("~~~md\n", "~~~\n"),
        ("~~~~~~\n", "~~~~~~\n"),
    ]
    for open_, close in wrappers:
        report = f"{open_}Example:\n{inner}{close}"
        assert outcome_check(log, report)["state"] == "INCONCLUSIVE", repr(open_)


def test_valid_fence_then_unclosed_second_opening_is_inconclusive():
    """A second top-level ```airlock-counts opening (even unclosed) voids authority."""
    log = sample_log(False)
    report = format_counts_block(31, 7) + "\n```airlock-counts\nERROR: 99\n"
    assert outcome_check(log, report)["state"] == "INCONCLUSIVE"


def test_plain_authoritative_fence_still_verified():
    log = sample_log(False)
    assert outcome_check(log, format_counts_block(31, 7))["state"] == "VERIFIED"
