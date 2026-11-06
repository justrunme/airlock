"""Independent ERROR/WARN recount vs report.md (on this corpus only)."""

from airlock.web.tasks import outcome_check, recount_levels, sample_log


def test_recount_levels_on_sample_corpus():
    assert recount_levels(sample_log(False)) == {"ERROR": 31, "WARN": 7}
    assert recount_levels(sample_log(True)) == {"ERROR": 31, "WARN": 8}


def test_outcome_check_verified_when_report_matches():
    log = sample_log(False)
    report = "# app.log report\n\nERROR: 31  WARN: 7\n"
    out = outcome_check(log, report)
    assert out["state"] == "VERIFIED"
    assert out["expected"] == out["reported"] == {"ERROR": 31, "WARN": 7}
    assert "on this corpus" in out["note"]


def test_outcome_check_failed_on_unequivocal_mismatch():
    log = sample_log(False)
    report = "# app.log report\n\nERROR: 99  WARN: 7\n"
    out = outcome_check(log, report)
    assert out["state"] == "FAILED"
    assert out["expected"]["ERROR"] == 31
    assert out["reported"]["ERROR"] == 99


def test_outcome_check_inconclusive_without_parsable_counts():
    log = sample_log(False)
    assert outcome_check(log, None)["state"] == "INCONCLUSIVE"
    assert outcome_check(log, "# no numbers here\n")["state"] == "INCONCLUSIVE"
    partial = outcome_check(log, "ERROR: 31\n")  # WARN missing
    assert partial["state"] == "INCONCLUSIVE"
    assert partial["reported"]["ERROR"] == 31
    assert partial["reported"]["WARN"] is None
    assert partial["detail"]["WARN"] == "missing"


def test_outcome_check_conflict_is_inconclusive_not_last_wins():
    """Negative: contradictory claims must not resolve to VERIFIED via last-wins."""
    log = sample_log(False)
    report = "ERROR: 99  WARN: 99\n\nLater restates ERROR: 31  WARN: 7\n"
    out = outcome_check(log, report)
    assert out["state"] == "INCONCLUSIVE"
    assert out["detail"]["ERROR"] == "conflict"
    assert out["detail"]["WARN"] == "conflict"
    assert out["reported"]["ERROR"] is None


def test_outcome_check_decimals_commas_exponents_huge_are_inconclusive():
    log = sample_log(False)
    cases = [
        "ERROR: 31.9  WARN: 7\n",
        "ERROR: 31,000  WARN: 7\n",
        "ERROR: 3e1  WARN: 7\n",
        "ERROR: 31000000000  WARN: 7\n",  # >9 digits
        "ERROR: 31  WARN: 7.0\n",
    ]
    for report in cases:
        out = outcome_check(log, report)
        assert out["state"] == "INCONCLUSIVE", report
        # Never crash; never truncate into a false VERIFIED.
        assert out["state"] != "VERIFIED"


def test_outcome_check_duplicate_same_value_is_verified():
    log = sample_log(False)
    report = "ERROR: 31  WARN: 7\nSummary again: ERROR: 31 WARN: 7\n"
    assert outcome_check(log, report)["state"] == "VERIFIED"
