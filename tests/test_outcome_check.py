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
    assert "was not tampered with" in out["note"]


def test_outcome_check_failed_on_mismatched_counts():
    """Negative: a wrong report is FAILED, not VERIFIED."""
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
