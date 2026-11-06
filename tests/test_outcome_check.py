"""Independent ERROR/WARN recount vs ```airlock-counts fence only."""

from airlock.web.tasks import format_counts_block, outcome_check, recount_levels, sample_log

_INNER = "```airlock-counts\nERROR: 31\nWARN: 7\n```\n"


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


def test_same_length_wrapper_then_trailing_counts_is_inconclusive():
    """Nested counts inside ``` voids the doc even if a later top-level fence appears."""
    log = sample_log(False)
    report = "```\n" + _INNER + "```\n" + format_counts_block(31, 7)
    assert outcome_check(log, report)["state"] == "INCONCLUSIVE"


def test_wrapper_variants_do_not_count_as_authoritative():
    """Tagged/bare backtick and tilde wrappers of varying lengths keep examples out."""
    log = sample_log(False)
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
        report = f"{open_}Example:\n{_INNER}{close}"
        assert outcome_check(log, report)["state"] == "INCONCLUSIVE", repr(open_)


def test_mixed_marker_rejection():
    """Mixed `~ runs are ambiguous — never an authoritative counts fence."""
    log = sample_log(False)
    mixed = [
        "```~airlock-counts\nERROR: 31\nWARN: 7\n```~\n",
        "`~`airlock-counts\nERROR: 31\nWARN: 7\n`~`\n",
        "~~`airlock-counts\nERROR: 31\nWARN: 7\n~~`\n",
        "`~`~airlock-counts\nERROR: 31\nWARN: 7\n`~`~\n",
        "  ```~airlock-counts\nERROR: 31\nWARN: 7\n  ```~\n",
    ]
    for report in mixed:
        assert outcome_check(log, report)["state"] == "INCONCLUSIVE", repr(report)


def test_indented_wrapper_1_2_3_spaces_is_inconclusive():
    """1–3 space-indented outer fences are real Markdown fences; nested counts void."""
    log = sample_log(False)
    for n in (1, 2, 3):
        pad = " " * n
        for open_m, close_m, tag in (
            ("````", "````", ""),
            ("````", "````", "markdown"),
            ("~~~~", "~~~~", ""),
            ("~~~", "~~~", "md"),
        ):
            open_line = f"{pad}{open_m}{tag}\n" if tag else f"{pad}{open_m}\n"
            report = f"{open_line}{_INNER}{pad}{close_m}\n"
            assert outcome_check(log, report)["state"] == "INCONCLUSIVE", (n, open_m, tag)


def test_indent4_wrapper_is_inconclusive():
    """Indent ≥4 fence-shaped lines are ambiguous under the strict subset."""
    log = sample_log(False)
    report = "    ````\n" + _INNER + "    ````\n"
    assert outcome_check(log, report)["state"] == "INCONCLUSIVE"


def test_valid_fence_then_unclosed_second_opening_is_inconclusive():
    """A second top-level ```airlock-counts opening (even unclosed) voids authority."""
    log = sample_log(False)
    report = format_counts_block(31, 7) + "\n```airlock-counts\nERROR: 99\n"
    assert outcome_check(log, report)["state"] == "INCONCLUSIVE"


def test_plain_authoritative_fence_still_verified():
    log = sample_log(False)
    assert outcome_check(log, format_counts_block(31, 7))["state"] == "VERIFIED"


def test_indented_canonical_counts_0_to_3_still_verified():
    """Top-level counts fence may itself be indented 0–3 spaces."""
    log = sample_log(False)
    for n in (0, 1, 2, 3):
        pad = " " * n
        report = f"{pad}```airlock-counts\nERROR: 31\nWARN: 7\n{pad}```\n"
        assert outcome_check(log, report)["state"] == "VERIFIED", n


def test_adversarial_fence_matrix_examples_never_verified():
    """Exhaustive wrapper matrix: examples must never VERIFIED; plain unique still does."""
    log = sample_log(False)
    assert outcome_check(log, format_counts_block(31, 7))["state"] == "VERIFIED"

    families = [
        ("`", 3),
        ("`", 4),
        ("`", 5),
        ("~", 3),
        ("~", 4),
        ("~", 6),
    ]
    tags = ["", "markdown", "md", "text"]
    failures: list[str] = []

    for indent in range(0, 5):
        pad = " " * indent
        for char, n in families:
            marker = char * n
            for tag in tags:
                open_line = f"{pad}{marker}{tag}\n" if tag else f"{pad}{marker}\n"
                # closed wrapper
                closed = f"{open_line}Example:\n{_INNER}{pad}{marker}\n"
                # unclosed wrapper
                unclosed = f"{open_line}Example:\n{_INNER}"
                for label, report in (("closed", closed), ("open", unclosed)):
                    state = outcome_check(log, report)["state"]
                    if state == "VERIFIED":
                        failures.append(f"{label} indent={indent} {marker!r} tag={tag!r}")

    # Mixed markers (homogeneous grammar rejects)
    for mixed_open, mixed_close in (
        ("```~", "```~"),
        ("`~`", "`~`"),
        ("~~`", "~~`"),
        ("`~~", "`~~"),
        ("~~~`", "~~~`"),
    ):
        for indent in range(0, 5):
            pad = " " * indent
            report = f"{pad}{mixed_open}\n{_INNER}{pad}{mixed_close}\n"
            if outcome_check(log, report)["state"] == "VERIFIED":
                failures.append(f"mixed indent={indent} {mixed_open!r}")

    # Duplicate / malformed tags around a would-be match
    malformed = [
        "```airlock-counts\nERROR: 31\nWARN: 7\n```\n```airlock-counts\nERROR: 31\nWARN: 7\n```\n",
        "```airlock-counts\nERROR: 31\nWARN: 7\n",
        "```airlock-counts\nERROR: 31\nWARN: 7\n~~~~\n",  # wrong family close
        "~~~airlock-counts\nERROR: 31\nWARN: 7\n```\n",  # wrong family close
        "```airlock-counts\nERROR: 31\nWARN: 7\n``\n",  # too short close
        "```not-counts\nERROR: 31\nWARN: 7\n```\n",
        "```airlock-counts extra\nERROR: 31\nWARN: 7\n```\n",  # first token still counts — see below
        "```Airlock-counts\nERROR: 31\nWARN: 7\n```\n",
        "```airlock-counts\nERROR: 31\nWARN: 07\n```\n",  # leading zero token — CLEAN_INT ok actually
    ]
    # Leading-zero "07" is still a clean int 7 — that may VERIFIED; drop from never-verify list.
    malformed = [m for m in malformed if "WARN: 07" not in m]
    # `airlock-counts extra` — first token is airlock-counts; closed unique → may VERIFIED.
    # That is legitimate under our tag rule; exclude from example-never-verify.
    malformed = [m for m in malformed if "airlock-counts extra" not in m]
    for report in malformed:
        if outcome_check(log, report)["state"] == "VERIFIED":
            failures.append(f"malformed {report!r}")

    assert not failures, "falsely VERIFIED:\n" + "\n".join(failures)
