"""Supported ERROR/WARN recount + canonical airlock-counts fence (v1).

Offline Evidence Bundle verification and the live host outcome_check share this
module. Changing it changes the verifier code_hash embedded in Task Verdicts.
"""

from __future__ import annotations

import re
from collections import Counter
from hashlib import sha256
from pathlib import Path
from typing import Any

COUNTS_FENCE = "airlock-counts"
COUNTS_CONTRACT = (
    "The report MUST include exactly one fenced block tagged airlock-counts whose "
    "body is only these two lines (integers from this log, nothing else):\n"
    "```airlock-counts\n"
    "ERROR: <n>\n"
    "WARN: <n>\n"
    "```\n"
    "Do not put counts only in prose, examples, or quotes; the checker ignores those."
)

VERIFIER_ID = "airlock.counts.error_warn"
VERIFIER_VERSION = "1"


def verifier_code_hash() -> str:
    """SHA-256 of this module's source bytes — the supported v1 verifier identity."""
    return sha256(Path(__file__).read_bytes()).hexdigest()


def verifier_identity() -> dict[str, str]:
    return {
        "id": VERIFIER_ID,
        "version": VERIFIER_VERSION,
        "code_hash": verifier_code_hash(),
    }


def recount_levels(log_bytes: bytes) -> dict[str, int]:
    """Trusted host-side recount of severity tokens on this corpus's log.

    Counts the second whitespace-separated field when it is ERROR or WARN.
    Does not trust the model, the report, or the receipt world-state claim.
    """
    counts: Counter[str] = Counter()
    for line in log_bytes.decode("utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[1] in ("ERROR", "WARN"):
            counts[parts[1]] += 1
    return {"ERROR": int(counts["ERROR"]), "WARN": int(counts["WARN"])}


# Bound count tokens so huge digit strings never inflate into unbounded ints.
_MAX_COUNT_DIGITS = 9
_CLEAN_INT = re.compile(rf"^\d{{1,{_MAX_COUNT_DIGITS}}}$")
_COUNT_LINE = re.compile(r"^(ERROR|WARN):\s*(\S+)\s*$")
# Strict subset: 0–3 spaces + homogeneous ` or ~ run. Mixed / indent≥4 → ambiguous.
_FENCE_SHAPED = re.compile(r"^( *)([`~]{3,})(.*)$")
_TAB_BEFORE_FENCE = re.compile(r"^[ \t]*\t[ \t]*[`~]{3,}")


def format_counts_block(error: int, warn: int) -> str:
    """Canonical ``airlock-counts`` fence for reports and fixtures."""
    return f"```{COUNTS_FENCE}\nERROR: {error}\nWARN: {warn}\n```"


def _ambiguous(status: str) -> dict[str, Any]:
    return {
        "ERROR": {"value": None, "status": "ambiguous"},
        "WARN": {"value": None, "status": "ambiguous"},
        "block_status": status,
    }


def _classify_fence_line(raw: str) -> tuple[int, str, str] | str | None:
    """Return (ticks, family_char, info) | 'ambiguous' | None if not fence-shaped.

    Homogeneous backtick/tilde markers only; indent must be 0–3 spaces.
    Indent ≥4 or mixed marker runs reject as ambiguous (strict subset).
    """
    # Trailing spaces on a fence line are insignificant (CommonMark closers).
    line = raw.rstrip(" \t")
    if _TAB_BEFORE_FENCE.match(line):
        return "ambiguous"
    m = _FENCE_SHAPED.match(line)
    if not m:
        return None
    indent, marker, rest = m.group(1), m.group(2), m.group(3)
    if len(indent) > 3:
        return "ambiguous"
    families = set(marker)
    if families != {"`"} and families != {"~"}:
        return "ambiguous"
    return (len(marker), marker[0], rest.strip())


def _body_counts(body_lines: list[str]) -> dict[str, Any]:
    """Parse ERROR/WARN lines inside one authoritative fence body."""
    found: dict[str, int] = {}
    for raw in body_lines:
        line = raw.strip()
        if not line:
            continue
        m = _COUNT_LINE.fullmatch(line)
        if not m or not _CLEAN_INT.fullmatch(m.group(2)):
            return _ambiguous("unsupported_format")
        level = m.group(1)
        value = int(m.group(2))
        if level in found:
            return _ambiguous("conflict")
        found[level] = value
    out: dict[str, Any] = {"block_status": "ok"}
    for level in ("ERROR", "WARN"):
        if level not in found:
            out[level] = {"value": None, "status": "missing"}
            out["block_status"] = "incomplete"
        else:
            out[level] = {"value": found[level], "status": "ok"}
    return out


def _parse_counts_block(text: str) -> dict[str, Any]:
    """Line-oriented fence walk: only a top-level closed ``airlock-counts`` counts.

    Strict bounded Markdown subset: 0–3 space indent, homogeneous backtick or
    tilde markers. Bare top-level fences OPEN (not ignored closes). Nested
    ``airlock-counts`` inside wrappers are not authoritative. Mixed markers,
    indent ≥4 fence shapes, duplicate/unclosed tagged openings → INCONCLUSIVE.
    Closing requires same marker family and length ≥ opening. Prose outside one
    authoritative fence is ignored.
    """
    empty = {
        "ERROR": {"value": None, "status": "missing"},
        "WARN": {"value": None, "status": "missing"},
        "block_status": "missing",
    }
    if not text:
        return empty

    # Surrounding non-counts fences: (tick_count, fence_char).
    outer: list[tuple[int, str]] = []
    # Authoritative counts open: (tick_count, fence_char).
    counts_open: tuple[int, str] | None = None
    counts_body: list[str] = []
    completed: list[list[str]] = []
    counts_openings = 0

    for raw in text.splitlines():
        classified = _classify_fence_line(raw)
        if classified == "ambiguous":
            return _ambiguous("ambiguous_fence")
        if classified is not None:
            ticks, char, info = classified
            tag = info.split()[0] if info else ""

            if counts_open is not None:
                c_ticks, c_char = counts_open
                if not info and char == c_char and ticks >= c_ticks:
                    completed.append(counts_body)
                    counts_open = None
                    counts_body = []
                    continue
                counts_body.append(raw)
                continue

            if outer:
                # Counts tag inside any wrapper voids authority (strict subset):
                # same-length outer fences would otherwise treat the nested
                # closer as the outer closer and let a later block VERIFIED.
                if tag == COUNTS_FENCE:
                    return _ambiguous("nested_fence")
                o_ticks, o_char = outer[-1]
                # Same fence family + enough ticks + empty info closes the outer.
                if not info and char == o_char and ticks >= o_ticks:
                    outer.pop()
                # Else content (nested shorter/other-family fences).
                continue

            # Top-level: any fence line opens. Bare fences open too (not closes).
            if tag == COUNTS_FENCE:
                counts_openings += 1
                if counts_openings > 1:
                    return _ambiguous("duplicate_fence")
                counts_open = (ticks, char)
                counts_body = []
                continue
            outer.append((ticks, char))
            continue

        if counts_open is not None:
            counts_body.append(raw)

    if counts_open is not None:
        return _ambiguous("unclosed_fence")
    if counts_openings == 0:
        return empty
    if len(completed) != 1:
        return _ambiguous("duplicate_fence")
    return _body_counts(completed[0])


def outcome_check(log_bytes: bytes, report_text: str | None) -> dict[str, Any]:
    """Compare the authoritative top-level ``airlock-counts`` fence to a recount.

    VERIFIED: one well-formed top-level fence with ERROR and WARN matching.
    FAILED: one well-formed top-level fence whose integers disagree.
    INCONCLUSIVE: missing, nested-in-example, duplicate, unclosed, or malformed.
    Prose outside a single authoritative fence does not invalidate. Never raises.

    A valid receipt signature is not proof of this world-state claim.
    """
    expected = recount_levels(log_bytes)
    note = (
        "on this corpus only; host recount vs one top-level ```airlock-counts fence "
        "(nested examples / unclosed / duplicates are inconclusive; other prose ignored). "
        "A valid receipt signature means the receipt was not tampered with; it does "
        "not by itself prove the world-state claim inside the receipt."
    )
    if report_text is None:
        return {
            "state": "INCONCLUSIVE",
            "expected": expected,
            "reported": {"ERROR": None, "WARN": None},
            "detail": {"ERROR": "missing", "WARN": "missing", "block": "missing"},
            "note": note,
        }
    parsed = _parse_counts_block(report_text)
    reported = {"ERROR": parsed["ERROR"]["value"], "WARN": parsed["WARN"]["value"]}
    detail = {
        "ERROR": parsed["ERROR"]["status"],
        "WARN": parsed["WARN"]["status"],
        "block": parsed["block_status"],
    }
    if parsed["block_status"] != "ok":
        state = "INCONCLUSIVE"
    elif reported["ERROR"] == expected["ERROR"] and reported["WARN"] == expected["WARN"]:
        state = "VERIFIED"
    else:
        state = "FAILED"
    return {
        "state": state,
        "expected": expected,
        "reported": reported,
        "detail": detail,
        "note": note,
    }
