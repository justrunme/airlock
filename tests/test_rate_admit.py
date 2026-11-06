"""Cross-limiter admission: non-mutating reject, single charge on success."""

import pytest

from airlock.web.limits import RateLimitedError, RateLimiter, admit_all


def test_rejected_admission_leaves_counters_unchanged_across_rollover():
    """Minute window expires; day still full. Reject must not charge the minute.

    Deterministic clock: after rollover, min has capacity and day does not.
    Preflight must not call reserve() to manufacture the exception (that could
    succeed after expiry and mutate capacity before the day reject).
    """
    t = [1000.0]

    def clock():
        return t[0]

    minute = RateLimiter(1, 60, clock=clock)
    day = RateLimiter(1, 86400, clock=clock)
    minute.reserve("ip", 1, now=1000.0)
    day.reserve("ip", 1, now=1000.0)
    assert minute.charged("ip") == 1
    assert day.charged("ip") == 1

    # Minute window expires; day hit remains.
    t[0] = 1061.0
    assert minute.can_admit("ip", 1, now=t[0])[0] is True
    assert day.can_admit("ip", 1, now=t[0])[0] is False

    with pytest.raises(RateLimitedError):
        admit_all([(minute, "ip"), (day, "ip")], 1, now=t[0])

    # Reject left minute uncharged (still 0 in-window after expiry).
    assert minute.charged("ip") == 0
    assert day.charged("ip") == 1


def test_successful_admission_charged_once_at_shared_timestamp():
    t = [5000.0]

    def clock():
        return t[0]

    minute = RateLimiter(2, 60, clock=clock)
    day = RateLimiter(2, 86400, clock=clock)
    admit_all([(minute, "ip"), (day, "ip")], 1, now=t[0])
    assert minute.charged("ip") == 1
    assert day.charged("ip") == 1
    # Same timestamp again fits once more, not double-charged by preflight.
    admit_all([(minute, "ip"), (day, "ip")], 1, now=t[0])
    assert minute.charged("ip") == 2
    assert day.charged("ip") == 2
    with pytest.raises(RateLimitedError):
        admit_all([(minute, "ip"), (day, "ip")], 1, now=t[0])
    assert minute.charged("ip") == 2
    assert day.charged("ip") == 2
