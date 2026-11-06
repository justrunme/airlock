"""Per-IP rate limits, a global concurrency gate and attempt counters."""

import json
import os
import threading
import time
from collections import deque
from contextlib import contextmanager
from pathlib import Path


class RateLimitedError(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"rate limited, retry after {retry_after}s")
        self.retry_after = retry_after


class BusyError(Exception):
    pass


class RateLimiter:
    """Sliding-window limiter: at most ``limit`` hits per ``window_s`` per key."""

    MAX_KEYS = 50_000

    def __init__(self, limit: int, window_s: float, clock=time.monotonic):
        self.limit = limit
        self.window_s = window_s
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> None:
        self.reserve(key, 1)

    def _queue(self, key: str, now: float) -> deque[float]:
        if len(self._hits) > self.MAX_KEYS:
            self._gc(now)
        q = self._hits.setdefault(key, deque())
        while q and q[0] <= now - self.window_s:
            q.popleft()
        return q

    def _retry_after(self, q: deque[float], now: float) -> int:
        if not q:
            return 1
        return max(1, int(q[0] + self.window_s - now) + 1)

    def can_admit(self, key: str, n: int, *, now: float) -> tuple[bool, int]:
        """Non-mutating capacity check at ``now``. Never charges hits.

        Returns ``(ok, retry_after)``. Pruning expired entries is allowed; charging
        a reject path via ``reserve`` is not.
        """
        if n < 1:
            return True, 0
        with self._lock:
            q = self._queue(key, now)
            if len(q) + n > self.limit:
                return False, self._retry_after(q, now)
            return True, 0

    def remaining(self, key: str) -> int:
        """How many more hits ``key`` may take in the current window."""
        now = self.clock()
        with self._lock:
            return max(0, self.limit - len(self._queue(key, now)))

    def charged(self, key: str) -> int:
        """Current in-window hit count for tests / diagnostics."""
        now = self.clock()
        with self._lock:
            return len(self._queue(key, now))

    def reserve(self, key: str, n: int, *, now: float | None = None) -> None:
        """Atomically admit ``n`` slots for ``key``, or raise without consuming any.

        Pass the same ``now`` used in a prior ``can_admit`` preflight so expiry is
        deterministic across limiters. Atomic only within this limiter.
        """
        if n < 1:
            return
        ts = self.clock() if now is None else now
        with self._lock:
            q = self._queue(key, ts)
            if len(q) + n > self.limit:
                raise RateLimitedError(self._retry_after(q, ts))
            for _ in range(n):
                q.append(ts)

    def _gc(self, now: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - self.window_s]:
            del self._hits[k]


def admit_all(
    limiters: list[tuple[RateLimiter, str]],
    n: int,
    *,
    now: float,
) -> None:
    """Preflight every limiter at ``now`` without charging; commit only if all pass.

    Rejected admissions leave every limiter's counters unchanged. Successful
    admissions charge exactly once per limiter at the shared timestamp.
    """
    if n < 1:
        return
    for lim, key in limiters:
        ok, retry = lim.can_admit(key, n, now=now)
        if not ok:
            raise RateLimitedError(retry)
    for lim, key in limiters:
        lim.reserve(key, n, now=now)


class Gate:
    """Global cap on concurrent sandbox runs; fails fast instead of queueing."""

    def __init__(self, size: int):
        self.size = size
        self._sem = threading.BoundedSemaphore(size)

    @contextmanager
    def slot(self):
        if not self._sem.acquire(blocking=False):
            raise BusyError()
        try:
            yield
        finally:
            self._sem.release()


class Stats:
    """Arena counters persisted as a small JSON file."""

    FIELDS = ("attempts", "blocked_by_policy", "ran_in_sandbox", "rejected")

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        try:
            data = json.loads(path.read_text())
            self.data = {k: int(data.get(k, 0)) for k in self.FIELDS}
        except (OSError, ValueError):
            self.data = dict.fromkeys(self.FIELDS, 0)

    def bump(self, *fields: str) -> None:
        with self._lock:
            for f in fields:
                self.data[f] += 1
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data))
            os.replace(tmp, self.path)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.data)
