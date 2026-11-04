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
        now = self.clock()
        with self._lock:
            if len(self._hits) > self.MAX_KEYS:
                self._gc(now)
            q = self._hits.setdefault(key, deque())
            while q and q[0] <= now - self.window_s:
                q.popleft()
            if len(q) >= self.limit:
                raise RateLimitedError(max(1, int(q[0] + self.window_s - now) + 1))
            q.append(now)

    def _gc(self, now: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or q[-1] <= now - self.window_s]:
            del self._hits[k]


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
