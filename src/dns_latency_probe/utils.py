from __future__ import annotations

import threading
import time


class RateLimiter:
    """Simple monotonic rate limiter with deterministic stepping."""

    def __init__(self, rate_per_second: float) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")
        self._interval = 1.0 / rate_per_second
        self._next_deadline = time.monotonic()
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next_deadline:
                time.sleep(self._next_deadline - now)
                now = time.monotonic()
            self._next_deadline = max(self._next_deadline + self._interval, now)
