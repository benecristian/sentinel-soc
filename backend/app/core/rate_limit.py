"""In-memory fixed-window rate limiter.

Why rate limiting: login, upload and simulation endpoints are the most abusable
surfaces. Login without a limit allows online password guessing. Upload and
simulation are CPU and storage heavy, so they are a denial-of-service lever.

Limitation (documented in SECURITY.md): counters live in process memory. That is
correct for the single-process deployment used here. A multi-worker or
multi-node deployment would need a shared store such as Redis.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class _Window:
    started_at: float
    count: int


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


class FixedWindowRateLimiter:
    """Thread-safe fixed-window counter keyed by arbitrary strings."""

    _PRUNE_THRESHOLD = 10_000

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int) -> RateLimitResult:
        now = self._clock()
        with self._lock:
            if len(self._windows) > self._PRUNE_THRESHOLD:
                self._prune(now, window_seconds)

            window = self._windows.get(key)
            if window is None or now - window.started_at >= window_seconds:
                window = _Window(started_at=now, count=0)
                self._windows[key] = window

            if window.count >= limit:
                retry_after = math.ceil(window_seconds - (now - window.started_at))
                return RateLimitResult(allowed=False, remaining=0, retry_after_seconds=retry_after)

            window.count += 1
            return RateLimitResult(
                allowed=True, remaining=limit - window.count, retry_after_seconds=0
            )

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()

    def _prune(self, now: float, window_seconds: int) -> None:
        expired = [k for k, w in self._windows.items() if now - w.started_at >= window_seconds]
        for key in expired:
            del self._windows[key]
