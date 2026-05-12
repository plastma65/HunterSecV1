"""Token-bucket rate limiter — per-target and global.

Thread-safe via :class:`threading.Lock`; safe to call from async code
(lock hold time is sub-millisecond, so event-loop stalls are negligible
for this use case).  An ``async_consume`` method is provided for callers
inside ``async`` functions so they can ``await`` the check without
spin-blocking the event loop.

Two buckets are maintained per :class:`RateLimiter` instance:

* **global** — shared across all targets, capacity = ``global_rps`` tokens.
* **per-target** — one bucket per target string, capacity =
  ``per_target_rps`` tokens.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Final

from huntersec.exceptions import RateLimitExceededError

_BURST_WINDOW: Final[float] = 1.0  # burst capacity = 1 second worth of tokens


@dataclass
class _TokenBucket:
    """Single token bucket; not for direct external use."""

    rate: float  # tokens refilled per second
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self._tokens = self.rate * _BURST_WINDOW
        self._last_refill = time.monotonic()

    @property
    def capacity(self) -> float:
        """Maximum tokens the bucket can hold."""
        return self.rate * _BURST_WINDOW

    def consume(self) -> bool:
        """Attempt to consume one token atomically.

        Returns:
            True if a token was available and consumed; False if rate-limited.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._last_refill = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class RateLimiter:
    """Dual-bucket rate limiter: per-target + global.

    Args:
        global_rps: Maximum combined requests per second across all targets.
        per_target_rps: Maximum requests per second for a single target.

    Example:
        >>> limiter = RateLimiter(global_rps=100.0, per_target_rps=10.0)
        >>> limiter.consume("192.0.2.1")  # raises RateLimitExceededError if over limit
    """

    def __init__(self, global_rps: float, per_target_rps: float) -> None:
        self._global_rps = global_rps
        self._per_target_rps = per_target_rps
        self._global_bucket = _TokenBucket(rate=global_rps)
        self._target_buckets: dict[str, _TokenBucket] = {}
        self._buckets_lock = threading.Lock()

    def _get_or_create_bucket(self, target: str) -> _TokenBucket:
        with self._buckets_lock:
            if target not in self._target_buckets:
                self._target_buckets[target] = _TokenBucket(rate=self._per_target_rps)
            return self._target_buckets[target]

    def consume(self, target: str) -> None:
        """Consume one token for the given target. Thread-safe.

        Checks global limit first, then per-target limit.  If either bucket is
        empty, raises immediately (non-blocking — callers must back off).

        Args:
            target: Identifier for the target being rated (IP, hostname, …).

        Raises:
            RateLimitExceededError: If global or per-target rate is exceeded.
        """
        if not self._global_bucket.consume():
            raise RateLimitExceededError(
                f"Global rate limit exceeded ({self._global_rps} RPS). "
                f"Request for target {target!r} denied."
            )
        bucket = self._get_or_create_bucket(target)
        if not bucket.consume():
            raise RateLimitExceededError(
                f"Per-target rate limit exceeded ({self._per_target_rps} RPS) "
                f"for target {target!r}."
            )

    async def async_consume(self, target: str) -> None:
        """Async-compatible wrapper around :meth:`consume`.

        Delegates to :func:`asyncio.to_thread` so the event loop is not blocked
        while the (sub-millisecond) lock is held.

        Args:
            target: Identifier for the target being rated.

        Raises:
            RateLimitExceededError: If rate exceeded (propagated from sync path).
        """
        await asyncio.to_thread(self.consume, target)
