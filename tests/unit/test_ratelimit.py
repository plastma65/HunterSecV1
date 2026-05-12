"""Unit tests for huntersec.safety.ratelimit.RateLimiter."""

from __future__ import annotations

import asyncio
import time

import pytest

from huntersec.exceptions import RateLimitExceededError
from huntersec.safety.ratelimit import RateLimiter, _TokenBucket


# ── TokenBucket unit tests ────────────────────────────────────────────────────


def test_token_bucket_starts_full() -> None:
    bucket = _TokenBucket(rate=10.0)
    # Should be able to consume up to capacity (rate * 1s burst window)
    consumed = sum(1 for _ in range(10) if bucket.consume())
    assert consumed == 10


def test_token_bucket_denies_after_burst_exhausted() -> None:
    bucket = _TokenBucket(rate=5.0)
    for _ in range(5):
        assert bucket.consume() is True
    assert bucket.consume() is False  # bucket empty


def test_token_bucket_refills_over_time() -> None:
    bucket = _TokenBucket(rate=10.0)
    # Drain all tokens
    while bucket.consume():
        pass
    # Manually advance time by setting last_refill back
    bucket._last_refill -= 1.0
    # After 1 second, should have rate tokens again
    assert bucket.consume() is True


# ── RateLimiter allow / deny ──────────────────────────────────────────────────


def test_rate_limiter_allows_initial_requests() -> None:
    limiter = RateLimiter(global_rps=100.0, per_target_rps=10.0)
    for _ in range(10):
        limiter.consume("192.0.2.1")  # should not raise


def test_rate_limiter_per_target_blocks_burst() -> None:
    """A single target exceeding per_target_rps is denied."""
    limiter = RateLimiter(global_rps=1000.0, per_target_rps=5.0)
    for _ in range(5):
        limiter.consume("192.0.2.1")
    with pytest.raises(RateLimitExceededError, match="Per-target rate limit"):
        limiter.consume("192.0.2.1")


def test_rate_limiter_global_blocks_across_targets() -> None:
    """Multiple targets hitting the global cap are denied."""
    limiter = RateLimiter(global_rps=3.0, per_target_rps=1000.0)
    targets = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    for t in targets:
        limiter.consume(t)
    with pytest.raises(RateLimitExceededError, match="Global rate limit"):
        limiter.consume("192.0.2.4")


def test_rate_limiter_different_targets_have_independent_buckets() -> None:
    limiter = RateLimiter(global_rps=1000.0, per_target_rps=2.0)
    limiter.consume("192.0.2.1")
    limiter.consume("192.0.2.1")
    # Target 1 is exhausted, target 2 should still work
    limiter.consume("192.0.2.2")


def test_rate_limiter_per_target_raises_correct_exception() -> None:
    limiter = RateLimiter(global_rps=1000.0, per_target_rps=1.0)
    limiter.consume("192.0.2.1")
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.consume("192.0.2.1")
    assert "192.0.2.1" in str(exc_info.value)


def test_rate_limiter_global_raises_correct_exception() -> None:
    limiter = RateLimiter(global_rps=1.0, per_target_rps=1000.0)
    limiter.consume("192.0.2.1")
    with pytest.raises(RateLimitExceededError) as exc_info:
        limiter.consume("192.0.2.2")
    assert "Global rate limit" in str(exc_info.value)


def test_rate_limiter_refills_after_waiting() -> None:
    """After the bucket refills, requests should succeed again."""
    limiter = RateLimiter(global_rps=1000.0, per_target_rps=2.0)
    limiter.consume("192.0.2.1")
    limiter.consume("192.0.2.1")

    # Exhaust the bucket; now manually backdate the refill timestamp
    target_bucket = limiter._get_or_create_bucket("192.0.2.1")
    target_bucket._last_refill -= 2.0  # simulate 2 seconds passing

    # Should succeed after refill
    limiter.consume("192.0.2.1")


# ── Async interface ───────────────────────────────────────────────────────────


async def test_rate_limiter_async_consume_allows_requests() -> None:
    limiter = RateLimiter(global_rps=100.0, per_target_rps=10.0)
    await limiter.async_consume("192.0.2.1")


async def test_rate_limiter_async_consume_raises_on_denial() -> None:
    limiter = RateLimiter(global_rps=1000.0, per_target_rps=1.0)
    await limiter.async_consume("192.0.2.1")
    with pytest.raises(RateLimitExceededError):
        await limiter.async_consume("192.0.2.1")


async def test_rate_limiter_async_consume_concurrent_targets() -> None:
    """Concurrent async calls for different targets should not interfere."""
    limiter = RateLimiter(global_rps=1000.0, per_target_rps=10.0)
    targets = [f"192.0.2.{i}" for i in range(1, 6)]
    await asyncio.gather(*[limiter.async_consume(t) for t in targets])
