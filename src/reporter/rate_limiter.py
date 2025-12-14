"""Rate limiting utilities for abuse reporters."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RateLimiter:
    """
    Token bucket rate limiter for API calls.

    Allows bursting up to `burst_size` requests, then enforces
    `requests_per_minute` rate.
    """

    requests_per_minute: int = 60
    burst_size: int = 10
    _tokens: float = field(init=False)
    _last_update: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self):
        self._tokens = float(self.burst_size)
        self._last_update = time.monotonic()

    def _refill(self) -> None:
        """Refill tokens based on time elapsed."""
        now = time.monotonic()
        elapsed = now - self._last_update
        self._last_update = now

        # Add tokens based on time elapsed (tokens per second)
        tokens_per_second = self.requests_per_minute / 60.0
        self._tokens = min(self.burst_size, self._tokens + elapsed * tokens_per_second)

    async def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire a token, waiting if necessary.

        Args:
            timeout: Maximum time to wait in seconds. None = wait forever.

        Returns:
            True if token acquired, False if timed out.
        """
        deadline = (time.monotonic() + float(timeout)) if timeout is not None else None

        while True:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                if remaining is None:
                    await self._lock.acquire()
                else:
                    await asyncio.wait_for(self._lock.acquire(), timeout=remaining)
            except asyncio.TimeoutError:
                return False

            try:
                self._refill()

                if self._tokens >= 1:
                    self._tokens -= 1
                    return True

                tokens_per_second = self.requests_per_minute / 60.0
                wait_time = float("inf") if tokens_per_second <= 0 else (1 - self._tokens) / tokens_per_second
            finally:
                self._lock.release()

            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait_time = min(wait_time, remaining)

            await asyncio.sleep(max(0.0, wait_time))

    def can_proceed(self) -> bool:
        """Check if a request can proceed immediately without waiting."""
        self._refill()
        return self._tokens >= 1

    def wait_time(self) -> float:
        """Get estimated wait time until next token is available."""
        self._refill()
        if self._tokens >= 1:
            return 0.0
        tokens_per_second = self.requests_per_minute / 60.0
        return (1 - self._tokens) / tokens_per_second

    def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        self._tokens = float(self.burst_size)
        self._last_update = time.monotonic()


class RateLimiterRegistry:
    """Registry of rate limiters for different platforms."""

    def __init__(self):
        self._limiters: dict[str, RateLimiter] = {}

    def get(
        self,
        platform: str,
        requests_per_minute: int = 60,
        burst_size: int = 10,
    ) -> RateLimiter:
        """Get or create a rate limiter for a platform."""
        if platform not in self._limiters:
            self._limiters[platform] = RateLimiter(
                requests_per_minute=requests_per_minute,
                burst_size=burst_size,
            )
        return self._limiters[platform]

    def reset(self, platform: str) -> None:
        """Reset a specific platform's rate limiter."""
        if platform in self._limiters:
            self._limiters[platform].reset()

    def reset_all(self) -> None:
        """Reset all rate limiters."""
        for limiter in self._limiters.values():
            limiter.reset()


# Global registry instance
_registry = RateLimiterRegistry()


def get_rate_limiter(
    platform: str,
    requests_per_minute: int = 60,
    burst_size: int = 10,
) -> RateLimiter:
    """Get the rate limiter for a platform from the global registry."""
    return _registry.get(platform, requests_per_minute, burst_size)
