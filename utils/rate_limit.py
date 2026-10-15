"""A simple async per-host token-bucket rate limiter.

Every collector routes its outbound requests through this so OSINT-X never
hammers a third-party service, regardless of how many collectors are
running concurrently.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from urllib.parse import urlparse

from config import settings


class _HostBucket:
    def __init__(self, per_minute: int) -> None:
        self.capacity = max(per_minute, 1)
        self.tokens = float(self.capacity)
        self.per_minute = self.capacity
        self.updated_at = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated_at
            self.tokens = min(
                self.capacity, self.tokens + elapsed * (self.per_minute / 60.0)
            )
            self.updated_at = now
            if self.tokens < 1:
                wait = (1 - self.tokens) * (60.0 / self.per_minute)
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


class RateLimiter:
    def __init__(self, per_minute: int | None = None) -> None:
        self.per_minute = per_minute or settings.rate_limit_per_host_per_minute
        self._buckets: dict[str, _HostBucket] = defaultdict(
            lambda: _HostBucket(self.per_minute)
        )

    async def wait_for(self, url: str) -> None:
        host = urlparse(url).netloc or url
        await self._buckets[host].acquire()


rate_limiter = RateLimiter()
