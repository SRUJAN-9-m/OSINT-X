"""Common interface and shared HTTP plumbing for every collector/adapter.

Design goals (per spec section 12/13/19):
  * Every external source is its own adapter.
  * The engine keeps working if one adapter is unavailable.
  * Requests are rate-limited, timed out, retried with backoff, and sent
    with an identifiable User-Agent.
  * Nothing here ever attempts to bypass auth/CAPTCHA/paywalls -- collectors
    only ever issue plain GET/HEAD requests to public URLs or official APIs.
"""
from __future__ import annotations

import abc
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import settings
from database.models import CollectionResult, Finding
from utils.logger import get_logger
from utils.rate_limit import rate_limiter

logger = get_logger(__name__)

_cache: dict[str, tuple[float, httpx.Response]] = {}
_CACHE_TTL_SECONDS = 300


class BaseCollector(abc.ABC):
    """Subclass this for every new OSINT source."""

    name: str = "base"
    source_type: str = "public_website"

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                headers={"User-Agent": settings.user_agent},
                follow_redirects=True,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=6),
        retry=retry_if_exception_type(
            (httpx.TransportError, httpx.HTTPStatusError)
        ),
    )
    async def _request(
        self, method: str, url: str, use_cache: bool = True, **kwargs
    ) -> httpx.Response:
        """Rate-limited, retried, timed-out, cached HTTP request.

        Only ever used for plain public GET/HEAD requests or documented
        official-API calls -- never for bypassing auth or access controls.
        """
        cache_key = f"{method}:{url}:{kwargs.get('params')}"
        if use_cache and cache_key in _cache:
            ts, resp = _cache[cache_key]
            if time.monotonic() - ts < _CACHE_TTL_SECONDS:
                return resp

        await rate_limiter.wait_for(url)
        client = await self._get_client()
        resp = await client.request(method, url, **kwargs)
        if use_cache:
            _cache[cache_key] = (time.monotonic(), resp)
        return resp

    @abc.abstractmethod
    async def collect(self, target: str) -> CollectionResult:
        """Run this collector against `target`. Must never raise -- catch
        internally and return `available=False, error=...` instead, so one
        failing source never breaks the rest of the investigation."""
        raise NotImplementedError

    async def run(self, target: str) -> CollectionResult:
        result = CollectionResult(collector=self.name, target=target)
        try:
            result = await self.collect(target)
        except Exception as exc:  # never let one collector break the run
            logger.warning("Collector %s failed for %r: %s", self.name, target, exc)
            result.available = False
            result.error = str(exc)
        finally:
            result.finished_at = datetime.now(timezone.utc)
        return result


def unavailable_finding(category: str, label: str, reason: str) -> Finding:
    """Helper: build a Finding that clearly marks a source as unavailable
    rather than silently omitting it (spec requirement: never fabricate,
    always report unavailable sources)."""
    return Finding(
        category=category,
        label=label,
        detail="Source unavailable.",
        sources=[],
        unavailable=True,
        unavailable_reason=reason,
    )
