"""Social-media adapters.

Platforms with an official public API for reading public data (documented,
rate-limited, ToS-compliant) get a real adapter here. Platforms that only
expose data through logged-in-only interfaces, or whose Terms of Service
prohibit automated collection even of public pages (this commonly includes
LinkedIn, Instagram, TikTok, Facebook, X/Twitter's modern API tiers), are
represented as `NotConfiguredAdapter` stubs: they always report themselves
`unavailable` with a clear reason, rather than scraping in a way that could
violate ToS or produce unreliable, easily-broken results.

If you hold a legitimate, ToS-compliant API credential for one of these
(e.g. a licensed data-partner agreement), implement `collect()` on a new
subclass of `BaseCollector` and register it in `ADAPTERS` below -- nothing
else in the engine needs to change.
"""
from __future__ import annotations

from collectors.base import BaseCollector
from database.models import CollectionResult
from database.models import Confidence  # noqa: F401  (kept for adapter authors)


class NotConfiguredAdapter(BaseCollector):
    """A platform adapter that is intentionally not implemented because
    reliable, ToS-compliant public access isn't available without a
    specific licensed credential this project doesn't assume you have."""

    def __init__(self, platform: str, reason: str):
        super().__init__()
        self.name = f"social:{platform.lower()}"
        self.platform = platform
        self.reason = reason

    async def collect(self, target: str) -> CollectionResult:
        result = CollectionResult(collector=self.name, target=target, available=False)
        result.error = self.reason
        return result


ADAPTERS: dict[str, BaseCollector] = {
    "linkedin": NotConfiguredAdapter(
        "LinkedIn",
        "LinkedIn's Terms of Service prohibit automated scraping of profiles; "
        "no adapter is implemented. Use LinkedIn's official Talent/Marketing "
        "APIs if you hold a partnership, or collect manually/consensually.",
    ),
    "instagram": NotConfiguredAdapter(
        "Instagram",
        "Instagram's platform policies restrict automated profile scraping; "
        "no adapter is implemented. Use the official Instagram Graph API for "
        "content you/your client own or manage.",
    ),
    "tiktok": NotConfiguredAdapter(
        "TikTok",
        "No ToS-compliant public scraping method is bundled; implement via "
        "TikTok's official Research/Display API if you hold access.",
    ),
    "twitter_x": NotConfiguredAdapter(
        "X/Twitter",
        "Requires a paid X API tier; not configured by default. Add your "
        "bearer token and implement this adapter against the official API.",
    ),
    "youtube": NotConfiguredAdapter(
        "YouTube",
        "Requires a Google/YouTube Data API key; not configured by default.",
    ),
}


async def collect_all(target: str) -> list[CollectionResult]:
    return [await adapter.run(target) for adapter in ADAPTERS.values()]
