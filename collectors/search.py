"""Search-engine intelligence module.

Per spec: "Use official APIs where available. Do not scrape search engines
aggressively." This project does not bundle a scraper for any search
engine's results page (which would violate most engines' ToS). Instead it
provides a small abstraction you can back with any licensed search API
(Bing Web Search API, SerpAPI, Brave Search API, etc.) by setting
SEARCH_API_KEY / SEARCH_API_PROVIDER in .env and filling in `_call_api`.
"""
from __future__ import annotations

from collectors.base import BaseCollector, unavailable_finding
from config import settings
from database.models import CollectionResult, Confidence, Finding, Source, SourceType


class SearchCollector(BaseCollector):
    name = "search"
    source_type = SourceType.SEARCH_API.value

    async def collect(self, target: str) -> CollectionResult:
        result = CollectionResult(collector=self.name, target=target)

        if not settings.search_api_key or not settings.search_api_provider:
            result.findings.append(
                unavailable_finding(
                    "search",
                    "Search engine intelligence",
                    "No licensed search API configured (SEARCH_API_KEY / "
                    "SEARCH_API_PROVIDER). Configure one to enable this module; "
                    "OSINT-X will not scrape search engine result pages directly.",
                )
            )
            result.available = False
            return result

        # Example of how a real provider would be wired in -- left as an
        # explicit extension point rather than guessing at your provider's
        # exact request/response shape.
        result.findings.append(
            unavailable_finding(
                "search",
                "Search engine intelligence",
                f"SEARCH_API_PROVIDER={settings.search_api_provider!r} is set, but "
                "no request implementation exists yet for this provider. "
                "Implement `_call_api` in collectors/search.py against your "
                "provider's documented endpoint.",
            )
        )
        return result

    async def _call_api(self, query: str) -> list[Finding]:
        """Implement against your licensed provider's documented API and
        return real Findings with a Source pointing at that API. Left
        unimplemented deliberately -- provider request/response shapes and
        licensing terms vary too much to guess safely."""
        raise NotImplementedError
