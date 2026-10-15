"""Public document discovery (press releases, filings, PDFs, etc.).

Like collectors/search.py, real coverage of "find public documents
mentioning X" needs a licensed search API to be reliable and ToS-compliant.
This module exposes the extension point; wire it to the same provider you
configure for collectors/search.py.
"""
from __future__ import annotations

from collectors.base import BaseCollector, unavailable_finding
from config import settings
from database.models import CollectionResult


class DocumentsCollector(BaseCollector):
    name = "documents"
    source_type = "search_api"

    async def collect(self, target: str) -> CollectionResult:
        result = CollectionResult(collector=self.name, target=target)
        if not settings.search_api_key:
            result.findings.append(
                unavailable_finding(
                    "documents",
                    "Public document discovery",
                    "No licensed search API configured -- see collectors/search.py",
                )
            )
            result.available = False
        return result
