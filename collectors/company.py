"""Company OSINT.

Rather than duplicating logic, this composes the DomainCollector (for the
company's own domain, if provided/discoverable) and GitHub's official org
API (for a GitHub organization matching the company's likely handle). It
is intentionally conservative about "discovering" a company's domain from
just a name -- without a licensed search API (see collectors/search.py)
we do not guess a domain and present it as confirmed.
"""
from __future__ import annotations

from collectors.base import BaseCollector, unavailable_finding
from collectors.domain import DomainCollector
from config import settings
from database.models import CollectionResult, Confidence, Finding, Source, SourceType
from utils.normalization import normalize_domain


class CompanyCollector(BaseCollector):
    name = "company"
    source_type = SourceType.PUBLIC_WEBSITE.value

    async def collect(self, target: str) -> CollectionResult:
        """`target` may be a company name or, ideally, a known domain."""
        result = CollectionResult(collector=self.name, target=target)

        looks_like_domain = "." in target and " " not in target
        if looks_like_domain:
            domain = normalize_domain(target)
            domain_collector = DomainCollector()
            domain_result = await domain_collector.run(domain)
            for f in domain_result.findings:
                f.category = "company"
            result.findings.extend(domain_result.findings)
            await domain_collector.aclose()

            org_findings = await self._github_org(domain.split(".")[0])
            result.findings.extend(org_findings)
        else:
            result.findings.append(
                unavailable_finding(
                    "company",
                    "Company domain discovery",
                    "No domain was provided and no licensed search API is "
                    "configured to reliably resolve a company name to its "
                    "official domain (spec explicitly avoids guessing). "
                    "Re-run with the company's known domain, or configure "
                    "collectors/search.py with a licensed provider.",
                )
            )
            guess = target.lower().replace(" ", "")
            org_findings = await self._github_org(guess)
            result.findings.extend(org_findings)

        return result

    async def _github_org(self, org_guess: str) -> list[Finding]:
        url = f"https://api.github.com/orgs/{org_guess}"
        headers = {"Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        try:
            resp = await self._request("GET", url, headers=headers)
        except Exception as exc:
            return [unavailable_finding("company", "GitHub organization", str(exc))]

        if resp.status_code != 200:
            return [
                unavailable_finding(
                    "company",
                    "GitHub organization",
                    f"No GitHub org found at handle {org_guess!r} (HTTP {resp.status_code}). "
                    "This is only a guess based on the name/domain and may be wrong.",
                )
            ]

        data = resp.json()
        return [
            Finding(
                category="company",
                label="Possible GitHub organization",
                detail=str(
                    {
                        "login": data.get("login"),
                        "name": data.get("name"),
                        "blog": data.get("blog"),
                        "public_repos": data.get("public_repos"),
                        "email": data.get("email"),
                        "location": data.get("location"),
                    }
                ),
                entity_key=f"company:{org_guess}",
                sources=[
                    Source(
                        source="GitHub public REST API",
                        url=data.get("html_url", url),
                        source_type=SourceType.CODE_HOSTING_API,
                        reliability="third-party",
                        evidence="GET /orgs/{org} using a name-derived handle guess",
                    )
                ],
                confidence=Confidence.POSSIBLE,
                reasoning="Org handle was inferred from the company name/domain and not independently confirmed to belong to this company.",
            )
        ]
