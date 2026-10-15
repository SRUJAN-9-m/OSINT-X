"""Email OSINT.

By design this module:
  * normalizes and analyzes the domain part of the address (does it have
    MX records, is it a known free-mail provider, etc.) using the same
    passive DNS technique as DomainCollector.
  * optionally checks HaveIBeenPwned's official API for breach *names and
    dates* only, if HIBP_API_KEY is configured -- it NEVER retrieves or
    stores leaked passwords/credentials, and clearly separates
    "publicly discovered" from "potential breach exposure" per spec.
  * does not scrape arbitrary "people search" sites, which routinely
    aggregate non-public/broker data of uncertain provenance.
"""
from __future__ import annotations

import dns.resolver

from collectors.base import BaseCollector, unavailable_finding
from config import settings
from database.models import CollectionResult, Confidence, Finding, Source, SourceType
from utils.normalization import email_domain, normalize_email

_FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "proton.me", "aol.com", "gmx.com",
}


class EmailCollector(BaseCollector):
    name = "email"
    source_type = SourceType.DNS.value

    async def collect(self, target: str) -> CollectionResult:
        email = normalize_email(target)
        domain = email_domain(email)
        result = CollectionResult(collector=self.name, target=email)

        result.findings.append(self._provider_classification(email, domain))
        result.findings.extend(await self._mx_check(email, domain))
        result.findings.extend(await self._breach_check(email))

        return result

    def _provider_classification(self, email: str, domain: str) -> Finding:
        is_free = domain in _FREE_PROVIDERS
        return Finding(
            category="email",
            label="Provider classification",
            detail=(
                f"{domain} is a well-known free/consumer email provider."
                if is_free
                else f"{domain} does not match a common free-mail provider list "
                "and may be a custom/company domain (unverified)."
            ),
            entity_key=f"email:{email}",
            sources=[
                Source(
                    source="Static free-mail-provider reference list",
                    source_type=SourceType.MANUAL,
                    reliability="third-party",
                    evidence="Domain compared against a known list of consumer webmail providers",
                )
            ],
            confidence=Confidence.SUPPORTED if is_free else Confidence.POSSIBLE,
        )

    async def _mx_check(self, email: str, domain: str) -> list[Finding]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        try:
            answers = resolver.resolve(domain, "MX")
            mx_hosts = sorted(str(r.exchange).rstrip(".") for r in answers)
            return [
                Finding(
                    category="email",
                    label="Mail domain accepts mail (MX present)",
                    detail=", ".join(mx_hosts),
                    entity_key=f"email:{email}",
                    sources=[
                        Source(
                            source="Public DNS resolution",
                            source_type=SourceType.DNS,
                            reliability="official",
                            evidence=f"MX query for {domain}",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            ]
        except dns.resolver.NoAnswer:
            return [
                Finding(
                    category="email",
                    label="No MX records found",
                    detail=f"{domain} has no MX records; mail may be handled by the apex A/AAAA record or the domain does not accept mail.",
                    entity_key=f"email:{email}",
                    sources=[
                        Source(
                            source="Public DNS resolution",
                            source_type=SourceType.DNS,
                            reliability="official",
                            evidence=f"MX query for {domain} returned no records",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            ]
        except Exception as exc:
            return [unavailable_finding("email", "MX record check", str(exc))]

    async def _breach_check(self, email: str) -> list[Finding]:
        """Reports ONLY breach names/dates via the official HIBP API, and
        only if the user has configured a paid API key for it. Never
        fetches or stores actual leaked credentials."""
        if not settings.hibp_api_key:
            return [
                unavailable_finding(
                    "email",
                    "Potential breach exposure (HaveIBeenPwned)",
                    "HIBP_API_KEY not configured -- breach lookup skipped",
                )
            ]
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        try:
            resp = await self._request(
                "GET",
                url,
                headers={
                    "hibp-api-key": settings.hibp_api_key,
                    "User-Agent": settings.user_agent,
                },
                params={"truncateResponse": "true"},
            )
        except Exception as exc:
            return [
                unavailable_finding(
                    "email", "Potential breach exposure (HaveIBeenPwned)", str(exc)
                )
            ]

        if resp.status_code == 404:
            return [
                Finding(
                    category="email",
                    label="Potential breach exposure (HaveIBeenPwned)",
                    detail="No breaches recorded for this address at time of query.",
                    entity_key=f"email:{email}",
                    sources=[
                        Source(
                            source="HaveIBeenPwned official API",
                            url="https://haveibeenpwned.com",
                            source_type=SourceType.BREACH_NOTIFICATION_API,
                            reliability="official",
                            evidence="HTTP 404 = no known breach",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            ]
        if resp.status_code != 200:
            return [
                unavailable_finding(
                    "email",
                    "Potential breach exposure (HaveIBeenPwned)",
                    f"HTTP {resp.status_code}",
                )
            ]

        breach_names = [b["Name"] for b in resp.json()]
        return [
            Finding(
                category="email",
                label="Potential breach exposure (HaveIBeenPwned)",
                detail=(
                    "This address appears in the following publicly-disclosed "
                    f"breach corpora (names/dates only, no credentials retrieved): "
                    f"{', '.join(breach_names)}"
                ),
                entity_key=f"email:{email}",
                sources=[
                    Source(
                        source="HaveIBeenPwned official API",
                        url="https://haveibeenpwned.com",
                        source_type=SourceType.BREACH_NOTIFICATION_API,
                        reliability="official",
                        evidence=f"{len(breach_names)} breach name(s) returned",
                    )
                ],
                confidence=Confidence.CONFIRMED,
                reasoning="This is a 'potential breach exposure' finding, distinct from anything publicly discovered via search -- no passwords or other secrets were retrieved.",
            )
        ]
