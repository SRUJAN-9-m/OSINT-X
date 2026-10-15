"""Passive domain reconnaissance: DNS, WHOIS/RDAP, certificate transparency,
robots.txt/sitemap/security.txt, and basic security-header inspection.

Everything here is standard passive recon: public DNS queries, public
certificate-transparency logs (crt.sh), RDAP (the modern, official
successor to WHOIS), and reading files a site publishes for exactly this
purpose (robots.txt, security.txt). No scanning, no bypassing anything.
"""
from __future__ import annotations

import json

import dns.resolver

from collectors.base import BaseCollector, unavailable_finding
from database.models import CollectionResult, Confidence, Finding, Source, SourceType
from utils.logger import get_logger
from utils.normalization import normalize_domain

logger = get_logger(__name__)

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]


class DomainCollector(BaseCollector):
    name = "domain"
    source_type = SourceType.DNS.value

    async def collect(self, target: str) -> CollectionResult:
        domain = normalize_domain(target)
        result = CollectionResult(collector=self.name, target=domain)

        result.findings.extend(await self._dns_records(domain))
        result.findings.extend(await self._spf_dmarc(domain))
        result.findings.extend(await self._rdap(domain))
        result.findings.extend(await self._certificate_transparency(domain))
        result.findings.extend(await self._well_known_files(domain))

        return result

    # -- DNS ---------------------------------------------------------------
    async def _dns_records(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        for rtype in _DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                values = sorted({rdata.to_text() for rdata in answers})
                findings.append(
                    Finding(
                        category="domain",
                        label=f"{rtype} record(s)",
                        detail=", ".join(values),
                        entity_key=f"domain:{domain}",
                        sources=[
                            Source(
                                source="Public DNS resolution",
                                url=None,
                                source_type=SourceType.DNS,
                                reliability="official",
                                evidence=f"{rtype} query for {domain}",
                            )
                        ],
                        confidence=Confidence.CONFIRMED,
                        reasoning="Directly resolved from authoritative DNS.",
                    )
                )
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                findings.append(
                    unavailable_finding(
                        "domain", f"{rtype} record(s)", "Domain does not exist (NXDOMAIN)"
                    )
                )
                break
            except Exception as exc:  # timeouts, no nameservers, etc.
                findings.append(
                    unavailable_finding("domain", f"{rtype} record(s)", str(exc))
                )
        return findings

    async def _spf_dmarc(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0

        # SPF lives in TXT records at the apex.
        try:
            txts = resolver.resolve(domain, "TXT")
            spf_records = [
                r.to_text() for r in txts if "v=spf1" in r.to_text().lower()
            ]
            if spf_records:
                findings.append(
                    Finding(
                        category="domain",
                        label="SPF record",
                        detail="; ".join(spf_records),
                        entity_key=f"domain:{domain}",
                        sources=[
                            Source(
                                source="Public DNS resolution",
                                source_type=SourceType.DNS,
                                reliability="official",
                                evidence=f"TXT query for {domain}",
                            )
                        ],
                        confidence=Confidence.CONFIRMED,
                    )
                )
        except Exception as exc:
            findings.append(unavailable_finding("domain", "SPF record", str(exc)))

        # DMARC lives at _dmarc.<domain>.
        try:
            dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = [r.to_text() for r in dmarc]
            findings.append(
                Finding(
                    category="domain",
                    label="DMARC record",
                    detail="; ".join(dmarc_records),
                    entity_key=f"domain:{domain}",
                    sources=[
                        Source(
                            source="Public DNS resolution",
                            source_type=SourceType.DNS,
                            reliability="official",
                            evidence=f"TXT query for _dmarc.{domain}",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            )
        except Exception as exc:
            findings.append(unavailable_finding("domain", "DMARC record", str(exc)))

        return findings

    # -- RDAP / WHOIS --------------------------------------------------------
    async def _rdap(self, domain: str) -> list[Finding]:
        """RDAP is the IANA-standardized, machine-readable successor to
        WHOIS and is queried the same way any registrar/registry expects."""
        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = await self._request("GET", url)
            if resp.status_code != 200:
                return [
                    unavailable_finding(
                        "domain", "RDAP registration data", f"HTTP {resp.status_code}"
                    )
                ]
            data = resp.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            entities = [e.get("handle") for e in data.get("entities", []) if e.get("handle")]
            detail = json.dumps(
                {
                    "status": data.get("status"),
                    "events": events,
                    "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
                    "entity_handles": entities,
                },
                default=str,
            )
            return [
                Finding(
                    category="domain",
                    label="RDAP registration data",
                    detail=detail,
                    entity_key=f"domain:{domain}",
                    sources=[
                        Source(
                            source="RDAP (rdap.org bootstrap)",
                            url=url,
                            source_type=SourceType.WHOIS_RDAP,
                            reliability="official",
                            evidence="RDAP JSON response",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                    reasoning="RDAP is the registry/registrar's own authoritative record.",
                )
            ]
        except Exception as exc:
            logger.info("RDAP lookup failed for %s: %s", domain, exc)
            return [unavailable_finding("domain", "RDAP registration data", str(exc))]

    # -- Certificate transparency --------------------------------------------
    async def _certificate_transparency(self, domain: str) -> list[Finding]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = await self._request("GET", url)
            if resp.status_code != 200:
                return [
                    unavailable_finding(
                        "domain", "Certificate transparency subdomains",
                        f"HTTP {resp.status_code}",
                    )
                ]
            entries = resp.json()
            subdomains = sorted(
                {
                    name.strip().lower()
                    for entry in entries
                    for name in entry.get("name_value", "").split("\n")
                    if name.strip().lower().endswith(domain)
                }
            )
            if not subdomains:
                return []
            return [
                Finding(
                    category="domain",
                    label="Subdomains (certificate transparency)",
                    detail=", ".join(subdomains[:200]),
                    entity_key=f"domain:{domain}",
                    sources=[
                        Source(
                            source="crt.sh certificate transparency log search",
                            url=url,
                            source_type=SourceType.CERTIFICATE_TRANSPARENCY,
                            reliability="official",
                            evidence=f"{len(subdomains)} unique hostnames found in issued certificates",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                    reasoning=(
                        "Hostnames appear in publicly logged TLS certificates; "
                        "this does not confirm the subdomain is currently live."
                    ),
                )
            ]
        except Exception as exc:
            logger.info("crt.sh lookup failed for %s: %s", domain, exc)
            return [
                unavailable_finding(
                    "domain", "Subdomains (certificate transparency)", str(exc)
                )
            ]

    # -- robots.txt / sitemap.xml / security.txt -----------------------------
    async def _well_known_files(self, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        files = [
            ("robots.txt", f"https://{domain}/robots.txt"),
            ("sitemap.xml", f"https://{domain}/sitemap.xml"),
            ("security.txt", f"https://{domain}/.well-known/security.txt"),
        ]
        for label, url in files:
            try:
                resp = await self._request("GET", url)
                if resp.status_code == 200 and resp.text.strip():
                    findings.append(
                        Finding(
                            category="domain",
                            label=f"Published {label}",
                            detail=resp.text[:2000],
                            entity_key=f"domain:{domain}",
                            sources=[
                                Source(
                                    source=f"Publicly published {label}",
                                    url=url,
                                    source_type=SourceType.PUBLIC_WEBSITE,
                                    reliability="official",
                                    evidence=f"HTTP 200 from {url}",
                                )
                            ],
                            confidence=Confidence.CONFIRMED,
                        )
                    )
                else:
                    findings.append(
                        unavailable_finding(
                            "domain", f"Published {label}", f"HTTP {resp.status_code}"
                        )
                    )
            except Exception as exc:
                findings.append(unavailable_finding("domain", f"Published {label}", str(exc)))

        # Security headers on the homepage -- purely observational, read-only.
        try:
            resp = await self._request("GET", f"https://{domain}/")
            headers_of_interest = [
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "server",
                "x-powered-by",
            ]
            present = {
                h: resp.headers[h] for h in headers_of_interest if h in resp.headers
            }
            findings.append(
                Finding(
                    category="domain",
                    label="HTTP security headers (homepage)",
                    detail=json.dumps(present),
                    entity_key=f"domain:{domain}",
                    sources=[
                        Source(
                            source="Direct HTTP response headers",
                            url=f"https://{domain}/",
                            source_type=SourceType.PUBLIC_WEBSITE,
                            reliability="official",
                            evidence="Observed response headers on a single GET request",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            )
        except Exception as exc:
            findings.append(
                unavailable_finding("domain", "HTTP security headers (homepage)", str(exc))
            )

        return findings
