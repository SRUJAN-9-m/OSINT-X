"""Username presence checks across publicly browsable platforms.

Technique: the same one used by well-known open-source tools such as
Sherlock -- issue a single plain GET/HEAD request to a platform's public
profile URL pattern and look at the HTTP status code (and, for a few
platforms, a "not found" marker string) to decide whether a profile with
that username publicly exists. This does not scrape profile content,
does not log in, and does not bypass any access control.

Because platforms sometimes return 200 for a generic "user not found" page,
each check is intentionally conservative and reports POSSIBLE rather than
CONFIRMED unless the platform's behavior is unambiguous.
"""
from __future__ import annotations

from dataclasses import dataclass

from collectors.base import BaseCollector, unavailable_finding
from database.models import CollectionResult, Confidence, Finding, Source, SourceType
from utils.normalization import normalize_username


@dataclass(frozen=True)
class PlatformCheck:
    platform: str
    url_template: str  # must contain {username}
    not_found_marker: str | None = None  # substring present only on "not found" pages
    method: str = "GET"


# A deliberately small, well-behaved starter set. Add more via the
# `CHECKS` list -- no other code needs to change (open/closed design).
CHECKS: list[PlatformCheck] = [
    PlatformCheck("GitHub", "https://github.com/{username}", "Not Found"),
    PlatformCheck("GitLab", "https://gitlab.com/{username}", "Page Not Found"),
    PlatformCheck("Reddit", "https://www.reddit.com/user/{username}/about.json"),
    PlatformCheck("Stack Overflow (search)", "https://stackoverflow.com/users?tab=all&filter=all&search={username}"),
    PlatformCheck("Medium", "https://medium.com/@{username}"),
    PlatformCheck("Mastodon (mastodon.social)", "https://mastodon.social/@{username}"),
    PlatformCheck("Dev.to", "https://dev.to/{username}"),
    PlatformCheck("Hacker News", "https://news.ycombinator.com/user?id={username}", "No such user"),
]


class UsernameCollector(BaseCollector):
    name = "username"
    source_type = SourceType.PUBLIC_WEBSITE.value

    async def collect(self, target: str) -> CollectionResult:
        username = normalize_username(target)
        result = CollectionResult(collector=self.name, target=username)

        for check in CHECKS:
            url = check.url_template.format(username=username)
            try:
                resp = await self._request(check.method, url, use_cache=True)
            except Exception as exc:
                result.findings.append(
                    unavailable_finding(
                        "username", f"{check.platform} profile check", str(exc)
                    )
                )
                continue

            exists, confidence, reasoning = self._interpret(resp, check)
            if exists is None:
                result.findings.append(
                    unavailable_finding(
                        "username",
                        f"{check.platform} profile check",
                        f"Ambiguous response (HTTP {resp.status_code})",
                    )
                )
                continue

            if exists:
                result.findings.append(
                    Finding(
                        category="username",
                        label=f"Possible profile on {check.platform}",
                        detail=url,
                        entity_key=f"username:{username}",
                        sources=[
                            Source(
                                source=f"{check.platform} public profile page",
                                url=url,
                                source_type=SourceType.PUBLIC_WEBSITE,
                                reliability="third-party",
                                evidence=f"HTTP {resp.status_code}, no 'not found' marker present",
                            )
                        ],
                        confidence=confidence,
                        reasoning=reasoning
                        + " A matching username is a lead, not proof of identity: "
                        "different people commonly use the same handle on "
                        "different platforms.",
                    )
                )
            # If not exists and unambiguous, we simply omit a finding
            # (a negative result isn't reported as a "finding" per se).

        return result

    @staticmethod
    def _interpret(resp, check: PlatformCheck) -> tuple[bool | None, Confidence, str]:
        if resp.status_code == 404:
            return False, Confidence.UNVERIFIED, ""
        if resp.status_code >= 500 or resp.status_code == 429:
            return None, Confidence.UNVERIFIED, ""
        if check.not_found_marker and check.not_found_marker.lower() in resp.text.lower():
            return False, Confidence.UNVERIFIED, ""
        if resp.status_code == 200:
            return (
                True,
                Confidence.POSSIBLE,
                f"HTTP 200 returned for the {check.platform} profile URL.",
            )
        # Anything else (3xx after redirects resolved oddly, 401/403 on a
        # profile that requires login to view fully, etc.) is inconclusive.
        return None, Confidence.UNVERIFIED, ""
