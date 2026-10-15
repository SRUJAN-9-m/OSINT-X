"""GitHub / code-hosting OSINT via GitHub's official public REST API.

Only public, unauthenticated-readable endpoints are used. A token (if
configured) is used solely to raise the rate limit -- never to access
anything private.

Secret scanning: if the user explicitly points this collector at a
repository they are authorized to investigate, `scan_repo_for_secrets`
does a shallow pattern-based scan of *public* file content already
returned by the API and never prints the actual secret value -- only the
file path and a generic secret-type label, per spec section 6.
"""
from __future__ import annotations

import re

from collectors.base import BaseCollector, unavailable_finding
from config import settings
from database.models import (
    CollectionResult,
    Confidence,
    EntityRelationship,
    Finding,
    Source,
    SourceType,
)
from utils.normalization import normalize_username

_SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
}


class GitHubCollector(BaseCollector):
    name = "github"
    source_type = SourceType.CODE_HOSTING_API.value
    api_base = "https://api.github.com"

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        return headers

    async def collect(self, target: str) -> CollectionResult:
        username = normalize_username(target)
        result = CollectionResult(collector=self.name, target=username)

        profile = await self._profile(username)
        result.findings.extend(profile[0])
        result.relationships.extend(profile[1])

        result.findings.extend(await self._orgs(username))
        result.findings.extend(await self._repos_and_emails(username, result))

        return result

    async def _profile(self, username: str) -> tuple[list[Finding], list[EntityRelationship]]:
        url = f"{self.api_base}/users/{username}"
        try:
            resp = await self._request("GET", url, headers=self._headers())
        except Exception as exc:
            return [unavailable_finding("github", "GitHub profile", str(exc))], []

        if resp.status_code == 404:
            return [], []
        if resp.status_code != 200:
            return [
                unavailable_finding("github", "GitHub profile", f"HTTP {resp.status_code}")
            ], []

        data = resp.json()
        src = Source(
            source="GitHub public REST API",
            url=data.get("html_url", url),
            source_type=SourceType.CODE_HOSTING_API,
            reliability="official",
            evidence="GET /users/{username}",
        )
        detail_fields = {
            "name": data.get("name"),
            "bio": data.get("bio"),
            "company": data.get("company"),
            "blog": data.get("blog"),
            "location": data.get("location"),
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "created_at": data.get("created_at"),
        }
        finding = Finding(
            category="github",
            label="GitHub profile",
            detail=str({k: v for k, v in detail_fields.items() if v is not None}),
            entity_key=f"username:{username}",
            sources=[src],
            confidence=Confidence.CONFIRMED,
            reasoning="Directly returned by GitHub's official API for this exact username.",
        )
        relationships = []
        if data.get("blog"):
            relationships.append(
                EntityRelationship(
                    from_key=f"username:{username}",
                    to_key=f"website:{data['blog']}",
                    relation_type="lists_website_on_profile",
                    source=src,
                    evidence=f"GitHub profile 'blog' field = {data['blog']}",
                    confidence=Confidence.SUPPORTED,
                    explanation="The account owner published this link on their own public profile.",
                )
            )
        return [finding], relationships

    async def _orgs(self, username: str) -> list[Finding]:
        url = f"{self.api_base}/users/{username}/orgs"
        try:
            resp = await self._request("GET", url, headers=self._headers())
        except Exception as exc:
            return [unavailable_finding("github", "GitHub organizations", str(exc))]
        if resp.status_code != 200:
            return []
        orgs = [o["login"] for o in resp.json()]
        if not orgs:
            return []
        return [
            Finding(
                category="github",
                label="Public GitHub organization memberships",
                detail=", ".join(orgs),
                entity_key=f"username:{username}",
                sources=[
                    Source(
                        source="GitHub public REST API",
                        url=url,
                        source_type=SourceType.CODE_HOSTING_API,
                        reliability="official",
                        evidence="GET /users/{username}/orgs (public memberships only)",
                    )
                ],
                confidence=Confidence.CONFIRMED,
            )
        ]

    async def _repos_and_emails(self, username: str, result: CollectionResult) -> list[Finding]:
        url = f"{self.api_base}/users/{username}/repos"
        try:
            resp = await self._request(
                "GET", url, headers=self._headers(), params={"per_page": 20, "sort": "updated"}
            )
        except Exception as exc:
            return [unavailable_finding("github", "GitHub repositories", str(exc))]
        if resp.status_code != 200:
            return []

        repos = resp.json()
        findings: list[Finding] = []
        if repos:
            names = ", ".join(r["full_name"] for r in repos)
            findings.append(
                Finding(
                    category="github",
                    label="Public repositories (most recently updated, up to 20)",
                    detail=names,
                    entity_key=f"username:{username}",
                    sources=[
                        Source(
                            source="GitHub public REST API",
                            url=url,
                            source_type=SourceType.CODE_HOSTING_API,
                            reliability="official",
                            evidence="GET /users/{username}/repos",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                )
            )

        # Public commit-author emails: only from commits already public on
        # GitHub -- this surfaces information the author already chose to
        # make public in their git config, it does not defeat any privacy
        # control GitHub offers (e.g. "keep my email private" hides it here too).
        emails_found: set[str] = set()
        for repo in repos[:5]:  # keep this light and rate-limit-friendly
            commits_url = f"{self.api_base}/repos/{repo['full_name']}/commits"
            try:
                cresp = await self._request(
                    "GET", commits_url, headers=self._headers(), params={"per_page": 5}
                )
            except Exception:
                continue
            if cresp.status_code != 200:
                continue
            for commit in cresp.json():
                author = (commit.get("commit") or {}).get("author") or {}
                email = author.get("email")
                if email and "users.noreply.github.com" not in email:
                    emails_found.add(email)

        if emails_found:
            findings.append(
                Finding(
                    category="github",
                    label="Email address(es) exposed in public commit history",
                    detail=", ".join(sorted(emails_found)),
                    entity_key=f"username:{username}",
                    sources=[
                        Source(
                            source="GitHub public REST API (commit metadata)",
                            source_type=SourceType.CODE_HOSTING_API,
                            reliability="official",
                            evidence="Author email field on publicly visible commits",
                        )
                    ],
                    confidence=Confidence.CONFIRMED,
                    reasoning=(
                        "These addresses are embedded in git commit metadata the "
                        "author pushed to a public repository; GitHub's "
                        "'keep my email private' setting, if enabled, prevents "
                        "this by rewriting the author to a noreply address."
                    ),
                )
            )
        return findings


def scan_text_for_secrets(file_path: str, content: str) -> list[Finding]:
    """Pattern-based secret scan of already-public file content.

    Never includes the secret value itself in the output -- only the file
    path and a generic type label, per spec section 6. Intended for use
    only against repositories the investigator is explicitly authorized to
    review.
    """
    findings: list[Finding] = []
    for label, pattern in _SECRET_PATTERNS.items():
        if pattern.search(content):
            findings.append(
                Finding(
                    category="github",
                    label="Potential secret detected (redacted)",
                    detail=f"Possible {label} found in {file_path}. Value redacted.",
                    sources=[
                        Source(
                            source="Static pattern scan of authorized repository content",
                            source_type=SourceType.CODE_HOSTING_API,
                            reliability="third-party",
                            evidence=f"Regex match for {label} pattern in {file_path}",
                        )
                    ],
                    confidence=Confidence.POSSIBLE,
                    reasoning="Pattern match only; verify manually before taking action. Value intentionally not disclosed.",
                )
            )
    return findings
