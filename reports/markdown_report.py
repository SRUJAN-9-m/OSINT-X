"""Markdown report generator, following the 18-section structure from the
spec (section 10)."""
from __future__ import annotations

from datetime import datetime, timezone

from analyzers.timeline import build_timeline
from database.models import Confidence, Finding, Investigation


def _finding_block(f: Finding) -> str:
    src_lines = "\n".join(
        f"  - **Source:** {s.source}  \n"
        f"    **URL:** {s.url or 'n/a'}  \n"
        f"    **Collected:** {s.collected_at.isoformat()}  \n"
        f"    **Reliability:** {s.reliability}  \n"
        f"    **Evidence:** {s.evidence}"
        for s in f.sources
    )
    return (
        f"**Finding:** {f.label}\n\n"
        f"**Evidence:** {f.detail}\n\n"
        f"{src_lines}\n\n"
        f"**Confidence:** {f.confidence.value}\n\n"
        f"**Reasoning:** {f.reasoning or 'n/a'}\n"
    )


def generate_markdown_report(investigation: Investigation) -> str:
    scope = investigation.scope
    findings_by_category: dict[str, list[Finding]] = {}
    for f in investigation.findings:
        findings_by_category.setdefault(f.category, []).append(f)

    confirmed = [f for f in investigation.findings if f.confidence == Confidence.CONFIRMED and not f.unavailable]
    unverified = [f for f in investigation.findings if f.confidence == Confidence.UNVERIFIED and not f.unavailable]
    unavailable = [f for f in investigation.findings if f.unavailable]

    lines: list[str] = []
    lines.append("=" * 50)
    lines.append("OSINT INVESTIGATION REPORT")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"**Investigation ID:** {investigation.id}")
    lines.append(f"**Date:** {investigation.created_at.isoformat()}")
    lines.append(f"**Investigator:** {investigation.investigator}")
    lines.append(f"**Target Scope:** {scope.model_dump(exclude_none=True)}")
    lines.append("")

    lines.append("## 1. Executive Summary")
    lines.append(
        f"{len(investigation.findings)} finding(s) collected across "
        f"{len(findings_by_category)} module(s); {len(confirmed)} confirmed, "
        f"{len(unverified)} unverified, {len(unavailable)} source(s) unavailable."
    )
    lines.append("")

    lines.append("## 2. Target Identifiers")
    for field in ("name", "username", "email", "domain", "company", "url", "ip", "phone", "social_profile_url"):
        val = getattr(scope, field, None)
        if val:
            lines.append(f"- **{field}:** {val}")
    lines.append("")

    section_map = [
        ("3. Social Media Presence", ["username", "social"]),
        ("4. Domain Intelligence", ["domain"]),
        ("5. Email Intelligence", ["email"]),
        ("6. Company Intelligence", ["company"]),
        ("7. GitHub / Developer Intelligence", ["github"]),
        ("8. DNS / Infrastructure Intelligence", ["domain"]),
        ("9. Public Web Presence", ["username", "search", "documents"]),
    ]
    for title, categories in section_map:
        lines.append(f"## {title}")
        items = [f for cat in categories for f in findings_by_category.get(cat, []) if not f.unavailable]
        if not items:
            lines.append("_No confirmed findings in this section._")
        for f in items:
            lines.append(_finding_block(f))
            lines.append("")
        lines.append("")

    lines.append("## 10. Associated Entities")
    lines.append("## 11. Entity Relationship Graph")
    if investigation.relationships:
        for r in investigation.relationships:
            lines.append(
                f"- `{r.from_key}` --[{r.relation_type}]--> `{r.to_key}` "
                f"(confidence: {r.confidence.value}) — {r.explanation}"
            )
    else:
        lines.append("_No relationships established._")
    lines.append("")

    lines.append("## 12. Timeline")
    for event in build_timeline(investigation):
        lines.append(f"- {event['timestamp'].isoformat()} — {event['label']} ({event['source']})")
    lines.append("")

    lines.append("## 13. Important Findings")
    for f in confirmed:
        lines.append(f"- {f.label}: {f.detail[:200]}")
    lines.append("")

    lines.append("## 14. Unverified Findings")
    for f in unverified:
        lines.append(f"- {f.label}: {f.detail[:200]}")
    lines.append("")

    lines.append("## 15. Data Sources")
    seen = set()
    for s in investigation.sources_consulted:
        if s.source not in seen:
            seen.add(s.source)
            lines.append(f"- {s.source} ({s.source_type})")
    lines.append("")

    lines.append("## 16. Limitations")
    lines.append("- Only publicly accessible sources were queried.")
    lines.append("- No authentication, CAPTCHA, paywall, or access control was bypassed.")
    lines.append("- Username/email matches across platforms are leads, not proof of identity.")
    lines.append("- The following sources were unavailable during this run:")
    for u in investigation.unavailable_sources:
        lines.append(f"  - {u['module']} / {u['target']}: {u['error']}")
    lines.append("")

    lines.append("## 17. Collection Timestamp")
    lines.append(datetime.now(timezone.utc).isoformat())
    lines.append("")

    lines.append("## 18. OPSEC / Privacy Notes")
    lines.append(
        "- This report may contain personal data. Handle per your organization's "
        "data protection policy and applicable law."
    )
    lines.append(
        "- Delete this investigation (see API `DELETE` / CLI `--delete`) when it "
        "is no longer needed."
    )
    lines.append("")

    return "\n".join(lines)
