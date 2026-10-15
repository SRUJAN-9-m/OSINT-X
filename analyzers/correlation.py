"""The correlation engine: runs the relevant collectors for an
investigation scope, gathers their findings, and assembles an
`Investigation` object.

Critically, this module never declares two identities (e.g. a username on
platform A and a username on platform B) to be "the same person" purely
because the strings match. A shared username/email only ever produces a
`POSSIBLE`-or-lower relationship with an explanation that it is a lead, not
a conclusion -- upgraded only when a collector itself found corroborating
evidence (e.g. the same platform's own API links two things together).
"""
from __future__ import annotations

import asyncio

from analyzers.confidence import score_relationship
from collectors.base import BaseCollector
from collectors.domain import DomainCollector
from collectors.email import EmailCollector
from collectors.github import GitHubCollector
from collectors.company import CompanyCollector
from collectors.username import UsernameCollector
from database.models import (
    Confidence,
    EntityRelationship,
    Investigation,
    InvestigationScope,
    Source,
    SourceType,
)
from utils.logger import get_logger
from utils.normalization import entity_key, normalize_email, normalize_username

logger = get_logger(__name__)

MODULE_COLLECTORS: dict[str, type[BaseCollector]] = {
    "username": UsernameCollector,
    "email": EmailCollector,
    "domain": DomainCollector,
    "github": GitHubCollector,
    "company": CompanyCollector,
}


async def run_investigation(
    scope: InvestigationScope, investigator: str = "unspecified"
) -> Investigation:
    investigation = Investigation(investigator=investigator, scope=scope)

    tasks: list[tuple[str, str, BaseCollector]] = []
    modules = scope.modules or list(MODULE_COLLECTORS.keys())

    if "username" in modules and scope.username:
        tasks.append(("username", scope.username, UsernameCollector()))
    if "email" in modules and scope.email:
        tasks.append(("email", scope.email, EmailCollector()))
    if "domain" in modules and scope.domain:
        tasks.append(("domain", scope.domain, DomainCollector()))
    if "github" in modules and scope.username:
        tasks.append(("github", scope.username, GitHubCollector()))
    if "company" in modules and scope.company:
        tasks.append(("company", scope.company, CompanyCollector()))

    if not tasks:
        investigation.notes = "No modules ran: scope had no matching identifiers for the requested modules."
        return investigation

    results = await asyncio.gather(*(collector.run(target) for _, target, collector in tasks))

    for (module_name, target, collector), result in zip(tasks, results):
        if not result.available:
            investigation.unavailable_sources.append(
                {"module": module_name, "target": target, "error": result.error}
            )
        investigation.findings.extend(result.findings)
        investigation.relationships.extend(result.relationships)
        for f in result.findings:
            investigation.sources_consulted.extend(f.sources)
        await collector.aclose()

    investigation.relationships.extend(_cross_module_correlations(scope, investigation.findings))
    return investigation


def _cross_module_correlations(scope: InvestigationScope, findings) -> list[EntityRelationship]:
    """Only ever creates cautious, explicitly-labeled correlation
    relationships between identifiers the *user themselves* provided as
    part of one scope -- e.g. "this username and this email were
    investigated together", not "these two things are proven to be the
    same person"."""
    relationships: list[EntityRelationship] = []
    weak_source = Source(
        source="Investigator-provided scope co-occurrence",
        source_type=SourceType.MANUAL,
        reliability="self-reported",
        evidence="Both identifiers were submitted together as part of the same investigation scope.",
    )

    if scope.username and scope.email:
        relationships.append(
            EntityRelationship(
                from_key=entity_key("username", normalize_username(scope.username)),
                to_key=entity_key("email", normalize_email(scope.email)),
                relation_type="investigated_together",
                source=weak_source,
                evidence="Submitted in the same investigation request.",
                confidence=Confidence.UNVERIFIED,
                explanation=(
                    "This link reflects only that the investigator submitted "
                    "these two identifiers together -- it is NOT evidence "
                    "that they belong to the same person unless corroborated "
                    "by an actual source finding above."
                ),
            )
        )
    return relationships
