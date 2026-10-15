"""JSON report generator."""
from __future__ import annotations

import json

from analyzers.entities import build_graph, graph_to_json
from analyzers.timeline import build_timeline
from database.models import Investigation


def generate_json_report(investigation: Investigation) -> str:
    graph = graph_to_json(build_graph(investigation))
    timeline = build_timeline(investigation)

    payload = {
        "investigation_id": investigation.id,
        "investigator": investigation.investigator,
        "date": investigation.created_at.isoformat(),
        "scope": investigation.scope.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in investigation.findings if not f.unavailable],
        "unverified_or_unavailable": [
            f.model_dump(mode="json") for f in investigation.findings if f.unavailable
        ],
        "relationships": [r.model_dump(mode="json") for r in investigation.relationships],
        "entity_graph": graph,
        "timeline": [
            {**e, "timestamp": e["timestamp"].isoformat()} for e in timeline
        ],
        "sources_consulted": [s.model_dump(mode="json") for s in investigation.sources_consulted],
        "unavailable_sources": investigation.unavailable_sources,
        "limitations": [
            "Findings below CONFIRMED are leads requiring manual verification.",
            "Matching usernames/emails across platforms is correlation, not proof of identity.",
            "Only publicly accessible sources were queried; no authentication, "
            "CAPTCHA, or access control was bypassed.",
        ],
    }
    return json.dumps(payload, indent=2, default=str)
