"""Builds the entity relationship graph (spec section 9) from an
investigation's findings and relationships, using networkx."""
from __future__ import annotations

import networkx as nx

from database.models import Investigation


def build_graph(investigation: Investigation) -> nx.DiGraph:
    graph = nx.DiGraph()

    for finding in investigation.findings:
        if finding.entity_key:
            graph.add_node(finding.entity_key, kind=finding.entity_key.split(":")[0])

    for rel in investigation.relationships:
        graph.add_node(rel.from_key, kind=rel.from_key.split(":")[0])
        graph.add_node(rel.to_key, kind=rel.to_key.split(":")[0])
        graph.add_edge(
            rel.from_key,
            rel.to_key,
            relation_type=rel.relation_type,
            confidence=rel.confidence.value,
            evidence=rel.evidence,
            explanation=rel.explanation,
        )

    return graph


def graph_to_json(graph: nx.DiGraph) -> dict:
    return {
        "nodes": [
            {"id": n, "kind": data.get("kind", "unknown")}
            for n, data in graph.nodes(data=True)
        ],
        "edges": [
            {
                "from": u,
                "to": v,
                "relation_type": data.get("relation_type"),
                "confidence": data.get("confidence"),
                "evidence": data.get("evidence"),
                "explanation": data.get("explanation"),
            }
            for u, v, data in graph.edges(data=True)
        ],
    }
