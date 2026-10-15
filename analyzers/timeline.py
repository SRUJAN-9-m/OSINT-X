"""Builds a simple chronological timeline of collection events for the
report's Timeline section. This orders *when things were collected/found*,
not a claimed timeline of the target's real-world life -- OSINT-X never
infers real-world event dates that a source didn't state explicitly."""
from __future__ import annotations

from database.models import Investigation


def build_timeline(investigation: Investigation) -> list[dict]:
    events = []
    for f in investigation.findings:
        if f.unavailable:
            continue
        for s in f.sources:
            events.append(
                {
                    "timestamp": s.collected_at,
                    "label": f.label,
                    "source": s.source,
                    "confidence": f.confidence.value,
                }
            )
    events.sort(key=lambda e: e["timestamp"])
    return events
