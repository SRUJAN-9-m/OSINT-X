"""Confidence scoring rules (spec section 15).

Confidence is attached to *source correlation* only -- never used to imply
anything about a person's sensitive characteristics. These helpers score
how well-supported a piece of correlation evidence is, given how many
independent sources back it and how reliable those sources are.
"""
from __future__ import annotations

from database.models import Confidence, Source

_RELIABLE_TYPES = {"official"}


def score_relationship(sources: list[Source]) -> Confidence:
    """Given the sources backing one relationship/finding, decide its
    confidence tier."""
    if not sources:
        return Confidence.UNVERIFIED

    reliable_count = sum(1 for s in sources if s.reliability in _RELIABLE_TYPES)
    distinct_sources = len({s.source for s in sources})

    if reliable_count >= 1 and distinct_sources == 1:
        return Confidence.CONFIRMED
    if distinct_sources >= 2:
        return Confidence.SUPPORTED
    if distinct_sources == 1:
        return Confidence.POSSIBLE
    return Confidence.UNVERIFIED


def merge_confidence(existing: Confidence, new: Confidence) -> Confidence:
    """When the same fact is corroborated again, confidence can only move
    up the ladder, never be silently downgraded by a weaker duplicate."""
    order = [Confidence.UNVERIFIED, Confidence.POSSIBLE, Confidence.SUPPORTED, Confidence.CONFIRMED]
    return order[max(order.index(existing), order.index(new))]
