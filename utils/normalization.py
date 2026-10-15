"""Normalization helpers so the same identifier always keys the same
entity-graph node, regardless of how it was typed in."""
from __future__ import annotations

from urllib.parse import urlparse


def normalize_email(email: str) -> str:
    local, _, domain = email.strip().lower().partition("@")
    return f"{local}@{domain}"


def email_domain(email: str) -> str:
    return normalize_email(email).split("@", 1)[1]


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).netloc
    if d.startswith("www."):
        d = d[4:]
    return d


def normalize_username(username: str) -> str:
    return username.strip().lstrip("@")


def entity_key(kind: str, value: str) -> str:
    """Canonical key for a node in the entity relationship graph."""
    return f"{kind}:{value.strip().lower()}"
