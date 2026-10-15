"""Input validation for every target type OSINT-X accepts."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$"
)
_PHONE_RE = re.compile(r"^\+?[0-9()\-.\s]{7,20}$")


class ValidationError(ValueError):
    pass


def validate_username(value: str) -> str:
    value = value.strip()
    if not _USERNAME_RE.match(value):
        raise ValidationError(f"Invalid username format: {value!r}")
    return value


def validate_email(value: str) -> str:
    value = value.strip()
    if not _EMAIL_RE.match(value):
        raise ValidationError(f"Invalid email format: {value!r}")
    return value.lower()


def validate_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    value = re.sub(r"^https?://", "", value).split("/")[0]
    if not _DOMAIN_RE.match(value):
        raise ValidationError(f"Invalid domain format: {value!r}")
    return value


def validate_ip(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"Invalid IP address: {value!r}") from exc
    return value


def validate_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValidationError(f"Invalid URL: {value!r}")
    return value


def validate_phone(value: str) -> str:
    value = value.strip()
    if not _PHONE_RE.match(value):
        raise ValidationError(f"Invalid phone number format: {value!r}")
    return value


def validate_company_name(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 256:
        raise ValidationError("Company name must be 1-256 characters")
    return value
