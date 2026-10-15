"""Core data models shared across the whole platform.

Two layers live here:
  * Pydantic models -- what collectors/analyzers/reports pass around in memory.
  * SQLAlchemy ORM models -- how an investigation is persisted.

A `Finding` is never allowed to exist without a `Source`. This is enforced
by `Finding` requiring a non-empty `source` field at construction time.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


# --------------------------------------------------------------------------
# Confidence system (section 15 of the spec)
# --------------------------------------------------------------------------
class Confidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"    # directly supported by a reliable source
    SUPPORTED = "SUPPORTED"    # supported by multiple independent sources
    POSSIBLE = "POSSIBLE"      # indicators exist, insufficient evidence
    UNVERIFIED = "UNVERIFIED"  # could not be independently confirmed


class SourceType(str, enum.Enum):
    OFFICIAL_API = "official_api"
    PUBLIC_WEBSITE = "public_website"
    DNS = "dns"
    WHOIS_RDAP = "whois_rdap"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    CODE_HOSTING_API = "code_hosting_api"
    SEARCH_API = "search_api"
    BREACH_NOTIFICATION_API = "breach_notification_api"
    MANUAL = "manual"


# --------------------------------------------------------------------------
# Pydantic (in-memory / API) models
# --------------------------------------------------------------------------
class Source(BaseModel):
    """Every finding must carry one of these. Never fabricate one."""

    source: str
    url: Optional[str] = None
    source_type: SourceType
    collected_at: datetime = Field(default_factory=utcnow)
    reliability: str = "unknown"  # e.g. "official", "third-party", "self-reported"
    evidence: str = ""

    @field_validator("source")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Source.source must not be empty")
        return v


class Finding(BaseModel):
    id: str = Field(default_factory=new_id)
    investigation_id: Optional[str] = None
    category: str  # e.g. "username", "email", "domain", "github", "social"
    label: str  # short human-readable name, e.g. "GitHub profile found"
    detail: str  # the actual finding text
    entity_key: Optional[str] = None  # which entity node this attaches to
    unavailable: bool = False  # True if the *attempt* to collect this failed
    unavailable_reason: Optional[str] = None
    sources: list[Source] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNVERIFIED
    reasoning: str = ""
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("sources")
    @classmethod
    def _must_have_source_unless_unavailable(
        cls, v: list[Source], info
    ) -> list[Source]:
        unavailable = info.data.get("unavailable", False)
        if not unavailable and not v:
            raise ValueError(
                "Finding must have at least one Source (or be marked unavailable=True)"
            )
        return v


class EntityRelationship(BaseModel):
    """An edge in the entity graph (section 9 of the spec)."""

    id: str = Field(default_factory=new_id)
    from_key: str
    to_key: str
    relation_type: str  # e.g. "uses_username", "controls_domain", "owns_repo"
    source: Source
    evidence: str
    confidence: Confidence = Confidence.UNVERIFIED
    explanation: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class CollectionResult(BaseModel):
    """What every collector returns from `.collect()`."""

    collector: str
    target: str
    findings: list[Finding] = Field(default_factory=list)
    relationships: list[EntityRelationship] = Field(default_factory=list)
    available: bool = True
    error: Optional[str] = None
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None


class InvestigationScope(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    domain: Optional[str] = None
    company: Optional[str] = None
    name: Optional[str] = None
    ip: Optional[str] = None
    url: Optional[str] = None
    phone: Optional[str] = None
    social_profile_url: Optional[str] = None
    modules: list[str] = Field(default_factory=list)


class Investigation(BaseModel):
    id: str = Field(default_factory=new_id)
    investigator: str = "unspecified"
    scope: InvestigationScope
    created_at: datetime = Field(default_factory=utcnow)
    findings: list[Finding] = Field(default_factory=list)
    relationships: list[EntityRelationship] = Field(default_factory=list)
    sources_consulted: list[Source] = Field(default_factory=list)
    unavailable_sources: list[dict[str, Any]] = Field(default_factory=list)
    notes: str = ""


# --------------------------------------------------------------------------
# SQLAlchemy ORM (persistence layer)
# --------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


class InvestigationORM(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigator: Mapped[str] = mapped_column(String(128), default="unspecified")
    scope_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    notes: Mapped[str] = mapped_column(Text, default="")

    findings: Mapped[list["FindingORM"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    relationships_: Mapped[list["RelationshipORM"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    category: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(Text)
    entity_key: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    sources_json: Mapped[list] = mapped_column(JSON, default=list)
    confidence: Mapped[str] = mapped_column(String(16), default=Confidence.UNVERIFIED.value)
    reasoning: Mapped[str] = mapped_column(Text, default="")
    unavailable: Mapped[bool] = mapped_column(default=False)
    unavailable_reason: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[InvestigationORM] = relationship(back_populates="findings")


class RelationshipORM(Base):
    __tablename__ = "relationships"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    from_key: Mapped[str] = mapped_column(String(256))
    to_key: Mapped[str] = mapped_column(String(256))
    relation_type: Mapped[str] = mapped_column(String(128))
    source_json: Mapped[dict] = mapped_column(JSON)
    evidence: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(16), default=Confidence.UNVERIFIED.value)
    explanation: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[InvestigationORM] = relationship(back_populates="relationships_")
