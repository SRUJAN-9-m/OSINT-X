"""Database engine/session management and persistence helpers."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from config import settings
from database.models import (
    Base,
    FindingORM,
    Investigation,
    InvestigationORM,
    RelationshipORM,
)

_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


@contextmanager
def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def save_investigation(investigation: Investigation) -> None:
    with get_session() as session:
        orm = InvestigationORM(
            id=investigation.id,
            investigator=investigation.investigator,
            scope_json=investigation.scope.model_dump(mode="json"),
            created_at=investigation.created_at,
            notes=investigation.notes,
        )
        session.merge(orm)
        for f in investigation.findings:
            session.merge(
                FindingORM(
                    id=f.id,
                    investigation_id=investigation.id,
                    category=f.category,
                    label=f.label,
                    detail=f.detail,
                    entity_key=f.entity_key,
                    sources_json=[s.model_dump(mode="json") for s in f.sources],
                    confidence=f.confidence.value,
                    reasoning=f.reasoning,
                    unavailable=f.unavailable,
                    unavailable_reason=f.unavailable_reason,
                    created_at=f.created_at,
                )
            )
        for r in investigation.relationships:
            session.merge(
                RelationshipORM(
                    id=r.id,
                    investigation_id=investigation.id,
                    from_key=r.from_key,
                    to_key=r.to_key,
                    relation_type=r.relation_type,
                    source_json=r.source.model_dump(mode="json"),
                    evidence=r.evidence,
                    confidence=r.confidence.value,
                    explanation=r.explanation,
                    created_at=r.created_at,
                )
            )


def load_investigation(investigation_id: str) -> InvestigationORM | None:
    with get_session() as session:
        return session.get(InvestigationORM, investigation_id)


def delete_investigation(investigation_id: str) -> bool:
    """Section 18 privacy requirement: allow deleting an investigation."""
    with get_session() as session:
        orm = session.get(InvestigationORM, investigation_id)
        if orm is None:
            return False
        session.delete(orm)
        return True
