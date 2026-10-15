import pytest
from pydantic import ValidationError as PydanticValidationError

from analyzers.confidence import score_relationship
from database.models import Confidence, Finding, Source, SourceType


def _source(reliability="official"):
    return Source(
        source="Test Source",
        source_type=SourceType.PUBLIC_WEBSITE,
        reliability=reliability,
        evidence="unit test",
    )


def test_finding_requires_source_unless_unavailable():
    with pytest.raises(PydanticValidationError):
        Finding(category="x", label="y", detail="z", sources=[])


def test_finding_allows_no_source_if_unavailable():
    f = Finding(category="x", label="y", detail="z", sources=[], unavailable=True)
    assert f.unavailable is True


def test_confidence_single_official_source_is_confirmed():
    assert score_relationship([_source("official")]) == Confidence.CONFIRMED


def test_confidence_two_sources_is_supported():
    s1 = _source("third-party")
    s2 = Source(
        source="Other Source",
        source_type=SourceType.PUBLIC_WEBSITE,
        reliability="third-party",
        evidence="unit test",
    )
    assert score_relationship([s1, s2]) == Confidence.SUPPORTED


def test_confidence_no_sources_is_unverified():
    assert score_relationship([]) == Confidence.UNVERIFIED
