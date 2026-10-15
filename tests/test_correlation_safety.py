import pytest

from analyzers.correlation import _cross_module_correlations
from database.models import Confidence, InvestigationScope


def test_username_email_cooccurrence_is_never_auto_confirmed():
    scope = InvestigationScope(username="alice99", email="alice@example.com")
    rels = _cross_module_correlations(scope, [])
    assert len(rels) == 1
    rel = rels[0]
    # Co-occurrence in one investigation request must NEVER be treated as
    # proof of identity -- only ever UNVERIFIED until corroborated by a
    # real collector finding.
    assert rel.confidence == Confidence.UNVERIFIED
    assert "NOT evidence" in rel.explanation
