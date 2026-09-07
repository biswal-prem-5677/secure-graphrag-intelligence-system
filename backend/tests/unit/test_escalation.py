import pytest
from app.evaluation.escalation_policy import escalation_policy
from app.schemas.schemas import ConfidenceLevel, EscalationAction, GraphData


def test_escalation_empty_retrieval():
    dec = escalation_policy.evaluate_post_retrieval(GraphData(), [], ConfidenceLevel.INSUFFICIENT)
    assert dec.action == EscalationAction.ESCALATE_REVIEW
    assert "No verified graph entities" in dec.reason


def test_escalation_ambiguous_entity():
    dec = escalation_policy.evaluate_pre_retrieval("bank")
    assert dec.action == EscalationAction.ESCALATE_DISAMBIGUATE
