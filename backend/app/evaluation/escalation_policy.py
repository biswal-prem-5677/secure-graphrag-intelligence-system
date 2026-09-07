"""
EscalationPolicy: Deterministic, policy-driven escalation decision engine.
"""
from __future__ import annotations

import re
from typing import Optional
from pydantic import BaseModel
from app.core.logging import get_logger
from app.evaluation.claim_verifier import ClaimVerificationResult
from app.schemas.schemas import ConfidenceLevel, EscalationAction, EvidenceRecord, GraphData

logger = get_logger("escalation_policy")


class EscalationDecision(BaseModel):
    action: EscalationAction
    reason: str
    guidance: Optional[str] = None


class EscalationPolicy:
    """Deterministic, policy-driven escalation decision engine."""

    def evaluate_pre_retrieval(self, query: str, estimated_tokens: int = 0) -> Optional[EscalationDecision]:
        """Check for pre-retrieval escalation triggers (security, ambiguity, budget)."""
        q = query.strip()

        # Check Ambiguity: single generic word queries like "bank", "corp", "health"
        if re.match(r"^(bank|corp|health|energy|systems|hospital|defense)$", q, re.IGNORECASE):
            return EscalationDecision(
                action=EscalationAction.ESCALATE_DISAMBIGUATE,
                reason=f"Query '{q}' is highly ambiguous without specific threat actor or campaign identifier.",
                guidance="Prompt analyst to specify full threat entity name (e.g. 'Apex Defense Corp' or 'Metro Health System').",
            )

        # Check Budget
        if estimated_tokens > 4000:
            return EscalationDecision(
                action=EscalationAction.ESCALATE_BUDGET,
                reason=f"Task token estimate ({estimated_tokens}) exceeds task budget (4000).",
                guidance="Truncate context or prompt user for narrower scope.",
            )

        return None

    def evaluate_post_retrieval(
        self,
        graph_data: GraphData,
        evidence_records: list[EvidenceRecord],
        confidence: ConfidenceLevel,
        claim_result: Optional[ClaimVerificationResult] = None,
    ) -> EscalationDecision:
        """Evaluate retrieval density, claim grounding, and contradictions for escalation."""
        # Case 1: Empty retrieval
        if not graph_data.nodes:
            return EscalationDecision(
                action=EscalationAction.ESCALATE_REVIEW,
                reason="No verified graph entities or relationship paths exist in the intelligence base.",
                guidance="Route to analyst for external threat intelligence research.",
            )

        # Case 2: Low confidence
        if confidence == ConfidenceLevel.LOW:
            return EscalationDecision(
                action=EscalationAction.ESCALATE_REVIEW,
                reason="Low confidence: Entity found but corroborating evidence reports are missing.",
                guidance="Flag findings as unverified preliminary intelligence.",
            )

        # Case 3: Unsupported claims / hallucinations
        if claim_result and not claim_result.is_fully_grounded:
            return EscalationDecision(
                action=EscalationAction.ESCALATE_REVIEW,
                reason="Generated answer contains unsupported claims with zero graph grounding.",
                guidance="Suppress ungrounded answer and present raw subgraph evidence to analyst.",
            )

        return EscalationDecision(
            action=EscalationAction.NONE,
            reason="Intelligence graph contains verified entities, relationship paths, and corroborating evidence.",
            guidance="Present verified intelligence response directly to user.",
        )


escalation_policy = EscalationPolicy()
