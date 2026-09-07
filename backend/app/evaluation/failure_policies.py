"""
FailurePolicy definitions for every operational failure mode in the GraphRAG pipeline.
"""
from __future__ import annotations

from typing import Dict, Optional
from pydantic import BaseModel
from app.schemas.schemas import EscalationAction, OperationalState


class FailurePolicy(BaseModel):
    state: OperationalState
    default_escalation: EscalationAction
    user_guidance: str
    recovery_action: str
    backoff_seconds: float = 0.0


FAILURE_POLICIES: Dict[OperationalState, FailurePolicy] = {
    OperationalState.EMPTY_RETRIEVAL: FailurePolicy(
        state=OperationalState.EMPTY_RETRIEVAL,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="No verified threat actors, malware, or infrastructure matching your query were found in the knowledge graph. Try asking about known entities such as PHANTOM DRAGON or DragonScale.",
        recovery_action="Route to analyst review and prompt query reformulation",
    ),
    OperationalState.LOW_CONFIDENCE_RETRIEVAL: FailurePolicy(
        state=OperationalState.LOW_CONFIDENCE_RETRIEVAL,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="Limited graph connectivity was discovered. Results are presented with preliminary confidence and require corroborating evidence.",
        recovery_action="Bounded secondary graph expansion with uncertainty qualification",
    ),
    OperationalState.CONTEXT_TOO_LONG: FailurePolicy(
        state=OperationalState.CONTEXT_TOO_LONG,
        default_escalation=EscalationAction.ESCALATE_BUDGET,
        user_guidance="Retrieved graph subgraph exceeded maximum allowable context budget. Context was compressed.",
        recovery_action="Compress context, deduplicate relationship paths, and prioritize verified evidence",
    ),
    OperationalState.LLM_TIMEOUT: FailurePolicy(
        state=OperationalState.LLM_TIMEOUT,
        default_escalation=EscalationAction.NONE,
        user_guidance="AI reasoning timed out while analyzing complex graph paths. The retrieved graph evidence is displayed below for direct analyst review.",
        recovery_action="Fallback to fast bounded heuristic summarizer or return raw verified subgraph",
    ),
    OperationalState.LLM_RATE_LIMIT: FailurePolicy(
        state=OperationalState.LLM_RATE_LIMIT,
        default_escalation=EscalationAction.NONE,
        user_guidance="AI provider rate limit reached. The system automatically retried and provided bounded deterministic intelligence.",
        recovery_action="Exponential backoff with jitter, followed by fallback to local deterministic summarizer",
        backoff_seconds=2.0,
    ),
    OperationalState.LLM_PROVIDER_ERROR: FailurePolicy(
        state=OperationalState.LLM_PROVIDER_ERROR,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="AI service encountered an upstream provider error. Structured graph data has been retrieved safely.",
        recovery_action="Failover to secondary provider in fallback chain",
    ),
    OperationalState.LLM_INVALID_OUTPUT: FailurePolicy(
        state=OperationalState.LLM_INVALID_OUTPUT,
        default_escalation=EscalationAction.NONE,
        user_guidance="AI output format was corrected against system schema constraints.",
        recovery_action="Sanitize and schema-validate output structure",
    ),
    OperationalState.COST_BUDGET_EXCEEDED: FailurePolicy(
        state=OperationalState.COST_BUDGET_EXCEEDED,
        default_escalation=EscalationAction.ESCALATE_BUDGET,
        user_guidance="Investigation exceeded daily cost/token budget allocation for your tier.",
        recovery_action="Halt model generation and present existing verified subgraph",
    ),
    OperationalState.LOW_CONFIDENCE_ANSWER: FailurePolicy(
        state=OperationalState.LOW_CONFIDENCE_ANSWER,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="Answer generated with low confidence due to limited source corroboration.",
        recovery_action="Qualify findings with explicit uncertainty warnings and cite missing corroboration",
    ),
    OperationalState.CONTRADICTORY_EVIDENCE: FailurePolicy(
        state=OperationalState.CONTRADICTORY_EVIDENCE,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="Conflicting intelligence reports detected across sources. Both perspectives are presented for human analyst verification.",
        recovery_action="Present conflicting claims side-by-side with source attribution rather than a definitive conclusion",
    ),
    OperationalState.UNSUPPORTED_CLAIM: FailurePolicy(
        state=OperationalState.UNSUPPORTED_CLAIM,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="Generated claims were verified against the knowledge graph; unverified statements were suppressed.",
        recovery_action="Suppress ungrounded assertions and present verified subgraph",
    ),
    OperationalState.AMBIGUOUS_ENTITY: FailurePolicy(
        state=OperationalState.AMBIGUOUS_ENTITY,
        default_escalation=EscalationAction.ESCALATE_DISAMBIGUATE,
        user_guidance="Multiple candidate entities match your query. Please specify which threat entity you wish to investigate.",
        recovery_action="Present candidate entity matches for user disambiguation",
    ),
    OperationalState.SECURITY_BLOCK: FailurePolicy(
        state=OperationalState.SECURITY_BLOCK,
        default_escalation=EscalationAction.ESCALATE_SECURITY,
        user_guidance="Query rejected: contains potentially malicious payload or unauthorized traversal pattern.",
        recovery_action="Neutralize payload, reject execution, and record high-priority audit incident",
    ),
    OperationalState.GRAPH_TIMEOUT: FailurePolicy(
        state=OperationalState.GRAPH_TIMEOUT,
        default_escalation=EscalationAction.NONE,
        user_guidance="Graph traversal took longer than expected. Retrying with bounded single-hop scope.",
        recovery_action="Retry traversal with strict 1-hop depth",
    ),
    OperationalState.GRAPH_UNAVAILABLE: FailurePolicy(
        state=OperationalState.GRAPH_UNAVAILABLE,
        default_escalation=EscalationAction.NONE,
        user_guidance="Knowledge graph database is temporarily unavailable. Operating in bounded offline cache mode.",
        recovery_action="Switch to offline in-memory graph repository",
    ),
    OperationalState.CACHE_FAILURE: FailurePolicy(
        state=OperationalState.CACHE_FAILURE,
        default_escalation=EscalationAction.NONE,
        user_guidance="Cache read bypassed; freshly retrieved from live intelligence graph.",
        recovery_action="Bypass cache and execute direct live graph retrieval",
    ),
    OperationalState.AUTHORIZATION_FAILURE: FailurePolicy(
        state=OperationalState.AUTHORIZATION_FAILURE,
        default_escalation=EscalationAction.ESCALATE_SECURITY,
        user_guidance="Insufficient authorization privileges to access the requested threat intelligence node.",
        recovery_action="Enforce RBAC role check and log audit event",
    ),
    OperationalState.VALIDATION_FAILURE: FailurePolicy(
        state=OperationalState.VALIDATION_FAILURE,
        default_escalation=EscalationAction.NONE,
        user_guidance="Query format is invalid. Queries must be between 3 and 1000 characters.",
        recovery_action="Return 422 Unprocessable Entity with input constraints",
    ),
    OperationalState.TASK_COMPLETED: FailurePolicy(
        state=OperationalState.TASK_COMPLETED,
        default_escalation=EscalationAction.NONE,
        user_guidance="Investigation successfully completed with verified evidence grounding.",
        recovery_action="Present verified intelligence response",
    ),
    OperationalState.TASK_ESCALATED: FailurePolicy(
        state=OperationalState.TASK_ESCALATED,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="Investigation routed to analyst review due to policy threshold.",
        recovery_action="Assign investigation to human analyst queue",
    ),
    OperationalState.TASK_FAILED: FailurePolicy(
        state=OperationalState.TASK_FAILED,
        default_escalation=EscalationAction.ESCALATE_REVIEW,
        user_guidance="Investigation encountered an unrecoverable system error. Please retry or contact administrator.",
        recovery_action="Log diagnostic stack trace and alert system operator",
    ),
}


def get_failure_policy(state: OperationalState) -> FailurePolicy:
    """Lookup failure policy definition for an operational state."""
    return FAILURE_POLICIES.get(
        state,
        FailurePolicy(
            state=state,
            default_escalation=EscalationAction.NONE,
            user_guidance="Standard investigation state.",
            recovery_action="Continue execution",
        ),
    )
