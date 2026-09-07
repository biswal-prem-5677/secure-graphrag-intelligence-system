"""
Pydantic schemas for all API request/response models and operational states.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import re


class OperationalState(str, Enum):
    """Canonical operational state enumeration for investigations and tasks."""
    EMPTY_RETRIEVAL = "EMPTY_RETRIEVAL"
    LOW_CONFIDENCE_RETRIEVAL = "LOW_CONFIDENCE_RETRIEVAL"
    CONTEXT_TOO_LONG = "CONTEXT_TOO_LONG"
    LLM_TIMEOUT = "LLM_TIMEOUT"
    LLM_RATE_LIMIT = "LLM_RATE_LIMIT"
    LLM_PROVIDER_ERROR = "LLM_PROVIDER_ERROR"
    LLM_INVALID_OUTPUT = "LLM_INVALID_OUTPUT"
    COST_BUDGET_EXCEEDED = "COST_BUDGET_EXCEEDED"
    LOW_CONFIDENCE_ANSWER = "LOW_CONFIDENCE_ANSWER"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    UNSUPPORTED_CLAIM = "UNSUPPORTED_CLAIM"
    AMBIGUOUS_ENTITY = "AMBIGUOUS_ENTITY"
    SECURITY_BLOCK = "SECURITY_BLOCK"
    GRAPH_TIMEOUT = "GRAPH_TIMEOUT"
    GRAPH_UNAVAILABLE = "GRAPH_UNAVAILABLE"
    CACHE_FAILURE = "CACHE_FAILURE"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_ESCALATED = "TASK_ESCALATED"
    TASK_FAILED = "TASK_FAILED"


class TaskCompletionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    TASK_COMPLETED = "TASK_COMPLETED"
    FAILED = "FAILED"
    TASK_FAILED = "TASK_FAILED"
    ESCALATED = "ESCALATED"
    TASK_ESCALATED = "TASK_ESCALATED"
    AMBIGUOUS_ENTITY = "AMBIGUOUS_ENTITY"
    REFUSED = "REFUSED"


class EscalationAction(str, Enum):
    NONE = "NONE"
    ESCALATE_REVIEW = "ESCALATE_REVIEW"
    ESCALATE_DISAMBIGUATE = "ESCALATE_DISAMBIGUATE"
    ESCALATE_SECURITY = "ESCALATE_SECURITY"
    ESCALATE_BUDGET = "ESCALATE_BUDGET"


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


# Auth Schemas
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=100)
    email: Optional[str] = Field(default=None, max_length=255)


class UserResponse(BaseModel):
    id: Optional[str] = None
    username: str
    email: Optional[str] = None
    role: str
    disabled: bool = False


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    username: str
    role: str


# Query Schemas
class QueryRequest(BaseModel):
    query: str = Field(..., min_length=3, max_length=1000, description="Natural language query")
    bypass_cache: bool = Field(default=False, description="Force fresh graph traversal")
    max_hops: int = Field(default=2, ge=1, le=4)
    session_id: Optional[str] = None

    @field_validator("query")
    @classmethod
    def sanitize_query(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3:
            raise ValueError("Query must be at least 3 characters")
        return v


class EvidenceRecord(BaseModel):
    source_id: str
    title: str
    source_type: str
    confidence: float
    summary: str
    date: Optional[str] = None


class RelationshipStep(BaseModel):
    source: str
    relation: str
    target: str
    evidence_ids: List[str] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    name: str
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphData(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class StageTimings(BaseModel):
    validation_ms: float = 0.0
    cache_lookup_ms: float = 0.0
    query_analysis_ms: float = 0.0
    graph_retrieval_ms: float = 0.0
    context_assembly_ms: float = 0.0
    llm_generation_ms: float = 0.0
    claim_verification_ms: float = 0.0
    total_pipeline_ms: float = 0.0


class InvestigationProgressStep(BaseModel):
    step_name: str
    status: str
    duration_ms: float
    details: Optional[str] = None


class QueryResponse(BaseModel):
    query_id: str
    query: str
    answer: str
    confidence: ConfidenceLevel
    confidence_explanation: str
    operational_state: OperationalState
    task_status: TaskCompletionStatus
    escalation_action: EscalationAction
    graph_data: GraphData
    relationship_paths: List[RelationshipStep] = Field(default_factory=list)
    evidence_records: List[EvidenceRecord] = Field(default_factory=list)
    cited_sources: List[str] = Field(default_factory=list)
    unsupported_claims: List[str] = Field(default_factory=list)
    faithfulness_score: float = 1.0
    cached: bool = False
    cost_usd: float = 0.0
    stage_timings: StageTimings = Field(default_factory=StageTimings)
    progress_steps: List[InvestigationProgressStep] = Field(default_factory=list)
    user_guidance: Optional[str] = None


class EntityResponse(BaseModel):
    id: str
    name: str
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class EntityRelationshipsResponse(BaseModel):
    entity_id: str
    relationships: List[RelationshipStep] = Field(default_factory=list)


class EntityGraphResponse(BaseModel):
    entity_id: str
    graph: GraphData


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "1.0.0"


class ReadyResponse(BaseModel):
    status: str
    neo4j: str
    cache: str
    active_llm: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    operational_state: Optional[OperationalState] = None


class QueryHistoryItem(BaseModel):
    query_id: str
    query: str
    timestamp: str
    confidence: str
    operational_state: str
