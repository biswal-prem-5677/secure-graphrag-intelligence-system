"""
Abstract interface for all LLM providers in the GraphRAG pipeline.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class LLMResponse(BaseModel):
    answer: str
    confidence: str = "HIGH"
    confidence_explanation: str = ""
    cited_sources: List[str] = Field(default_factory=list)
    raw_response: Optional[Dict[str, Any]] = None


class BaseLLMProvider(ABC):
    """Abstract interface for all LLM providers in the GraphRAG pipeline."""

    @abstractmethod
    async def generate_grounded_answer(
        self, query: str, graph_context: str, **kwargs: Any
    ) -> LLMResponse:
        """Generate a factual response grounded strictly in graph context."""
        pass


LLMProvider = BaseLLMProvider
