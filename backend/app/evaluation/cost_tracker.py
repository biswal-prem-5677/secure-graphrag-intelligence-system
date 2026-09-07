"""
CostTracker: Thread-safe cost and token accounting store with configurable budgets.
"""
from __future__ import annotations

import time
from threading import Lock
from typing import Any, Dict, List
from pydantic import BaseModel
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("cost_tracker")


class QueryCostRecord(BaseModel):
    model_config = {"protected_namespaces": ()}
    query_id: str
    model_name: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_usd: float
    token_budget_exceeded: bool
    timestamp: float


class CostTracker:
    """Thread-safe cost and token accounting store."""

    # Pricing per 1,000,000 tokens (input, output) in USD
    MODEL_PRICING = {
        "gemini-2.0-flash": (0.10, 0.40),
        "llama-3.3-70b-versatile": (0.59, 0.79),
        "gpt-4o-mini": (0.15, 0.60),
        "mock": (0.00, 0.00),
    }

    def __init__(self) -> None:
        self._records: List[QueryCostRecord] = []
        self._lock = Lock()

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count based on standard ~1.3 tokens per word heuristic."""
        if not text:
            return 0
        words = len(text.strip().split())
        return max(1, int(words * 1.3))

    def calculate_and_record(
        self,
        query_id: str,
        prompt_text: str,
        completion_text: str,
        model_name: Optional[str] = None,
    ) -> QueryCostRecord:
        """Calculate token usage and cost, validating against token budget."""
        model = model_name or settings.GEMINI_MODEL
        p_tokens = self.estimate_tokens(prompt_text)
        c_tokens = self.estimate_tokens(completion_text)
        tot_tokens = p_tokens + c_tokens

        # Check budget
        exceeded = tot_tokens > settings.MAX_CONTEXT_TOKENS

        rates = self.MODEL_PRICING.get(model, (0.20, 0.60))
        cost = (p_tokens / 1_000_000 * rates[0]) + (c_tokens / 1_000_000 * rates[1])

        record = QueryCostRecord(
            query_id=query_id,
            model_name=model,
            prompt_tokens=p_tokens,
            completion_tokens=c_tokens,
            total_tokens=tot_tokens,
            cost_usd=round(cost, 6),
            token_budget_exceeded=exceeded,
            timestamp=time.time(),
        )

        with self._lock:
            self._records.append(record)

        return record

    def get_summary(self) -> Dict[str, Any]:
        """Aggregate total token usage and financial cost."""
        with self._lock:
            if not self._records:
                return {
                    "total_queries": 0,
                    "total_tokens": 0,
                    "total_cost_usd": 0.0,
                    "mean_cost_per_query": 0.0,
                    "budget_violations": 0,
                }
            tot_q = len(self._records)
            tot_tok = sum(r.total_tokens for r in self._records)
            tot_cost = sum(r.cost_usd for r in self._records)
            violations = sum(1 for r in self._records if r.token_budget_exceeded)
            return {
                "total_queries": tot_q,
                "total_tokens": tot_tok,
                "total_cost_usd": round(tot_cost, 6),
                "mean_cost_per_query": round(tot_cost / tot_q, 6),
                "budget_violations": violations,
            }


cost_tracker = CostTracker()
