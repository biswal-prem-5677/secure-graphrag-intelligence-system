from typing import Any, Dict, List
from pydantic import BaseModel


class TaskEvaluationResult(BaseModel):
    task_id: str
    completed: bool = True
    faithfulness_score: float = 1.0
    hallucination_rate: float = 0.0
    cost_usd: float = 0.0
    escalated: bool = False
    escalation_appropriate: bool = True


def compute_primary_five_metrics(results: List[TaskEvaluationResult]) -> Dict[str, float]:
    """Computes the canonical M1-M5 AI Quality & Evaluation Metrics."""
    if not results:
        return {
            "m1_task_completion_rate": 0.0,
            "m2_faithfulness": 0.0,
            "m3_hallucination_rate": 0.0,
            "m4_mean_cost_per_task": 0.0,
            "m5_escalation_rate": 0.0,
            "appropriate_escalation_rate": 1.0,
        }

    n = len(results)
    m1 = sum(1 for r in results if r.completed) / n
    m2 = sum(r.faithfulness_score for r in results) / n
    m3 = sum(r.hallucination_rate for r in results) / n
    m4 = sum(r.cost_usd for r in results) / n
    m5 = sum(1 for r in results if r.escalated) / n
    escalated_results = [r for r in results if r.escalated]
    appr = sum(1 for r in escalated_results if r.escalation_appropriate) / len(escalated_results) if escalated_results else 1.0

    return {
        "m1_task_completion_rate": round(m1, 2),
        "m2_faithfulness": round(m2, 2),
        "m3_hallucination_rate": round(m3, 2),
        "m4_mean_cost_per_task": round(m4, 4),
        "m5_escalation_rate": round(m5, 2),
        "appropriate_escalation_rate": round(appr, 2),
    }
