import sys
from pathlib import Path
_proj = Path(__file__).resolve().parents[3]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

import pytest
from evaluation.metrics.task_metrics import TaskEvaluationResult, compute_primary_five_metrics


def test_primary_five_metrics_calculation():
    """Verify aggregated metrics math across varied task outcomes."""
    results = [
        TaskEvaluationResult(
            task_id="t1",
            completed=True,
            faithfulness_score=1.0,
            hallucination_rate=0.0,
            cost_usd=0.001,
            escalated=False,
            escalation_appropriate=True,
        ),
        TaskEvaluationResult(
            task_id="t2",
            completed=True,
            faithfulness_score=0.9,
            hallucination_rate=0.1,
            cost_usd=0.002,
            escalated=False,
            escalation_appropriate=True,
        ),
        TaskEvaluationResult(
            task_id="t3",
            completed=False,
            faithfulness_score=0.8,
            hallucination_rate=0.2,
            cost_usd=0.0015,
            escalated=True,
            escalation_appropriate=True,
        ),
    ]
    metrics = compute_primary_five_metrics(results)
    assert metrics["m1_task_completion_rate"] == 0.67
    assert metrics["m2_faithfulness"] == 0.90
    assert metrics["m3_hallucination_rate"] == 0.10
    assert metrics["m4_mean_cost_per_task"] == 0.0015
    assert metrics["m5_escalation_rate"] == 0.33


def test_empty_results_handling():
    """Verify empty dataset does not produce ZeroDivisionError."""
    metrics = compute_primary_five_metrics([])
    assert metrics["m1_task_completion_rate"] == 0.0
    assert metrics["m4_mean_cost_per_task"] == 0.0
