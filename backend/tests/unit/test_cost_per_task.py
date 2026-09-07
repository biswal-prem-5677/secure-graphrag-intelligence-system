import sys
from pathlib import Path
_proj = Path(__file__).resolve().parents[3]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

import pytest
from evaluation.metrics.task_metrics import TaskEvaluationResult, compute_primary_five_metrics


def test_m4_mean_cost_per_task():
    tasks = [
        TaskEvaluationResult(task_id="T1", cost_usd=0.001),
        TaskEvaluationResult(task_id="T2", cost_usd=0.003),
        TaskEvaluationResult(task_id="T3", cost_usd=0.002),
    ]
    m = compute_primary_five_metrics(tasks)
    assert m["m4_mean_cost_per_task"] == 0.002
