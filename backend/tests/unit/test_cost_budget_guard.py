import pytest
from app.evaluation.cost_tracker import CostTracker


def test_cost_budget_guard_exceeded_flag():
    tracker = CostTracker()
    prompt = "Word " * 2000  # ~2600 tokens
    completion = "Word " * 500  # ~650 tokens

    rec = tracker.calculate_and_record("Q-TEST", prompt, completion, "gemini-2.0-flash")
    assert rec.total_tokens > 2000
    assert rec.token_budget_exceeded is True
    assert rec.cost_usd > 0.0
