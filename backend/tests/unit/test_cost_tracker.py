import pytest
from app.evaluation.cost_tracker import cost_tracker


def test_cost_tracker_calculation_and_summary():
    prompt = "This is a query about PHANTOM DRAGON malware."
    completion = "PHANTOM DRAGON uses DragonScale."
    rec = cost_tracker.calculate_and_record("TEST-01", prompt, completion, "gemini-2.0-flash")
    assert rec.prompt_tokens > 0
    assert rec.completion_tokens > 0

    summary = cost_tracker.get_summary()
    assert summary["total_queries"] >= 1
    assert summary["total_cost_usd"] >= 0.0
