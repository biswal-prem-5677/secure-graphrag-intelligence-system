import sys
from pathlib import Path
_proj = Path(__file__).resolve().parents[3]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

import pytest
from evaluation.metrics.confidence_metrics import evaluate_confidence_calibration
from evaluation.metrics.cost_metrics import calculate_query_cost, estimate_token_count
from evaluation.metrics.generation_metrics import evaluate_groundedness
from evaluation.metrics.latency_metrics import calculate_percentiles
from evaluation.metrics.retrieval_metrics import (
    compute_mrr,
    compute_ndcg,
    compute_path_recovery_rate,
    compute_precision_recall_f1,
)


def test_retrieval_metrics_exact_match():
    retrieved = ["PHANTOM DRAGON", "DragonScale", "Cobalt Strike"]
    expected = ["PHANTOM DRAGON", "DragonScale"]
    p, r, f1 = compute_precision_recall_f1(retrieved, expected, k=2)
    assert p == 1.0
    assert r == 1.0
    assert f1 == 1.0


def test_retrieval_metrics_empty_expected():
    p, r, f1 = compute_precision_recall_f1(["A"], [], k=5)
    assert p == 0.0 and r == 1.0 and f1 == 0.0


def test_mrr_first_position():
    assert compute_mrr(["A", "B", "C"], ["A"]) == 1.0


def test_mrr_third_position():
    assert round(compute_mrr(["X", "Y", "A"], ["A"]), 2) == 0.33


def test_ndcg_ranking():
    score = compute_ndcg(["A", "B"], ["A", "B"], k=2)
    assert score == 1.0


def test_path_recovery_rate():
    ret = [("A", "USES", "B")]
    exp = [("A", "USES", "B"), ("B", "EXPLOITS", "C")]
    rate = compute_path_recovery_rate(ret, exp)
    assert rate == 0.5


def test_generation_groundedness_supported():
    answer = "PHANTOM DRAGON uses DragonScale."
    claims = ["PHANTOM DRAGON uses DragonScale"]
    res = evaluate_groundedness(answer, claims)
    assert res["claim_support_rate"] == 1.0
    assert res["hallucination_rate"] == 0.0


def test_generation_groundedness_hallucination():
    answer = "DragonScale is a custom backdoor used by PHANTOM DRAGON."
    claims = ["DragonScale is ransomware made by Fancy Bear"]
    res = evaluate_groundedness(answer, claims)
    assert res["claim_support_rate"] < 1.0


def test_confidence_calibration():
    cases = [
        {"predicted_tier": "HIGH", "is_correct": True},
        {"predicted_tier": "HIGH", "is_correct": True},
        {"predicted_tier": "INSUFFICIENT", "is_correct": True},
    ]
    calib = evaluate_confidence_calibration(cases)
    assert calib["HIGH"] == 1.0
    assert calib["INSUFFICIENT"] == 1.0


def test_cost_calculation():
    assert estimate_token_count("Word " * 10) == 13
    cost = calculate_query_cost(1000, 500, "gemini-2.0-flash")
    assert cost["cost_usd"] > 0.0


def test_latency_percentiles():
    lats = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    p = calculate_percentiles(lats)
    assert p["p50"] == 55.0
    assert p["p95"] > 90.0
    assert p["avg"] == 55.0
