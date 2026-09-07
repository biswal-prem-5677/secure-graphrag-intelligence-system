import math
from typing import Any, Dict, List, Set, Tuple


def compute_precision_recall_f1(retrieved: List[str], expected: List[str], k: int = 5) -> Tuple[float, float, float]:
    """Calculate Precision@k, Recall@k, and F1@k for retrieved entities/evidence."""
    if not expected:
        return 0.0, 1.0, 0.0
    ret_k = set(retrieved[:k])
    exp_set = set(expected)
    matched = ret_k.intersection(exp_set)
    precision = len(matched) / len(ret_k) if ret_k else 0.0
    recall = len(matched) / len(exp_set) if exp_set else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return round(precision, 2), round(recall, 2), round(f1, 2)


def compute_mrr(retrieved: List[str], expected: List[str]) -> float:
    """Compute Reciprocal Rank of the first relevant retrieved item."""
    exp_set = set(expected)
    for idx, item in enumerate(retrieved):
        if item in exp_set:
            return round(1.0 / (idx + 1), 2)
    return 0.0


def compute_ndcg(retrieved: List[str], expected: List[str], k: int = 5) -> float:
    """Compute Normalized Discounted Cumulative Gain (nDCG@k)."""
    exp_set = set(expected)
    dcg = 0.0
    for idx, item in enumerate(retrieved[:k]):
        if item in exp_set:
            dcg += 1.0 / math.log2(idx + 2)
    idcg = sum(1.0 / math.log2(i + 2) for i in range(min(len(expected), k)))
    return round(dcg / idcg, 2) if idcg > 0 else 0.0


def compute_path_recovery_rate(retrieved_paths: List[Any], expected_paths: List[Any]) -> float:
    """Calculate percentage of expected relationship chains recovered."""
    if not expected_paths:
        return 1.0
    ret_set = {str(p) for p in retrieved_paths}
    exp_set = {str(p) for p in expected_paths}
    matched = ret_set.intersection(exp_set)
    return round(len(matched) / len(exp_set), 2)
