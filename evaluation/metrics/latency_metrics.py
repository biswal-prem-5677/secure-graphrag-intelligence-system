from typing import Any, Dict, List


def calculate_percentiles(latencies: List[float]) -> Dict[str, float]:
    """Calculate p50, p95, p99, min, max, and average latency."""
    if not latencies:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "avg": 0.0, "min": 0.0, "max": 0.0}
    sorted_lats = sorted(latencies)
    n = len(sorted_lats)

    if n % 2 == 1:
        p50 = sorted_lats[n // 2]
    else:
        p50 = (sorted_lats[n // 2 - 1] + sorted_lats[n // 2]) / 2.0

    def p(pct: float) -> float:
        idx = int(pct * n)
        return sorted_lats[min(idx, n - 1)]

    return {
        "p50": round(p50, 2),
        "p95": round(p(0.95), 2),
        "p99": round(p(0.99), 2),
        "avg": round(sum(sorted_lats) / n, 2),
        "min": round(sorted_lats[0], 2),
        "max": round(sorted_lats[-1], 2),
    }
