from typing import Any, Dict, List


def evaluate_confidence_calibration(results: List[Dict[str, Any]]) -> Dict[str, float]:
    """Evaluate accuracy calibration across confidence tiers (HIGH, MEDIUM, LOW, INSUFFICIENT)."""
    calibration: Dict[str, float] = {}
    tiers = ["HIGH", "MEDIUM", "LOW", "INSUFFICIENT"]
    for t in tiers:
        tier_results = [r for r in results if r.get("predicted_tier") == t]
        if not tier_results:
            calibration[t] = 1.0
        else:
            correct = sum(1 for r in tier_results if r.get("is_correct", False))
            calibration[t] = round(correct / len(tier_results), 2)
    return calibration
