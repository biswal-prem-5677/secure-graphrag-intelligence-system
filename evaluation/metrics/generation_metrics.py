import re
from typing import Any, Dict, List


def evaluate_groundedness(
    generated_answer: str, expected_claims: List[str], is_refusal_expected: bool = False
) -> Dict[str, Any]:
    """Evaluate factual groundedness and claim support against expected claims."""
    ans_lower = generated_answer.lower()

    if is_refusal_expected:
        refusal_correct = "insufficient evidence" in ans_lower or "could not establish" in ans_lower
        return {
            "claim_support_rate": 1.0 if refusal_correct else 0.0,
            "hallucination_rate": 0.0 if refusal_correct else 1.0,
            "refusal_correct": refusal_correct,
        }

    if not expected_claims:
        return {"claim_support_rate": 1.0, "hallucination_rate": 0.0, "refusal_correct": False}

    supported = 0
    for claim in expected_claims:
        tokens = [w for w in re.findall(r"\w+", claim.lower()) if len(w) > 3]
        if tokens:
            matched = sum(1 for t in tokens if t in ans_lower)
            if matched / len(tokens) >= 0.6:
                supported += 1

    support_rate = round(supported / len(expected_claims), 2)
    halluc_rate = round(1.0 - support_rate, 2)
    return {
        "claim_support_rate": support_rate,
        "hallucination_rate": halluc_rate,
        "refusal_correct": False,
    }
