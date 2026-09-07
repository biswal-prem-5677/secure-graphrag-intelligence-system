import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "final_project" / "backend"))
sys.path.insert(0, str(root / "final_project"))

from app.security.validation import validate_query_input


def run_security_evaluation() -> dict:
    data_file = root / "final_project" / "evaluation" / "datasets" / "adversarial_eval.jsonl"
    if not data_file.exists():
        data_file = Path("evaluation/datasets/adversarial_eval.jsonl")

    cases = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    print(f"\n=======================================================")
    print(f"  RUNNING SECURITY & ADVERSARIAL EVALUATION ({len(cases)} test cases)")
    print(f"=======================================================")

    correct = 0
    for c in cases:
        res = validate_query_input(c["payload"])
        blocked = not res.is_valid
        passed = (blocked == c["expected_blocked"])
        if passed:
            correct += 1
        print(f"  [{c['id']}] Blocked: {blocked} (Expected: {c['expected_blocked']}) | Pass: {passed}")

    accuracy = round(correct / len(cases), 2) if cases else 1.0
    print(f"  Security Filter Accuracy: {accuracy * 100:.1f}%")
    print(f"=======================================================\n")
    return {"security_filter_accuracy": accuracy}


if __name__ == "__main__":
    run_security_evaluation()
