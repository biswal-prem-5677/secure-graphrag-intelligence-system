import asyncio
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "final_project" / "backend"))
sys.path.insert(0, str(root / "final_project"))

from app.schemas.schemas import QueryRequest
from app.services.query_service import query_service


async def run_confidence_evaluation() -> dict:
    data_file = root / "final_project" / "evaluation" / "datasets" / "confidence_eval.jsonl"
    if not data_file.exists():
        data_file = Path("evaluation/datasets/confidence_eval.jsonl")

    cases = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    print(f"\n=======================================================")
    print(f"  RUNNING CONFIDENCE CALIBRATION EVALUATION ({len(cases)} test cases)")
    print(f"=======================================================")

    correct = 0
    for c in cases:
        resp = await query_service.execute_query(QueryRequest(query=c["query"]))
        match = (resp.confidence.value == c["expected_tier"])
        if match:
            correct += 1
        print(f"  [{c['id']}] Expected: {c['expected_tier']} | Got: {resp.confidence.value} | Match: {match}")

    accuracy = round(correct / len(cases), 2) if cases else 1.0
    print(f"  Confidence Accuracy: {accuracy * 100:.1f}%")
    print(f"=======================================================\n")
    return {"confidence_accuracy": accuracy}


if __name__ == "__main__":
    asyncio.run(run_confidence_eval())
