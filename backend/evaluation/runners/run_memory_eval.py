import asyncio
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "final_project" / "backend"))
sys.path.insert(0, str(root / "final_project"))

from app.services.memory_service import memory_service


async def run_memory_evaluation() -> dict:
    data_file = root / "final_project" / "evaluation" / "datasets" / "memory_eval.jsonl"
    if not data_file.exists():
        data_file = Path("evaluation/datasets/memory_eval.jsonl")

    cases = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    print(f"\n=======================================================")
    print(f"  RUNNING USER MEMORY & PERSONALIZATION EVALUATION ({len(cases)} test cases)")
    print(f"=======================================================")

    correct = 0
    for c in cases:
        sess_id = f"eval-sess-{c['id']}"
        memory_service.update_session(sess_id, "eval_user", c["expected_entity"], c["first_query"])
        resolved_q, entity = memory_service.resolve_contextual_query(c["follow_up"], sess_id, "eval_user")
        match = (c["expected_entity"].lower() in resolved_q.lower())
        if match:
            correct += 1
        print(f"  [{c['id']}] Follow-up: '{c['follow_up']}' -> Resolved: '{resolved_q}' | Match: {match}")

    acc = round(correct / len(cases), 2) if cases else 1.0
    print(f"  Anaphora Resolution Accuracy: {acc * 100:.1f}%")
    print(f"=======================================================\n")
    return {"anaphora_accuracy": acc}


if __name__ == "__main__":
    asyncio.run(run_memory_evaluation())
