import asyncio
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "backend"))
sys.path.insert(0, str(root))

from app.schemas.schemas import QueryRequest
from app.services.query_service import query_service
from evaluation.metrics.generation_metrics import evaluate_groundedness


async def run_generation_evaluation() -> dict:
    data_file = root / "evaluation" / "datasets" / "generation_eval.jsonl"
    if not data_file.exists():
        data_file = Path("evaluation/datasets/generation_eval.jsonl")

    cases = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    print(f"\n=======================================================")
    print(f"  RUNNING GENERATION & GROUNDEDNESS EVALUATION ({len(cases)} test cases)")
    print(f"=======================================================")

    scores = []
    for c in cases:
        resp = await query_service.execute_query(QueryRequest(query=c["query"]))
        res = evaluate_groundedness(resp.answer, c["expected_claims"], c["refusal_expected"])
        scores.append(res["claim_support_rate"])
        print(f"  [{c['id']}] ClaimSupp: {res['claim_support_rate']:.2f} | HallucRate: {res['hallucination_rate']:.2f}")

    avg_supp = round(sum(scores) / len(scores), 2) if scores else 1.0
    print(f"  Mean Claim Grounding: {avg_supp * 100:.1f}%")
    print(f"=======================================================\n")
    return {"mean_grounding": avg_supp}


if __name__ == "__main__":
    asyncio.run(run_generation_evaluation())
