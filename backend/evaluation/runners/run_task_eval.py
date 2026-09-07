import asyncio
import json
import sys
from pathlib import Path

# Add paths
root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "final_project" / "backend"))
sys.path.insert(0, str(root / "final_project"))

from app.schemas.schemas import QueryRequest, OperationalState, TaskCompletionStatus
from app.services.query_service import query_service
from evaluation.metrics.task_metrics import TaskEvaluationResult, compute_primary_five_metrics


async def run_task_evaluation() -> dict:
    data_file = root / "final_project" / "evaluation" / "datasets" / "task_eval.jsonl"
    if not data_file.exists():
        data_file = Path("evaluation/datasets/task_eval.jsonl")

    tasks = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                tasks.append(json.loads(line))

    print(f"\n=======================================================")
    print(f"  RUNNING DEEP AI TASK EVALUATION ({len(tasks)} tasks)")
    print(f"=======================================================")

    results: list[TaskEvaluationResult] = []
    for t in tasks:
        req = QueryRequest(query=t["query"])
        resp = await query_service.execute_query(req)
        completed = (resp.task_status == TaskCompletionStatus.TASK_COMPLETED)
        escalated = (resp.operational_state in (OperationalState.TASK_ESCALATED, OperationalState.AMBIGUOUS_ENTITY, OperationalState.EMPTY_RETRIEVAL))

        res = TaskEvaluationResult(
            task_id=t["id"],
            completed=completed,
            faithfulness_score=resp.faithfulness_score,
            hallucination_rate=round(1.0 - resp.faithfulness_score, 2),
            cost_usd=resp.cost_usd,
            escalated=escalated,
            escalation_appropriate=True,
        )
        results.append(res)
        print(f"  [{t['id']}] Status: {resp.task_status.value} | State: {resp.operational_state.value} | Faithfulness: {resp.faithfulness_score:.2f} | Cost: ${resp.cost_usd:.5f}")

    metrics = compute_primary_five_metrics(results)
    print(f"\n  M1 Task Completion Rate: {metrics['m1_task_completion_rate'] * 100:.1f}%")
    print(f"  M2 Faithfulness Score   : {metrics['m2_faithfulness']:.2f}")
    print(f"  M3 Hallucination Rate   : {metrics['m3_hallucination_rate'] * 100:.1f}%")
    print(f"  M4 Mean Cost Per Task   : ${metrics['m4_mean_cost_per_task']:.6f}")
    print(f"  M5 Escalation Rate      : {metrics['m5_escalation_rate'] * 100:.1f}%")
    print(f"=======================================================\n")
    return metrics


if __name__ == "__main__":
    asyncio.run(run_task_evaluation())
