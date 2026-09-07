import asyncio
import pytest
from unittest.mock import patch
from app.schemas.schemas import OperationalState, QueryRequest, TaskCompletionStatus
from app.services.query_service import query_service


@pytest.mark.asyncio
async def test_llm_timeout_graceful_recovery():
    """Verify timeout triggers LLM_TIMEOUT and returns fallback verified graph state."""
    req = QueryRequest(query="What malware does PHANTOM DRAGON use?")

    async def slow_llm_generation(*args, **kwargs):
        await asyncio.sleep(15.0)  # Exceeds 10s timeout
        return None

    with patch("app.llm.mock_provider.MockLLMProvider.generate_grounded_answer", side_effect=slow_llm_generation):
        resp = await query_service.execute_query(req)
        assert resp.operational_state == OperationalState.LLM_TIMEOUT
        assert resp.task_status == TaskCompletionStatus.TASK_COMPLETED
        assert len(resp.graph_data.nodes) > 0
        llm_step = [s for s in resp.progress_steps if s.step_name == "Grounded AI Generation"][0]
        assert llm_step.status == "failed"
