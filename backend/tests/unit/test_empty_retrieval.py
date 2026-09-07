import pytest
from unittest.mock import AsyncMock, patch
from app.schemas.schemas import ConfidenceLevel, OperationalState, QueryRequest, TaskCompletionStatus
from app.services.query_service import query_service


@pytest.mark.asyncio
async def test_empty_retrieval_short_circuit_behavior():
    """Verify empty retrieval does NOT call the LLM and returns EMPTY_RETRIEVAL with guidance."""
    req = QueryRequest(query="What is the non-existent imaginary alien syndicate Omega999?")

    with patch("app.llm.factory.get_llm_provider") as mock_factory:
        mock_provider = AsyncMock()
        mock_factory.return_value = mock_provider

        resp = await query_service.execute_query(req)

        # Ensure LLM was NEVER called
        mock_provider.generate_grounded_answer.assert_not_called()

        assert resp.operational_state == OperationalState.EMPTY_RETRIEVAL
        assert resp.confidence == ConfidenceLevel.INSUFFICIENT
        assert resp.task_status == TaskCompletionStatus.TASK_COMPLETED
        assert resp.user_guidance is not None
        assert "No verified threat actors" in resp.user_guidance


@pytest.mark.asyncio
async def test_empty_retrieval_progress_steps():
    """Verify empty retrieval generates genuine runtime progress steps without faking completion of skipped stages."""
    req = QueryRequest(query="Tell me about UnknownActorXYZ123")
    resp = await query_service.execute_query(req)

    step_names = [s.step_name for s in resp.progress_steps]
    assert "Input Validation" in step_names
    assert "Cache Lookup" in step_names
    assert "Entity Resolution" in step_names
    assert "Evidence Collection" in step_names

    # Grounded AI Generation was short-circuited and MUST NOT appear
    assert "Grounded AI Generation" not in step_names
