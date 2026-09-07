import pytest
from unittest.mock import patch
from app.evaluation.failure_policies import get_failure_policy
from app.schemas.schemas import OperationalState, QueryRequest, TaskCompletionStatus
from app.services.query_service import query_service


def test_failure_policy_rate_limit_properties():
    """Verify canonical failure policy definitions for rate limits and errors."""
    policy = get_failure_policy(OperationalState.LLM_RATE_LIMIT)
    assert policy.backoff_seconds > 0.0
    assert "rate limit" in policy.user_guidance.lower()


@pytest.mark.asyncio
async def test_llm_provider_error_handling():
    """Verify upstream provider exception maps to LLM_PROVIDER_ERROR."""
    req = QueryRequest(query="What malware does PHANTOM DRAGON use?")
    with patch("app.llm.mock_provider.MockLLMProvider.generate_grounded_answer", side_effect=RuntimeError("Provider 500")):
        resp = await query_service.execute_query(req)
        assert resp.operational_state == OperationalState.LLM_PROVIDER_ERROR
        assert resp.task_status == TaskCompletionStatus.TASK_FAILED
