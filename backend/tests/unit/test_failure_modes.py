import pytest
from app.evaluation.failure_policies import FAILURE_POLICIES, get_failure_policy
from app.schemas.schemas import OperationalState


def test_all_21_operational_states_have_failure_policies():
    states = list(OperationalState)
    for s in states:
        policy = get_failure_policy(s)
        assert policy.state == s
        assert len(policy.user_guidance) > 10
        assert len(policy.recovery_action) > 5
