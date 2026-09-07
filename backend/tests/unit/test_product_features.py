import pytest
from app.models.feedback import UserFeedbackCreate, feedback_store
from app.models.profile import profile_store
from app.models.saved import SavedInvestigationCreate, saved_store
from app.schemas.schemas import ConfidenceLevel


def test_profile_lifecycle_and_onboarding():
    p = profile_store.get_profile("analyst_prod")
    assert p.onboarding_completed is False
    profile_store.complete_onboarding("analyst_prod")
    assert profile_store.get_profile("analyst_prod").onboarding_completed is True
    profile_store.reset_onboarding("analyst_prod")
    assert profile_store.get_profile("analyst_prod").onboarding_completed is False


def test_saved_investigations_and_user_isolation():
    inv = SavedInvestigationCreate(
        query_id="Q1",
        query="What malware does PHANTOM DRAGON use?",
        title="Operation Jade Storm Analysis",
        answer="PHANTOM DRAGON utilizes DragonScale backdoor communicating with update-service.example.net.",
        confidence=ConfidenceLevel.HIGH,
        confidence_explanation="Supported by 2 CERT sources",
    )
    saved = saved_store.save("analyst_1", inv)
    assert saved.id is not None

    # Analyst 1 can see it
    list1 = saved_store.list_for_user("analyst_1")
    assert len(list1) == 1

    # Analyst 2 cannot see Analyst 1's saved items
    list2 = saved_store.list_for_user("analyst_2")
    assert len(list2) == 0

    # Rename
    saved_store.update_title("analyst_1", saved.id, "Updated Jade Storm Title")
    assert saved_store.get("analyst_1", saved.id).title == "Updated Jade Storm Title"

    # Delete
    deleted = saved_store.delete("analyst_1", saved.id)
    assert deleted is True
    assert len(saved_store.list_for_user("analyst_1")) == 0


def test_user_feedback_and_quality_metrics():
    fb = UserFeedbackCreate(
        query_id="Q-1",
        query="What is unknown actor X?",
        rating=5,
        comment="Accurate graph retrieval",
    )
    from app.models.feedback import UserFeedback
    feedback_store.submit_feedback(UserFeedback(**fb.model_dump(), user_id="analyst_fb"))
    metrics = feedback_store.get_metrics()
    assert metrics.total_feedback >= 1
    assert metrics.average_rating >= 4.0
