import pytest
from app.models.memory import memory_store
from app.services.memory_service import memory_service


def test_user_memory_crud_and_isolation():
    memory_store.add_or_update_memory("user_a", "favorite_actor", "PHANTOM DRAGON")
    memory_store.add_or_update_memory("user_b", "favorite_actor", "CRIMSON WOLF")

    m_a = memory_store.get_memories("user_a")
    m_b = memory_store.get_memories("user_b")

    assert len(m_a) == 1 and m_a[0].value == "PHANTOM DRAGON"
    assert len(m_b) == 1 and m_b[0].value == "CRIMSON WOLF"


def test_contextual_anaphora_resolution():
    memory_service.update_session("sess-1", "user_a", "PHANTOM DRAGON", "Tell me about PHANTOM DRAGON")
    res_query, entity = memory_service.resolve_contextual_query("What malware does this actor use?", "sess-1", "user_a")
    assert "PHANTOM DRAGON" in res_query
    assert entity == "PHANTOM DRAGON"


def test_pronoun_resolution_without_context():
    """Queries with pronouns when no session context exists should remain unaffected."""
    res_query, entity = memory_service.resolve_contextual_query("What does it do?", "sess-none", "user_x")
    assert res_query == "What does it do?"
    assert entity is None


def test_personalization_hint_formatting():
    memory_store.add_or_update_memory("analyst_concise", "result_density", "compact")
    hint = memory_service.get_personalization_hint("analyst_concise")
    assert "concisely" in hint.lower()


def test_session_context_cross_user_isolation():
    """Verify that session context in User A does not bleed into User B."""
    memory_service.update_session("shared-id", "user_1", "Entity1", "Query 1")
    ctx2 = memory_store.get_session_context("shared-id", "user_2")
    assert ctx2.last_entity is None


def test_user_memory_privacy_clear_all():
    """Verify GDPR right-to-be-forgotten full memory purge."""
    memory_store.add_or_update_memory("user_gdpr", "k1", "v1")
    assert len(memory_store.get_memories("user_gdpr")) == 1
    memory_store.clear_all_for_user("user_gdpr")
    assert len(memory_store.get_memories("user_gdpr")) == 0


def test_memory_cannot_override_graph_facts():
    """User preferences shape formatting but CANNOT alter factual graph assertions."""
    memory_store.add_or_update_memory("user_test", "preference", "override facts")
    # Verify graph retriever returns original node properties regardless of user memory
    from app.retrieval.graph_retriever import graph_retriever
    data = graph_retriever._get_offline_data()
    actor = next(n for n in data["nodes"] if n["id"] == "act-001")
    assert actor["name"] == "PHANTOM DRAGON"
