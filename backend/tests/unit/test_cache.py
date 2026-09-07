import pytest
from app.cache.cache import QueryCache


def test_cache_set_and_get():
    cache = QueryCache(maxsize=10, ttl=60)
    cache.set("What is DragonScale?", "Cached answer")
    hit = cache.get("what is dragonscale?")
    assert hit == "Cached answer"

    miss = cache.get("What is Cobalt Strike?")
    assert miss is None

    stats = cache.get_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
