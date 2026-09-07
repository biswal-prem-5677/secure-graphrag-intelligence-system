import pytest
from app.retrieval.query_analyzer import query_analyzer


def test_entity_extraction_threat_actor():
    res = query_analyzer.analyze("What malware does PHANTOM DRAGON use?")
    assert "PHANTOM DRAGON" in res.entities
    assert "USES" in res.intended_relationships


def test_multi_hop_depth_detection():
    res = query_analyzer.analyze(
        "What infrastructure is connected to PHANTOM DRAGON through malware relationships?"
    )
    assert res.is_multi_hop is True
    assert res.max_hops == 3


def test_cve_extraction():
    res = query_analyzer.analyze("Does DragonScale exploit CVE-2023-DEMO-001?")
    assert "CVE-2023-DEMO-001" in res.cves
    assert "DragonScale" in res.entities


def test_ip_address_extraction():
    res = query_analyzer.analyze("Tell me about connections to 203.0.113.42")
    assert "203.0.113.42" in res.ip_addresses
