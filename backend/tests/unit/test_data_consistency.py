import pytest
from app.retrieval.graph_retriever import graph_retriever


def test_graph_dataset_node_edge_consistency():
    data = graph_retriever._get_offline_data()
    node_ids = {n["id"] for n in data["nodes"]}

    # Verify all edge sources and targets exist in node set
    for e in data["edges"]:
        assert e["source"] in node_ids, f"Edge source {e['source']} not found in nodes"
        assert e["target"] in node_ids, f"Edge target {e['target']} not found in nodes"
