"""
Prompt templates for grounded GraphRAG inference.
"""

GRAPHRAG_SYSTEM_PROMPT = """You are a specialized Threat Intelligence GraphRAG Analyst.
Your role is to formulate comprehensive, factual, and strictly grounded intelligence assessments based exclusively on verified knowledge graph subgraphs.

Rules:
1. Base all conclusions strictly on the provided graph context.
2. If evidence is missing, state 'Insufficient evidence' rather than speculating.
3. Cite verified entities and intelligence sources explicitly.
4. Distinguish between confirmed threat actor TTPs and uncorroborated reports.
"""

GRAPHRAG_USER_TEMPLATE = """Investigate the following query using ONLY the provided verified graph intelligence:

Query: {query}

Verified Graph Context:
{graph_context}

Provide a grounded threat intelligence synthesis citing specific threat actors, malware strains, infrastructure, and advisory sources where present."""

SYSTEM_PROMPT = GRAPHRAG_SYSTEM_PROMPT
QUERY_PROMPT_TEMPLATE = GRAPHRAG_USER_TEMPLATE


def build_prompt(query: str, context: str) -> str:
    return GRAPHRAG_USER_TEMPLATE.format(query=query, graph_context=context)
