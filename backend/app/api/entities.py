"""
Entities & subgraphs exploration API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.logging import get_logger
from app.graph.client import neo4j_client
from app.models.user import User
from app.schemas.schemas import EntityGraphResponse, EntityRelationshipsResponse, EntityResponse, GraphData, GraphNode
from app.security.auth import get_current_user
from app.security.validation import validate_entity_id
from app.retrieval.graph_retriever import graph_retriever

logger = get_logger("api_entities")
router = APIRouter(prefix="/api/v1/entities", tags=["Entities & Subgraphs"])


@router.get("/{entity_id}", response_model=EntityResponse)
async def get_entity_by_id(
    entity_id: str,
    current_user: User = Depends(get_current_user),
) -> EntityResponse:
    """Retrieve an entity by its unique ID."""
    if not validate_entity_id(entity_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid entity identifier format")
    nodes = await graph_retriever.resolve_entities([entity_id])
    if not nodes:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entity not found")
    n = nodes[0]
    return EntityResponse(id=n.id, name=n.name, label=n.label, properties=n.properties)


@router.get("/{entity_id}/relationships", response_model=EntityRelationshipsResponse)
async def get_entity_relationships(
    entity_id: str,
    current_user: User = Depends(get_current_user),
) -> EntityRelationshipsResponse:
    """Retrieve all direct one-hop relationships for a given entity."""
    if not validate_entity_id(entity_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid entity identifier format")
    res = await graph_retriever.retrieve_subgraph([entity_id], max_depth=1)
    return EntityRelationshipsResponse(entity_id=entity_id, relationships=res.relationship_paths)


@router.get("/{entity_id}/graph", response_model=EntityGraphResponse)
async def get_entity_graph(
    entity_id: str,
    current_user: User = Depends(get_current_user),
) -> EntityGraphResponse:
    """Retrieve 1-hop subgraph suitable for D3.js visualization."""
    if not validate_entity_id(entity_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid entity identifier format")
    res = await graph_retriever.retrieve_subgraph([entity_id], max_depth=2)
    return EntityGraphResponse(entity_id=entity_id, graph=res.graph_data)
