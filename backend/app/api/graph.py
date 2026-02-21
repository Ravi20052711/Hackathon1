"""
=============================================================
API ROUTER - Graph Analysis
=============================================================
Serves graph data for the Cytoscape.js visualization.
Nodes = IOCs/ThreatActors/Campaigns
Edges = Relationships between them

Routes:
  GET /api/graph/          - Full graph data for visualization
  GET /api/graph/stats     - Graph analytics (centrality, communities)
  POST /api/graph/path     - Find path between two nodes
=============================================================
"""

from fastapi import APIRouter
from app.services.graph.graph_analyzer import GraphAnalyzer
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

# Graph analysis engine using NetworkX
graph_analyzer = GraphAnalyzer()


@router.get("/")
async def get_graph_data():
    """
    Returns nodes and edges formatted for Cytoscape.js.
    Cytoscape expects: { nodes: [{data:{id,label,...}}], edges: [{data:{source,target}}] }
    """
    return graph_analyzer.get_graph_for_visualization()


@router.get("/stats")
async def get_graph_stats():
    """Graph analytics: community count, most connected nodes, etc."""
    return graph_analyzer.get_stats()


@router.post("/path")
async def find_attack_path(source_id: str, target_id: str):
    """
    Find the shortest connection path between two nodes.
    Useful for understanding how threat actors connect to victim infrastructure.
    """
    path = graph_analyzer.find_path(source_id, target_id)
    return {"path": path, "length": len(path)}
