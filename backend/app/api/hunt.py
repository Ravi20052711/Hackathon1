"""
=============================================================
API ROUTER - Threat Hunting
=============================================================
Auto-generates hunt queries from threat intelligence.
"""

from fastapi import APIRouter
from app.services.hunting.hunt_engine import HuntEngine
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
hunt_engine = HuntEngine()


@router.get("/")
async def list_hunts():
    """Return all generated hunt queries sorted by creation time."""
    return hunt_engine.get_all_hunts()


@router.post("/generate")
async def generate_hunt(ioc_value: str, ioc_type: str, risk_score: int = 50):
    """
    Generate hunt queries for a specific IOC.
    Returns Splunk SPL, Elastic KQL, and Sigma YAML.
    """
    return hunt_engine.generate_hunt_queries(ioc_value, ioc_type, risk_score)


@router.get("/templates")
async def get_hunt_templates():
    """Pre-built hunt templates for common attack patterns."""
    return hunt_engine.get_templates()
