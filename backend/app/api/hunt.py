"""
API ROUTER - Threat Hunting
"""

from fastapi import APIRouter
from app.services.hunting.hunt_engine import HuntEngine
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
hunt_engine = HuntEngine()


@router.get("/")
async def list_hunts():
    """Return pre-built hunt queries."""
    return hunt_engine.get_prebuilt_hunts()


@router.post("/generate")
async def generate_hunt(ioc_value: str, ioc_type: str, risk_score: int = 50):
    """Generate Splunk, Elastic, Sigma queries for a specific IOC."""
    try:
        result = hunt_engine.generate_queries(ioc_value, ioc_type)
        return result
    except Exception as e:
        logger.error(f"Hunt generation error: {e}")
        return {"error": str(e)}


@router.get("/templates")
async def get_hunt_templates():
    """Pre-built hunt templates for common attack patterns."""
    return hunt_engine.get_prebuilt_hunts()