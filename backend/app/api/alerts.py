"""
=============================================================
API ROUTER - SIEM Alerts
=============================================================
Handles ingestion and enrichment of SIEM alerts.
An alert comes in as a raw log line, gets processed to:
  1. Extract IOCs (IPs, domains, hashes)
  2. Query threat intel DB for each IOC
  3. Calculate composite risk score
  4. Generate LLM threat summary
  5. Return enriched alert with recommendations

Routes:
  GET  /api/alerts/          - List enriched alerts
  POST /api/alerts/          - Submit raw alert for enrichment
  GET  /api/alerts/{id}      - Get single enriched alert
  GET  /api/alerts/live      - WebSocket for real-time alerts
=============================================================
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.models.schemas import AlertCreate, AlertSeverity
from app.services.siem.alert_enricher import AlertEnricher
from app.core.supabase_client import get_supabase
from typing import List
from datetime import datetime
import uuid
import asyncio
import json
import logging
import random

logger = logging.getLogger(__name__)
router = APIRouter()

# Alert enrichment service
enricher = AlertEnricher()

# WebSocket connection manager for real-time alert streaming
class ConnectionManager:
    """Manages active WebSocket connections for live feed."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Send message to ALL connected WebSocket clients."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass  # Client disconnected, will be cleaned up

manager = ConnectionManager()


@router.get("/")
async def list_alerts(limit: int = 20):
    """Return recent enriched alerts, sorted by risk score."""
    supabase = get_supabase()

    if supabase is None:
        return _get_demo_alerts()

    try:
        result = supabase.table("alerts").select("*").order("risk_score", desc=True).limit(limit).execute()
        return result.data or _get_demo_alerts()
    except Exception as e:
        logger.error(f"List alerts error: {e}")
        return _get_demo_alerts()


@router.post("/")
async def submit_alert(alert: AlertCreate):
    """
    Submit a raw SIEM log for enrichment.
    Extracts IOCs, queries threat intel, generates AI summary.
    """
    logger.info(f"📨 New alert received from {alert.source_system}")

    # Run enrichment pipeline on the raw log
    enriched = await enricher.enrich_alert(alert)

    # Save to Supabase
    supabase = get_supabase()
    if supabase:
        supabase.table("alerts").insert(enriched).execute()

    # Broadcast to all WebSocket clients (real-time feed)
    await manager.broadcast({
        "event": "new_alert",
        "data": enriched
    })

    return enriched


@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    """
    WebSocket endpoint for real-time alert streaming.
    Frontend connects here to receive live updates without polling.
    Also sends simulated alerts every few seconds for demo purposes.
    """
    await manager.connect(websocket)
    try:
        # Send simulated live events to demonstrate real-time capability
        while True:
            await asyncio.sleep(random.uniform(3, 8))  # Random interval 3-8 seconds

            # Generate a simulated threat event
            demo_event = _generate_live_event()
            await manager.broadcast(demo_event)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")


def _generate_live_event():
    """Generate realistic simulated threat events for demo mode."""
    event_types = [
        {"type": "new_ioc", "severity": "high", "title": "Malicious IP Detected",
         "desc": "New C2 server communicating with internal hosts", "ioc": "45.33.32.156"},
        {"type": "alert_triggered", "severity": "critical", "title": "Ransomware Hash Match",
         "desc": "Known ransomware binary hash detected on endpoint", "ioc": "deadbeef12345678"},
        {"type": "new_ioc", "severity": "medium", "title": "Suspicious Domain Query",
         "desc": "DGA-generated domain queried by multiple hosts", "ioc": "xn--wbk5a5a.xyz"},
        {"type": "hunt_result", "severity": "high", "title": "Beaconing Pattern Found",
         "desc": "Regular outbound connections matching C2 signature", "ioc": "103.24.77.10"},
        {"type": "alert_triggered", "severity": "low", "title": "Port Scan Detected",
         "desc": "External IP scanning internal network ports", "ioc": "198.51.100.2"},
    ]

    event = random.choice(event_types)
    return {
        "event": event["type"],
        "data": {
            "id": str(uuid.uuid4()),
            "event_type": event["type"],
            "severity": event["severity"],
            "title": event["title"],
            "description": event["desc"],
            "ioc_value": event["ioc"],
            "risk_score": random.randint(30, 99),
            "source": random.choice(["Splunk", "Elastic", "Sentinel", "AlienVault OTX"]),
            "timestamp": datetime.utcnow().isoformat()
        }
    }


def _get_demo_alerts():
    """Demo alerts when Supabase is not configured."""
    return [
        {"id": "a1", "severity": "critical", "risk_score": 98,
         "source_system": "Splunk", "extracted_iocs": ["192.168.1.100", "evil-domain.xyz"],
         "llm_summary": "APT-29 affiliated C2 infrastructure detected. Immediate isolation recommended.",
         "recommended_actions": ["Block IP at perimeter firewall", "Isolate affected endpoints", "Initiate IR process"],
         "mitre_techniques": ["T1071.001", "T1566.001"],
         "raw_log": "2024-06-20 10:23:45 DENY TCP 192.168.1.100:443 -> 10.0.0.5:8443",
         "created_at": "2024-06-20T10:23:45Z"},
        {"id": "a2", "severity": "high", "risk_score": 77,
         "source_system": "Elastic",  "extracted_iocs": ["evil-domain.xyz"],
         "llm_summary": "Phishing domain used in credential harvesting campaign targeting financial sector.",
         "recommended_actions": ["Block domain in DNS", "Reset affected credentials", "Enable MFA"],
         "mitre_techniques": ["T1566.002", "T1078"],
         "raw_log": "DNS query for evil-domain.xyz from 10.0.1.42",
         "created_at": "2024-06-20T09:15:00Z"},
    ]
