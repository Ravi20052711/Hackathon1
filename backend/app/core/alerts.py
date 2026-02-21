"""
=============================================================
API ROUTER - Alerts (Local SQLite)
=============================================================
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.database import get_db
from app.services.siem.alert_enricher import AlertEnricher
from app.models.schemas import AlertCreate
from datetime import datetime
import uuid
import json
import asyncio
import random
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
enricher = AlertEnricher()


def row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for field in ['extracted_iocs', 'recommended_actions', 'mitre_techniques']:
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except:
                d[field] = []
    return d


class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for conn in self.active_connections[:]:
            try:
                await conn.send_json(message)
            except:
                self.active_connections.remove(conn)


manager = ConnectionManager()


@router.get("/")
async def list_alerts(limit: int = 20):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM alerts ORDER BY risk_score DESC LIMIT ?", (limit,)
        ).fetchall()
        return [row_to_dict(r) for r in rows]
    finally:
        db.close()


@router.post("/")
async def submit_alert(alert: AlertCreate):
    enriched = await enricher.enrich_alert(alert)

    db = get_db()
    try:
        db.execute("""
            INSERT INTO alerts (id, raw_log, source_system, severity, risk_score,
                extracted_iocs, llm_summary, recommended_actions, mitre_techniques,
                created_at, enriched_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            enriched['id'], enriched['raw_log'], enriched['source_system'],
            enriched['severity'], enriched['risk_score'],
            json.dumps(enriched.get('extracted_iocs', [])),
            enriched.get('llm_summary'),
            json.dumps(enriched.get('recommended_actions', [])),
            json.dumps(enriched.get('mitre_techniques', [])),
            enriched['created_at'], enriched.get('enriched_at')
        ))
        db.commit()
    finally:
        db.close()

    await manager.broadcast({"event": "new_alert", "data": enriched})
    return enriched


@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(random.uniform(3, 8))
            event = _generate_live_event()
            await manager.broadcast(event)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


def _generate_live_event():
    events = [
        {"type": "new_ioc", "severity": "high", "title": "Malicious IP Detected", "desc": "New C2 server identified", "ioc": "45.33.32.156"},
        {"type": "alert_triggered", "severity": "critical", "title": "Ransomware Hash Match", "desc": "Known ransomware binary detected", "ioc": "deadbeef12345678"},
        {"type": "new_ioc", "severity": "medium", "title": "Suspicious Domain", "desc": "DGA domain queried by multiple hosts", "ioc": "xn--wbk5a5a.xyz"},
        {"type": "hunt_result", "severity": "high", "title": "Beaconing Pattern Found", "desc": "Regular C2 beaconing detected", "ioc": "103.24.77.10"},
    ]
    event = random.choice(events)
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
            "source": random.choice(["Splunk", "Elastic", "AlienVault OTX"]),
            "timestamp": datetime.utcnow().isoformat()
        }
    }