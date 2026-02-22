"""
API ROUTER - Alerts with Real-time Threat Checking
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Body
from app.core.database import get_db
from datetime import datetime
import uuid, json, asyncio, random, logging

logger = logging.getLogger(__name__)
router = APIRouter()


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
    # Parse db_matches if stored
    if 'db_matches' in d and isinstance(d.get('db_matches'), str):
        try:
            d['db_matches'] = json.loads(d['db_matches'])
        except:
            d['db_matches'] = []
    if 'live_intel' in d and isinstance(d.get('live_intel'), str):
        try:
            d['live_intel'] = json.loads(d['live_intel'])
        except:
            d['live_intel'] = []
    return d


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
async def submit_alert(alert: dict = Body(...)):
    """
    Submit raw log for enrichment.
    Checks against:
    1. Local SQLite database (instant)
    2. AbuseIPDB live API (if key set)
    3. VirusTotal live API (if key set)
    4. Free IP geo lookup (always works)
    """
    try:
        from app.services.siem.alert_enricher import AlertEnricher
        enricher = AlertEnricher()
        enriched = await enricher.enrich_alert(alert)

        # Save to DB
        db = get_db()
        try:
            db.execute("""
                INSERT INTO alerts
                (id, raw_log, source_system, severity, risk_score,
                 extracted_iocs, llm_summary, recommended_actions,
                 mitre_techniques, created_at, enriched_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                enriched['id'],
                enriched['raw_log'],
                enriched['source_system'],
                enriched['severity'],
                enriched['risk_score'],
                json.dumps(enriched.get('extracted_iocs', [])),
                enriched.get('llm_summary', ''),
                json.dumps(enriched.get('recommended_actions', [])),
                json.dumps(enriched.get('mitre_techniques', [])),
                enriched['created_at'],
                enriched.get('enriched_at'),
            ))
            db.commit()
        finally:
            db.close()

        await manager.broadcast({"event": "new_alert", "data": enriched})
        return enriched

    except Exception as e:
        logger.error(f"Alert enrichment error: {e}")
        import traceback; traceback.print_exc()
        now = datetime.utcnow().isoformat()
        return {
            "id": str(uuid.uuid4()),
            "raw_log": alert.get('raw_log', ''),
            "source_system": alert.get('source_system', 'manual'),
            "severity": "medium", "risk_score": 0,
            "extracted_iocs": [], "db_matches": [],
            "live_intel": [], "live_threats_found": 0,
            "llm_summary": f"Enrichment error: {str(e)}",
            "recommended_actions": ["Check backend logs"],
            "mitre_techniques": [], "created_at": now, "enriched_at": now,
        }


@router.websocket("/ws/live")
async def websocket_live_feed(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(random.uniform(4, 9))
            await manager.broadcast(_generate_live_event())
    except WebSocketDisconnect:
        manager.disconnect(websocket)


def _generate_live_event():
    events = [
        {"type": "new_ioc", "severity": "high",     "title": "Malicious IP Detected",  "ioc": "45.33.32.156"},
        {"type": "alert",   "severity": "critical",  "title": "Ransomware Hash Match",  "ioc": "deadbeef12345678"},
        {"type": "new_ioc", "severity": "medium",    "title": "Suspicious Domain",      "ioc": "xn--wbk5a5a.xyz"},
        {"type": "hunt",    "severity": "high",      "title": "C2 Beaconing Pattern",   "ioc": "103.24.77.10"},
    ]
    e = random.choice(events)
    return {"event": e["type"], "data": {
        "id": str(uuid.uuid4()), "event_type": e["type"],
        "severity": e["severity"], "title": e["title"],
        "ioc_value": e["ioc"], "risk_score": random.randint(40, 99),
        "source": random.choice(["Splunk", "Elastic", "CrowdStrike"]),
        "timestamp": datetime.utcnow().isoformat()
    }}