"""
=============================================================
API ROUTER - Threat Feed (Local SQLite)
=============================================================
"""

from fastapi import APIRouter
from app.core.database import get_db
from datetime import datetime
import uuid
import random
import json

router = APIRouter()

DEMO_SOURCES = ["AlienVault OTX", "URLhaus", "MalwareBazaar", "AbuseIPDB", "VirusTotal"]
DEMO_EVENTS = [
    ("new_c2_ip", "high", "New C2 Server Identified", "Botnet C2 infrastructure detected"),
    ("malware_hash", "critical", "Novel Ransomware Variant", "Zero-day ransomware targeting enterprises"),
    ("phishing_domain", "medium", "Phishing Campaign Active", "Spear-phishing impersonating Microsoft"),
    ("apt_ioc", "high", "APT Activity Detected", "Lazarus Group TTPs observed"),
    ("vuln_exploit", "critical", "Active Exploitation", "CVE being actively exploited in the wild"),
]


@router.get("/")
async def get_feed(limit: int = 30):
    db = get_db()
    try:
        rows = db.execute(
            "SELECT * FROM feed_items ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        if rows:
            result = []
            for r in rows:
                d = dict(r)
                try:
                    d['tags'] = json.loads(d.get('tags', '[]'))
                except:
                    d['tags'] = []
                result.append(d)
            return result
    finally:
        db.close()

    return _generate_demo_feed(limit)


def _generate_demo_feed(count: int = 30):
    items = []
    for i in range(count):
        event = random.choice(DEMO_EVENTS)
        items.append({
            "id": str(uuid.uuid4()),
            "event_type": event[0],
            "severity": event[1],
            "title": event[2],
            "description": event[3],
            "ioc_value": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "risk_score": random.randint(40, 99),
            "source": random.choice(DEMO_SOURCES),
            "timestamp": datetime.utcnow().isoformat(),
            "tags": random.sample(["apt", "ransomware", "phishing", "c2"], k=2)
        })
    return items