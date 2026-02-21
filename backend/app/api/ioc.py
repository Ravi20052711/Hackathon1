"""
API ROUTER - IOC Management (Local SQLite)
Accepts both dict and Pydantic model for flexibility.
"""

from fastapi import APIRouter, Query, Body
from app.core.database import get_db
from app.services.enrichment.enrichment_pipeline import EnrichmentPipeline
from typing import Optional
from datetime import datetime
import uuid
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
enrichment = EnrichmentPipeline()


def row_to_dict(row):
    if row is None:
        return None
    d = dict(row)
    for field in ['tags', 'extracted_iocs', 'recommended_actions', 'mitre_techniques']:
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except:
                d[field] = []
    return d


@router.get("/stats")
async def get_ioc_stats():
    db = get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        high_risk = db.execute("SELECT COUNT(*) FROM iocs WHERE risk_score >= 70").fetchone()[0]
        critical = db.execute("SELECT COUNT(*) FROM iocs WHERE risk_score >= 90").fetchone()[0]
        avg = db.execute("SELECT AVG(risk_score) FROM iocs").fetchone()[0] or 0
        rows = db.execute("SELECT ioc_type, COUNT(*) as cnt FROM iocs GROUP BY ioc_type").fetchall()
        by_type = {row[0]: row[1] for row in rows}
        return {
            "total_iocs": total,
            "high_risk": high_risk,
            "critical": critical,
            "new_today": 0,
            "by_type": by_type,
            "avg_risk_score": round(avg, 1)
        }
    finally:
        db.close()


@router.get("/")
async def list_iocs(
    ioc_type: Optional[str] = Query(None),
    min_risk: int = Query(0),
    limit: int = Query(50),
    offset: int = Query(0),
):
    db = get_db()
    try:
        if ioc_type:
            rows = db.execute(
                "SELECT * FROM iocs WHERE ioc_type=? AND risk_score>=? ORDER BY risk_score DESC LIMIT ? OFFSET ?",
                (ioc_type, min_risk, limit, offset)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM iocs WHERE risk_score>=? ORDER BY risk_score DESC LIMIT ? OFFSET ?",
                (min_risk, limit, offset)
            ).fetchall()
        return [row_to_dict(r) for r in rows]
    finally:
        db.close()


@router.post("/")
async def create_ioc(ioc: dict = Body(...)):
    db = get_db()
    try:
        value = ioc.get('value', '')
        ioc_type = ioc.get('ioc_type', 'ip')

        enriched = await enrichment.enrich(value, ioc_type)
        ioc_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        db.execute("""
            INSERT INTO iocs (id, value, ioc_type, source, tags, notes, risk_score,
                vt_detections, vt_total, abuse_confidence, country, city,
                latitude, longitude, asn, first_seen, last_seen, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            ioc_id, value, ioc_type,
            ioc.get('source', 'manual'),
            json.dumps(ioc.get('tags', [])),
            ioc.get('notes'),
            enriched.get('risk_score', 0),
            enriched.get('vt_detections'),
            enriched.get('vt_total'),
            enriched.get('abuse_confidence'),
            enriched.get('country'),
            enriched.get('city'),
            enriched.get('latitude'),
            enriched.get('longitude'),
            enriched.get('asn'),
            now, now, now
        ))
        db.commit()

        row = db.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        return row_to_dict(row)
    except Exception as e:
        logger.error(f"Create IOC error: {e}")
        return {"error": str(e), "id": str(uuid.uuid4()), "value": ioc.get('value'), "risk_score": 0}
    finally:
        db.close()


@router.get("/{ioc_id}")
async def get_ioc(ioc_id: str):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM iocs WHERE id=?", (ioc_id,)).fetchone()
        if not row:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="IOC not found")
        return row_to_dict(row)
    finally:
        db.close()


@router.delete("/{ioc_id}")
async def delete_ioc(ioc_id: str):
    db = get_db()
    try:
        db.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))
        db.commit()
        return {"message": "IOC deleted", "id": ioc_id}
    finally:
        db.close()