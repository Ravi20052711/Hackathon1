"""
API ROUTER - Reports
Generates threat intelligence reports from DB data.
"""

from fastapi import APIRouter
from app.core.database import get_db
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
async def list_reports():
    """List available reports."""
    return [
        {"id": "1", "name": "IOC Summary Report", "type": "ioc_summary", "created_at": datetime.utcnow().isoformat()},
        {"id": "2", "name": "Threat Feed Report", "type": "feed_summary", "created_at": datetime.utcnow().isoformat()},
    ]


@router.get("/summary")
async def get_summary_report():
    """Generate a summary report from current DB data."""
    db = get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        critical = db.execute("SELECT COUNT(*) FROM iocs WHERE risk_score >= 90").fetchone()[0]
        high = db.execute("SELECT COUNT(*) FROM iocs WHERE risk_score >= 70 AND risk_score < 90").fetchone()[0]
        by_type = db.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type").fetchall()
        by_source = db.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC").fetchall()
        top_iocs = db.execute("SELECT value, ioc_type, risk_score, source FROM iocs ORDER BY risk_score DESC LIMIT 10").fetchall()
        total_alerts = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_iocs": total,
                "critical": critical,
                "high": high,
                "total_alerts": total_alerts,
            },
            "by_type": {r[0]: r[1] for r in by_type},
            "by_source": {r[0]: r[1] for r in by_source},
            "top_threats": [
                {"value": r[0], "type": r[1], "risk_score": r[2], "source": r[3]}
                for r in top_iocs
            ],
        }
    finally:
        db.close()


@router.post("/generate")
async def generate_ai_report(request: dict = None):
    """Generate AI-powered threat report using Claude if configured."""
    db = get_db()
    try:
        iocs = db.execute(
            "SELECT value, ioc_type, risk_score, source, tags FROM iocs ORDER BY risk_score DESC LIMIT 20"
        ).fetchall()

        ioc_list = []
        for r in iocs:
            ioc_list.append({
                "value": r[0], "ioc_type": r[1],
                "risk_score": r[2], "source": r[3],
                "tags": json.loads(r[4] or "[]")
            })
    finally:
        db.close()

    # Try Claude AI if configured
    try:
        from app.services.llm.llm_analyzer import LLMAnalyzer
        analyzer = LLMAnalyzer()
        ai_summary = await analyzer.summarize_campaign(ioc_list)
    except Exception as e:
        logger.error(f"AI report error: {e}")
        total = len(ioc_list)
        sources = list(set(i['source'] for i in ioc_list))
        avg_risk = sum(i['risk_score'] for i in ioc_list) // max(total, 1)
        ai_summary = (
            f"Threat Intelligence Report — {datetime.utcnow().strftime('%Y-%m-%d')}\n\n"
            f"Total IOCs analyzed: {total}\n"
            f"Data sources: {', '.join(sources)}\n"
            f"Average risk score: {avg_risk}/100\n\n"
            f"Add ANTHROPIC_API_KEY to .env for Claude AI-powered reports."
        )

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "ioc_count": len(ioc_list),
        "ai_summary": ai_summary,
        "top_threats": ioc_list[:5],
    }