"""
=============================================================
INGEST LOGS API — /api/ingest-logs
=============================================================
Accepts logs from any source (system, app, user, script).
Runs enrichment as a background task automatically.
Sends email alert if risk score >= 60.

Usage:
  POST /api/ingest-logs
  Body: { "logs": ["log line 1", "log line 2"], "source": "Windows" }

  Or single log:
  POST /api/ingest-logs
  Body: { "raw_log": "2026-02-22 blocked 185.220.101.45" }
=============================================================
"""

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import uuid
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class IngestRequest(BaseModel):
    raw_log:  Optional[str]       = None   # Single log line
    logs:     Optional[List[str]] = None   # Multiple log lines
    source:   Optional[str]       = "system"
    severity: Optional[str]       = "medium"


class IngestResponse(BaseModel):
    accepted:   int
    task_ids:   List[str]
    message:    str
    queued_at:  str


async def process_single_log(raw_log: str, source: str, task_id: str):
    """
    Background task:
    1. Extract IOCs
    2. Enrich (DB match + live APIs)
    3. Score risk
    4. Save to DB
    5. Send email if score >= 60
    6. Broadcast via WebSocket
    """
    logger.info(f"[{task_id}] Processing log from {source}")
    try:
        from app.services.siem.alert_enricher import AlertEnricher
        from app.core.database import get_db
        from app.services.email_service import send_threat_email

        enricher = AlertEnricher()
        enriched = await enricher.enrich_alert({
            "raw_log":       raw_log,
            "source_system": source,
            "severity":      "medium",
        })

        # Override ID with our task_id for tracking
        enriched["id"] = task_id

        # Save to database
        db = get_db()
        try:
            db.execute("""
                INSERT OR REPLACE INTO alerts
                (id, raw_log, source_system, severity, risk_score,
                 extracted_iocs, llm_summary, recommended_actions,
                 mitre_techniques, created_at, enriched_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                enriched["id"],
                enriched["raw_log"],
                enriched["source_system"],
                enriched["severity"],
                enriched["risk_score"],
                json.dumps(enriched.get("extracted_iocs", [])),
                enriched.get("llm_summary", ""),
                json.dumps(enriched.get("recommended_actions", [])),
                json.dumps(enriched.get("mitre_techniques", [])),
                enriched["created_at"],
                enriched.get("enriched_at"),
            ))
            db.commit()
            logger.info(f"[{task_id}] Saved to DB — risk: {enriched['risk_score']}/100 — {enriched['severity']}")
        finally:
            db.close()

        # Broadcast via WebSocket
        try:
            from app.api.alerts import manager
            await manager.broadcast({"event": "new_alert", "data": enriched})
        except Exception as e:
            logger.warning(f"[{task_id}] WebSocket broadcast failed: {e}")

        # Send email if risk >= 60
        risk = enriched.get("risk_score", 0)
        if risk >= 60:
            logger.info(f"[{task_id}] Risk {risk} >= 60 — sending email alert")
            sent = await send_threat_email(enriched)
            if sent:
                logger.info(f"[{task_id}] ✅ Email sent for risk {risk}/100")
            else:
                logger.warning(f"[{task_id}] ⚠️ Email failed — check SMTP settings in .env")
        else:
            logger.info(f"[{task_id}] Risk {risk} < 60 — no email sent")

    except Exception as e:
        logger.error(f"[{task_id}] Processing error: {e}")
        import traceback
        traceback.print_exc()


@router.post("/", response_model=IngestResponse)
async def ingest_logs(request: IngestRequest, background_tasks: BackgroundTasks):
    """
    Accept logs and process them in the background.
    Returns immediately — processing happens asynchronously.
    """
    # Collect all log lines
    log_lines = []

    if request.raw_log and request.raw_log.strip():
        log_lines.append(request.raw_log.strip())

    if request.logs:
        for line in request.logs:
            if line and line.strip():
                log_lines.append(line.strip())

    if not log_lines:
        return IngestResponse(
            accepted=0,
            task_ids=[],
            message="No log lines provided",
            queued_at=datetime.utcnow().isoformat()
        )

    # Queue each log line as a background task
    task_ids = []
    for line in log_lines[:20]:  # max 20 per request
        task_id = str(uuid.uuid4())
        task_ids.append(task_id)
        background_tasks.add_task(process_single_log, line, request.source or "system", task_id)

    logger.info(f"Queued {len(task_ids)} log(s) for background processing from '{request.source}'")

    return IngestResponse(
        accepted=len(task_ids),
        task_ids=task_ids,
        message=f"{len(task_ids)} log(s) queued for enrichment. Email sent if risk ≥ 60.",
        queued_at=datetime.utcnow().isoformat()
    )


@router.get("/status")
async def ingest_status():
    """Check how many alerts are in the database."""
    from app.core.database import get_db
    db = get_db()
    try:
        total  = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        high   = db.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('critical','high')").fetchone()[0]
        recent = db.execute(
            "SELECT raw_log, severity, risk_score, created_at FROM alerts ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
        return {
            "total_alerts":       total,
            "high_risk_alerts":   high,
            "recent":             [dict(r) for r in recent],
            "email_threshold":    60,
            "status":             "active"
        }
    finally:
        db.close()