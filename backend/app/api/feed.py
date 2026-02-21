"""
API ROUTER - Real Threat Feed
Fetches REAL data from URLhaus, Feodo Tracker, MalwareBazaar, STIX/TAXII
"""

from fastapi import APIRouter, BackgroundTasks, Body
from app.core.database import get_db
from datetime import datetime
import uuid
import json
import logging
import asyncio
import aiohttp
import csv
from io import StringIO

logger = logging.getLogger(__name__)
router = APIRouter()

_last_fetch = {}
_fetch_counts = {}


async def fetch_urlhaus(limit=50):
    iocs = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://urlhaus.abuse.ch/downloads/csv_recent/",
                timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                text = await resp.text()
        reader = csv.reader(StringIO(text))
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            try:
                if len(row) < 4:
                    continue
                url = row[2].strip().strip('"')
                status = row[3].strip().strip('"')
                threat = row[5].strip().strip('"') if len(row) > 5 else 'malware'
                if not url.startswith('http'):
                    continue
                iocs.append({
                    "value": url[:500],
                    "ioc_type": "url",
                    "risk_score": 95 if status == 'online' else 70,
                    "source": "URLhaus",
                    "tags": json.dumps([threat, status]),
                })
                if len(iocs) >= limit:
                    break
            except:
                continue
        logger.info(f"URLhaus: {len(iocs)} URLs")
    except Exception as e:
        logger.error(f"URLhaus error: {e}")
    return iocs


async def fetch_feodo(limit=50):
    iocs = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                text = await resp.text()
        reader = csv.reader(StringIO(text))
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            try:
                if len(row) < 2:
                    continue
                ip = row[1].strip().strip('"')
                malware = row[5].strip().strip('"') if len(row) > 5 else 'botnet'
                if len(ip.split('.')) != 4:
                    continue
                iocs.append({
                    "value": ip,
                    "ioc_type": "ip",
                    "risk_score": 90,
                    "source": "Feodo Tracker",
                    "tags": json.dumps([malware, "c2", "botnet"]),
                })
                if len(iocs) >= limit:
                    break
            except:
                continue
        logger.info(f"Feodo: {len(iocs)} IPs")
    except Exception as e:
        logger.error(f"Feodo error: {e}")
    return iocs


async def fetch_malwarebazaar(limit=30):
    iocs = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://bazaar.abuse.ch/export/csv/recent/",
                timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                text = await resp.text()
        reader = csv.reader(StringIO(text))
        for row in reader:
            if not row or row[0].startswith('#'):
                continue
            try:
                if len(row) < 2:
                    continue
                sha256 = row[1].strip().strip('"')
                signature = row[8].strip().strip('"') if len(row) > 8 else 'malware'
                if len(sha256) != 64:
                    continue
                iocs.append({
                    "value": sha256,
                    "ioc_type": "hash",
                    "risk_score": 95,
                    "source": "MalwareBazaar",
                    "tags": json.dumps([signature, "malware"]),
                })
                if len(iocs) >= limit:
                    break
            except:
                continue
        logger.info(f"MalwareBazaar: {len(iocs)} hashes")
    except Exception as e:
        logger.error(f"MalwareBazaar error: {e}")
    return iocs


def insert_iocs(iocs):
    db = get_db()
    inserted = 0
    try:
        for ioc in iocs:
            existing = db.execute(
                "SELECT id FROM iocs WHERE value=?", (ioc["value"],)
            ).fetchone()
            if not existing:
                now = datetime.utcnow().isoformat()
                db.execute("""
                    INSERT INTO iocs
                    (id, value, ioc_type, risk_score, source, tags, first_seen, last_seen, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    str(uuid.uuid4()), ioc["value"], ioc["ioc_type"],
                    ioc["risk_score"], ioc["source"], ioc["tags"],
                    now, now, now
                ))
                inserted += 1
        db.commit()
        logger.info(f"Inserted {inserted} new IOCs")
    except Exception as e:
        logger.error(f"Insert error: {e}")
    finally:
        db.close()
    return inserted


async def do_fetch(source: str, limit: int):
    logger.info(f"Starting fetch: {source}")
    all_iocs = []
    try:
        if source == "urlhaus":
            all_iocs = await fetch_urlhaus(limit)
        elif source == "feodo":
            all_iocs = await fetch_feodo(limit)
        elif source == "malwarebazaar":
            all_iocs = await fetch_malwarebazaar(limit)
        else:
            results = await asyncio.gather(
                fetch_urlhaus(limit),
                fetch_feodo(limit),
                fetch_malwarebazaar(limit),
                return_exceptions=True
            )
            for r in results:
                if isinstance(r, list):
                    all_iocs.extend(r)

        inserted = insert_iocs(all_iocs)
        _last_fetch[source] = datetime.utcnow().isoformat()
        _fetch_counts[source] = inserted
        logger.info(f"Fetch complete: {inserted} new IOCs from {source}")
    except Exception as e:
        logger.error(f"Fetch error: {e}")


@router.get("/")
async def get_feed(limit: int = 50):
    db = get_db()
    try:
        rows = db.execute("""
            SELECT id, value, ioc_type, risk_score, source, tags, country, city, created_at
            FROM iocs ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()

        result = []
        for r in rows:
            d = dict(r)
            try:
                d['tags'] = json.loads(d.get('tags', '[]'))
            except:
                d['tags'] = []
            score = d['risk_score']
            result.append({
                "id": d["id"],
                "event_type": f"new_{d['ioc_type']}",
                "severity": "critical" if score >= 90 else "high" if score >= 70 else "medium",
                "title": f"{d['ioc_type'].upper()} — {d['value'][:60]}",
                "description": f"Source: {d['source']} | Risk: {score}/100",
                "ioc_value": d["value"],
                "risk_score": score,
                "source": d["source"],
                "tags": d["tags"],
                "timestamp": d["created_at"],
            })
        return result
    finally:
        db.close()


@router.post("/refresh")
async def refresh_feeds(
    background_tasks: BackgroundTasks,
    source: str = "all",
    limit: int = 50
):
    background_tasks.add_task(do_fetch, source, limit)
    return {
        "message": f"Fetching from {source}...",
        "source": source,
        "status": "started"
    }


@router.get("/refresh/status")
async def get_status():
    db = get_db()
    try:
        total = db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        by_source = db.execute(
            "SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC"
        ).fetchall()
        return {
            "total_iocs": total,
            "last_fetched": _last_fetch,
            "last_inserted": _fetch_counts,
            "by_source": {r[0]: r[1] for r in by_source},
        }
    finally:
        db.close()


@router.post("/refresh/stix")
async def refresh_stix_feeds(background_tasks: BackgroundTasks):
    """
    Fetch real STIX/TAXII threat intelligence.
    Sources: ThreatFox (STIX 2.1), CISA KEV (STIX-aligned)
    """
    async def do_stix_fetch():
        try:
            from app.services.ingestion.stix_fetcher import STIXFetcher
            fetcher = STIXFetcher()
            result = await fetcher.fetch_all_stix()
            inserted = insert_iocs(result["db_ready"])
            _last_fetch["stix"] = datetime.utcnow().isoformat()
            _fetch_counts["stix"] = inserted
            logger.info(f"✅ STIX fetch complete: {inserted} new IOCs")
        except Exception as e:
            logger.error(f"STIX fetch error: {e}")

    background_tasks.add_task(do_stix_fetch)
    return {
        "message": "Fetching STIX/TAXII threat intelligence...",
        "sources": ["ThreatFox STIX 2.1", "CISA KEV"],
        "status": "started"
    }


@router.post("/stix/parse")
async def parse_stix_bundle(bundle: dict = Body(...)):
    """
    Parse and import a STIX 2.x bundle uploaded by the user.
    Accepts any valid STIX 2.x JSON bundle.
    """
    try:
        from app.services.ingestion.stix_fetcher import STIXFetcher
        fetcher = STIXFetcher()
        stix_objects = fetcher.parse_stix_bundle(bundle)
        db_rows = fetcher.stix_to_db(stix_objects)
        inserted = insert_iocs(db_rows)
        return {
            "message": f"STIX bundle parsed successfully",
            "objects_found": len(stix_objects),
            "inserted": inserted,
        }
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"STIX parse error: {str(e)}")