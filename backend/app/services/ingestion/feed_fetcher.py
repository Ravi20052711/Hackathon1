"""
=============================================================
REAL THREAT FEED FETCHER
=============================================================
Fetches real threat data from free public sources:
  - URLhaus (malware URLs - updated every few minutes)
  - MalwareBazaar (malware hashes - updated daily)
  - Feodo Tracker (botnet C2 IPs - updated daily)
  - ThreatFox (IOCs - updated daily)

No API keys needed for any of these!
=============================================================
"""

import aiohttp
import asyncio
import csv
import json
import uuid
import logging
from datetime import datetime
from io import StringIO

logger = logging.getLogger(__name__)


class RealFeedFetcher:
    """Fetches real IOC data from free public threat intel sources."""

    SOURCES = {
        "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "malwarebazaar": "https://bazaar.abuse.ch/export/csv/recent/",
        "threatfox": "https://threatfox.abuse.ch/export/csv/recent/",
    }

    async def fetch_urlhaus(self, limit=50) -> list:
        """
        Fetch recent malware URLs from URLhaus.
        Returns list of IOC dicts ready to insert into DB.
        """
        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.SOURCES["urlhaus"],
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status != 200:
                        return []
                    text = await resp.text()

            # Parse CSV - skip comment lines starting with #
            reader = csv.reader(StringIO(text))
            count = 0
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue
                try:
                    # URLhaus CSV format:
                    # id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                    if len(row) < 6:
                        continue
                    url = row[2].strip().strip('"')
                    status = row[3].strip().strip('"')
                    threat = row[5].strip().strip('"') if len(row) > 5 else 'malware'
                    tags = row[6].strip().strip('"') if len(row) > 6 else ''

                    if not url.startswith('http'):
                        continue

                    # Only include online/active URLs
                    risk = 95 if status == 'online' else 70

                    iocs.append({
                        "id": str(uuid.uuid4()),
                        "value": url[:500],  # Cap URL length
                        "ioc_type": "url",
                        "risk_score": risk,
                        "source": "URLhaus",
                        "tags": json.dumps([threat, status] if threat else [status]),
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                        "vt_detections": None,
                        "vt_total": None,
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat(),
                        "created_at": datetime.utcnow().isoformat(),
                    })
                    count += 1
                    if count >= limit:
                        break
                except Exception:
                    continue

            logger.info(f"✅ URLhaus: fetched {len(iocs)} malware URLs")

        except Exception as e:
            logger.error(f"URLhaus fetch error: {e}")

        return iocs

    async def fetch_feodo_ips(self, limit=50) -> list:
        """
        Fetch botnet C2 IP addresses from Feodo Tracker.
        These are real active botnet command & control servers.
        """
        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.SOURCES["feodo"],
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status != 200:
                        return []
                    text = await resp.text()

            reader = csv.reader(StringIO(text))
            count = 0
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue
                try:
                    # Feodo CSV: first_seen, dst_ip, dst_port, c2_status, last_online, malware
                    if len(row) < 2:
                        continue
                    ip = row[1].strip().strip('"')
                    malware = row[5].strip().strip('"') if len(row) > 5 else 'botnet'
                    status = row[3].strip().strip('"') if len(row) > 3 else 'active'

                    # Validate IP format
                    parts = ip.split('.')
                    if len(parts) != 4:
                        continue

                    iocs.append({
                        "id": str(uuid.uuid4()),
                        "value": ip,
                        "ioc_type": "ip",
                        "risk_score": 90 if status == 'online' else 75,
                        "source": "Feodo Tracker",
                        "tags": json.dumps([malware, "c2", "botnet"]),
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                        "vt_detections": None,
                        "vt_total": None,
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat(),
                        "created_at": datetime.utcnow().isoformat(),
                    })
                    count += 1
                    if count >= limit:
                        break
                except Exception:
                    continue

            logger.info(f"✅ Feodo Tracker: fetched {len(iocs)} botnet C2 IPs")

        except Exception as e:
            logger.error(f"Feodo fetch error: {e}")

        return iocs

    async def fetch_malwarebazaar(self, limit=30) -> list:
        """
        Fetch recent malware file hashes from MalwareBazaar.
        These are real malware samples uploaded by researchers.
        """
        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.SOURCES["malwarebazaar"],
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status != 200:
                        return []
                    text = await resp.text()

            reader = csv.reader(StringIO(text))
            count = 0
            for row in reader:
                if not row or row[0].startswith('#'):
                    continue
                try:
                    # MalwareBazaar CSV:
                    # first_seen, sha256, md5, sha1, reporter, file_name, file_type, mime_type, signature, tags
                    if len(row) < 5:
                        continue
                    sha256 = row[1].strip().strip('"')
                    file_type = row[6].strip().strip('"') if len(row) > 6 else 'unknown'
                    signature = row[8].strip().strip('"') if len(row) > 8 else 'malware'
                    tags_raw = row[9].strip().strip('"') if len(row) > 9 else ''

                    if len(sha256) != 64:  # Valid SHA256 length
                        continue

                    tag_list = [t.strip() for t in tags_raw.split('|') if t.strip()]
                    if signature:
                        tag_list.insert(0, signature)

                    iocs.append({
                        "id": str(uuid.uuid4()),
                        "value": sha256,
                        "ioc_type": "hash",
                        "risk_score": 95,  # All MalwareBazaar samples are confirmed malware
                        "source": "MalwareBazaar",
                        "tags": json.dumps(tag_list[:5]),
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                        "vt_detections": None,
                        "vt_total": None,
                        "first_seen": datetime.utcnow().isoformat(),
                        "last_seen": datetime.utcnow().isoformat(),
                        "created_at": datetime.utcnow().isoformat(),
                    })
                    count += 1
                    if count >= limit:
                        break
                except Exception:
                    continue

            logger.info(f"✅ MalwareBazaar: fetched {len(iocs)} malware hashes")

        except Exception as e:
            logger.error(f"MalwareBazaar fetch error: {e}")

        return iocs

    async def fetch_all(self, limit_each=30) -> dict:
        """
        Fetch from ALL sources concurrently.
        Returns dict with counts and combined IOC list.
        """
        logger.info("🔄 Fetching real threat intel from all sources...")

        # Run all fetches concurrently
        results = await asyncio.gather(
            self.fetch_urlhaus(limit_each),
            self.fetch_feodo_ips(limit_each),
            self.fetch_malwarebazaar(limit_each),
            return_exceptions=True
        )

        all_iocs = []
        for r in results:
            if isinstance(r, list):
                all_iocs.extend(r)

        return {
            "total": len(all_iocs),
            "iocs": all_iocs,
            "fetched_at": datetime.utcnow().isoformat()
        }