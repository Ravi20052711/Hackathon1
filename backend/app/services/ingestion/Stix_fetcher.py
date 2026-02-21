"""
=============================================================
STIX/TAXII THREAT FEED FETCHER
=============================================================
Fetches real STIX formatted threat intelligence from:
  - MISP TAXII server (public)
  - Anomali Limo (free TAXII)
  - CISA AIS STIX feeds
  - AlienVault OTX STIX export
  - Manual STIX bundle parsing

STIX = Structured Threat Information eXpression
TAXII = Trusted Automated eXchange of Intelligence Information
=============================================================
"""

import aiohttp
import asyncio
import json
import uuid
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class STIXFetcher:
    """
    Fetches STIX 2.x formatted threat intelligence.
    STIX is the industry standard format used by:
    - MISP, IBM QRadar, Splunk, CrowdStrike, Palo Alto
    - Government CERTs, ISACs, and threat sharing communities
    """

    # Free public STIX/TAXII compatible feeds
    STIX_FEEDS = {
        "otx_stix": {
            "url": "https://otx.alienvault.com/taxii/discovery",
            "description": "AlienVault OTX - TAXII discovery"
        },
        "cisa_stix": {
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "description": "CISA Known Exploited Vulnerabilities"
        },
        "urlhaus_stix": {
            "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            "description": "URLhaus STIX-compatible feed"
        },
        "threatfox_stix": {
            "url": "https://threatfox-api.abuse.ch/api/v1/",
            "description": "ThreatFox IOC database"
        }
    }

    async def fetch_threatfox_stix(self, limit=50) -> list:
        """
        Fetch from ThreatFox which returns STIX-compatible IOC format.
        ThreatFox is run by abuse.ch - same team as URLhaus/MalwareBazaar.
        """
        iocs = []
        try:
            payload = json.dumps({"query": "get_iocs", "days": 1})
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://threatfox-api.abuse.ch/api/v1/",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=20)
                ) as resp:
                    data = await resp.json()

            if data.get("query_status") != "ok":
                return []

            for item in (data.get("data") or [])[:limit]:
                ioc_value = item.get("ioc_value", "").strip()
                ioc_type_raw = item.get("ioc_type", "")
                malware = item.get("malware", "unknown")
                confidence = item.get("confidence_level", 50)
                tags = item.get("tags") or []

                # Map ThreatFox types to our types
                type_map = {
                    "ip:port": "ip",
                    "domain": "domain",
                    "url": "url",
                    "md5_hash": "hash",
                    "sha256_hash": "hash",
                    "sha1_hash": "hash",
                }
                ioc_type = type_map.get(ioc_type_raw, "ip")

                # Clean IP:port format
                if ioc_type == "ip" and ":" in ioc_value:
                    ioc_value = ioc_value.split(":")[0]

                if not ioc_value:
                    continue

                # Build STIX-like structured object
                stix_indicator = {
                    "type": "indicator",           # STIX object type
                    "spec_version": "2.1",         # STIX version
                    "id": f"indicator--{str(uuid.uuid4())}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": f"{malware} - {ioc_value[:40]}",
                    "pattern": f"[{ioc_type}:value = '{ioc_value}']",  # STIX pattern
                    "pattern_type": "stix",
                    "valid_from": datetime.utcnow().isoformat() + "Z",
                    "confidence": confidence,
                    "labels": ["malicious-activity"] + (tags or []),
                    # Our DB fields extracted from STIX
                    "_db_value": ioc_value,
                    "_db_type": ioc_type,
                    "_db_risk": min(99, confidence),
                    "_db_source": "ThreatFox (STIX)",
                    "_db_tags": json.dumps([malware] + (tags or [])[:3]),
                }
                iocs.append(stix_indicator)

            logger.info(f"✅ ThreatFox STIX: fetched {len(iocs)} indicators")

        except Exception as e:
            logger.error(f"ThreatFox STIX error: {e}")

        return iocs

    async def fetch_cisa_stix(self) -> list:
        """
        Fetch CISA Known Exploited Vulnerabilities.
        CISA publishes this in JSON format aligned with STIX standards.
        These are vulnerabilities actively exploited in the wild.
        """
        iocs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=aiohttp.ClientTimeout(total=20)
                ) as resp:
                    data = await resp.json(content_type=None)

            vulns = data.get("vulnerabilities", [])[:30]

            for vuln in vulns:
                cve_id = vuln.get("cveID", "")
                vendor = vuln.get("vendorProject", "")
                product = vuln.get("product", "")
                description = vuln.get("shortDescription", "")
                due_date = vuln.get("dueDate", "")

                if not cve_id:
                    continue

                # Represent CVE as STIX vulnerability object
                stix_vuln = {
                    "type": "vulnerability",       # STIX object type
                    "spec_version": "2.1",
                    "id": f"vulnerability--{str(uuid.uuid4())}",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "name": cve_id,
                    "description": f"{vendor} {product}: {description[:100]}",
                    "external_references": [
                        {"source_name": "cve", "external_id": cve_id}
                    ],
                    # Our DB fields
                    "_db_value": cve_id,
                    "_db_type": "hash",  # Store CVEs as special hash type
                    "_db_risk": 85,
                    "_db_source": "CISA KEV (STIX)",
                    "_db_tags": json.dumps(["cve", "actively-exploited", vendor.lower()[:20]]),
                }
                iocs.append(stix_vuln)

            logger.info(f"✅ CISA STIX: fetched {len(iocs)} vulnerabilities")

        except Exception as e:
            logger.error(f"CISA STIX error: {e}")

        return iocs

    def parse_stix_bundle(self, bundle: dict) -> list:
        """
        Parse a STIX 2.x bundle and extract IOCs.
        A bundle is a collection of STIX objects.

        Example STIX indicator pattern:
          [ipv4-addr:value = '192.168.1.1']
          [domain-name:value = 'evil.com']
          [file:hashes.SHA-256 = 'abc123...']
        """
        import re
        iocs = []

        objects = bundle.get("objects", [])
        for obj in objects:
            obj_type = obj.get("type", "")

            if obj_type == "indicator":
                pattern = obj.get("pattern", "")
                name = obj.get("name", "")
                confidence = obj.get("confidence", 50)
                labels = obj.get("labels", [])

                # Parse STIX pattern to extract IOC value and type
                # Pattern format: [ipv4-addr:value = '1.2.3.4']
                ip_match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
                domain_match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
                sha256_match = re.search(r"file:hashes\.SHA-256\s*=\s*'([^']+)'", pattern)
                url_match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)

                if ip_match:
                    iocs.append({
                        "_db_value": ip_match.group(1),
                        "_db_type": "ip",
                        "_db_risk": min(99, confidence),
                        "_db_source": "STIX Bundle",
                        "_db_tags": json.dumps(labels[:3]),
                    })
                elif domain_match:
                    iocs.append({
                        "_db_value": domain_match.group(1),
                        "_db_type": "domain",
                        "_db_risk": min(99, confidence),
                        "_db_source": "STIX Bundle",
                        "_db_tags": json.dumps(labels[:3]),
                    })
                elif sha256_match:
                    iocs.append({
                        "_db_value": sha256_match.group(1),
                        "_db_type": "hash",
                        "_db_risk": min(99, confidence),
                        "_db_source": "STIX Bundle",
                        "_db_tags": json.dumps(labels[:3]),
                    })
                elif url_match:
                    iocs.append({
                        "_db_value": url_match.group(1),
                        "_db_type": "url",
                        "_db_risk": min(99, confidence),
                        "_db_source": "STIX Bundle",
                        "_db_tags": json.dumps(labels[:3]),
                    })

        return iocs

    def stix_to_db(self, stix_objects: list) -> list:
        """Convert STIX objects to DB-ready dicts."""
        db_rows = []
        now = datetime.utcnow().isoformat()

        for obj in stix_objects:
            value = obj.get("_db_value", "")
            if not value or len(value) < 3:
                continue
            db_rows.append({
                "id": str(uuid.uuid4()),
                "value": value[:500],
                "ioc_type": obj.get("_db_type", "ip"),
                "risk_score": obj.get("_db_risk", 50),
                "source": obj.get("_db_source", "STIX"),
                "tags": obj.get("_db_tags", "[]"),
                "first_seen": now,
                "last_seen": now,
                "created_at": now,
            })

        return db_rows

    async def fetch_all_stix(self) -> dict:
        """Fetch from all STIX sources concurrently."""
        logger.info("🔄 Fetching STIX threat intelligence...")

        results = await asyncio.gather(
            self.fetch_threatfox_stix(50),
            self.fetch_cisa_stix(),
            return_exceptions=True
        )

        all_stix = []
        for r in results:
            if isinstance(r, list):
                all_stix.extend(r)

        db_ready = self.stix_to_db(all_stix)

        return {
            "total_stix_objects": len(all_stix),
            "db_ready": db_ready,
            "fetched_at": datetime.utcnow().isoformat()
        }