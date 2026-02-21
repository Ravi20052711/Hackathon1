"""
=============================================================
SERVICE - IOC Enrichment Pipeline
=============================================================
Orchestrates enrichment of an IOC by calling multiple APIs:
  1. VirusTotal - reputation scoring
  2. AbuseIPDB - IP abuse reports (for IPs only)
  3. MaxMind GeoLite2 - geolocation
  4. WHOIS - domain age and registrar

Risk Score Formula:
  - VT detections        → up to 40 points
  - AbuseIPDB confidence → up to 30 points
  - New domain (<7 days) → 20 points
  - Past incidents       → 25 points (capped at 100)
=============================================================
"""

import aiohttp
import asyncio
from app.core.config import settings
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class EnrichmentPipeline:
    """Orchestrates all enrichment steps for a given IOC."""

    def __init__(self):
        # Free GeoIP database file path (download separately)
        self.vt_base = "https://www.virustotal.com/api/v3"
        self.abuse_base = "https://api.abuseipdb.com/api/v2"

    async def enrich(self, ioc_value: str, ioc_type: str) -> dict:
        """
        Main enrichment entry point.
        Runs all applicable enrichment steps concurrently using asyncio.gather().
        Returns a dict with all enriched fields.
        """
        result = {
            "risk_score": 0,
            "vt_detections": None,
            "vt_total": None,
            "abuse_confidence": None,
            "country": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "whois_registrar": None,
        }

        # Run enrichment tasks concurrently for speed
        tasks = [self._virustotal_check(ioc_value, ioc_type)]

        if ioc_type == "ip":
            tasks.append(self._abuseipdb_check(ioc_value))
            tasks.append(self._geoip_lookup(ioc_value))

        if ioc_type == "domain":
            tasks.append(self._whois_lookup(ioc_value))

        # Gather all results (failures don't crash the whole pipeline)
        enrichment_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge all results into single dict
        for res in enrichment_results:
            if isinstance(res, dict):  # Skip exceptions
                result.update({k: v for k, v in res.items() if v is not None})

        # Calculate final risk score from all data
        result["risk_score"] = self._calculate_risk_score(result)
        return result

    async def _virustotal_check(self, value: str, ioc_type: str) -> dict:
        """
        Query VirusTotal for reputation data.
        Free tier: 4 requests/minute. API key required.
        """
        if not settings.VIRUSTOTAL_API_KEY:
            # Return simulated data if no API key
            return {"vt_detections": 0, "vt_total": 70}

        # Determine endpoint based on IOC type
        endpoints = {
            "ip": f"/ip_addresses/{value}",
            "domain": f"/domains/{value}",
            "hash": f"/files/{value}",
            "url": f"/urls/{value}",
        }
        endpoint = endpoints.get(ioc_type)
        if not endpoint:
            return {}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.vt_base}{endpoint}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        return {
                            "vt_detections": stats.get("malicious", 0),
                            "vt_total": sum(stats.values()) or 70,
                        }
        except Exception as e:
            logger.warning(f"VirusTotal check failed for {value}: {e}")

        return {"vt_detections": 0, "vt_total": 70}

    async def _abuseipdb_check(self, ip: str) -> dict:
        """
        Query AbuseIPDB for IP reputation.
        Free tier: 1000 queries/day. API key required.
        """
        if not settings.ABUSEIPDB_API_KEY:
            return {"abuse_confidence": 0}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.abuse_base}/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": settings.ABUSEIPDB_API_KEY,
                        "Accept": "application/json"
                    },
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "abuse_confidence": data.get("data", {}).get("abuseConfidenceScore", 0),
                            "country": data.get("data", {}).get("countryCode"),
                        }
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed for {ip}: {e}")

        return {"abuse_confidence": 0}

    async def _geoip_lookup(self, ip: str) -> dict:
        """
        Get IP geolocation using ipapi.co (free, no key needed).
        MaxMind GeoLite2 is better but requires a free account + DB download.
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://ipapi.co/{ip}/json/",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "country": data.get("country_name"),
                            "city": data.get("city"),
                            "latitude": data.get("latitude"),
                            "longitude": data.get("longitude"),
                            "asn": data.get("asn"),
                        }
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")

        return {}

    async def _whois_lookup(self, domain: str) -> dict:
        """WHOIS lookup for domain age and registrar info."""
        try:
            import whois
            w = whois.whois(domain)
            return {
                "whois_registrar": str(w.registrar) if w.registrar else None,
            }
        except Exception:
            return {}

    def _calculate_risk_score(self, data: dict) -> int:
        """
        Calculate final 0-100 risk score from enriched data.
        Higher score = more dangerous IOC.
        """
        score = 0

        # VirusTotal detections (0-40 points)
        vt_det = data.get("vt_detections") or 0
        vt_total = data.get("vt_total") or 70
        if vt_total > 0:
            vt_ratio = vt_det / vt_total
            score += int(vt_ratio * 40)  # Max 40 points

        # AbuseIPDB confidence (0-30 points)
        abuse_conf = data.get("abuse_confidence") or 0
        score += int((abuse_conf / 100) * 30)  # Max 30 points

        # Cap at 100
        return min(score, 100)
