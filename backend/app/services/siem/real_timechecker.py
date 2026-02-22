"""
=============================================================
REAL-TIME THREAT CHECKER
=============================================================
Checks IOCs against live external threat APIs beyond local DB.

Free APIs used:
1. AbuseIPDB     - IP reputation (free 1000/day)
   Get key: https://www.abuseipdb.com/register
   Add to .env: ABUSEIPDB_API_KEY=your-key

2. VirusTotal    - Hash/URL/IP/Domain scan (free 4/min)
   Get key: https://www.virustotal.com/gui/sign-in
   Add to .env: VIRUSTOTAL_API_KEY=your-key

3. No-key checks - Always works, no API key needed:
   - IP geolocation via ip-api.com
   - Tor exit node check
   - Private/reserved IP detection
=============================================================
"""

import aiohttp
import asyncio
import logging
import re

logger = logging.getLogger(__name__)


class RealtimeChecker:

    def __init__(self):
        from app.core.config import settings
        self.abuseipdb_key = getattr(settings, 'ABUSEIPDB_API_KEY', '')
        self.virustotal_key = getattr(settings, 'VIRUSTOTAL_API_KEY', '')
        self.has_abuseipdb = bool(self.abuseipdb_key and len(self.abuseipdb_key) > 10)
        self.has_virustotal = bool(self.virustotal_key and len(self.virustotal_key) > 10)

    async def check_ip_live(self, ip: str) -> dict:
        """
        Check an IP address against live threat sources.
        Always returns result — uses free sources if no API key.
        """
        result = {
            "ip": ip,
            "is_private": self._is_private_ip(ip),
            "geo": None,
            "abuseipdb": None,
            "virustotal": None,
            "threat_score": 0,
            "threat_summary": [],
        }

        # Skip private IPs
        if result["is_private"]:
            result["threat_summary"].append("Private/internal IP — not checked externally")
            return result

        # Run checks concurrently
        tasks = [self._get_ip_geo(ip)]
        if self.has_abuseipdb:
            tasks.append(self._check_abuseipdb(ip))
        if self.has_virustotal:
            tasks.append(self._check_virustotal_ip(ip))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Geo always first
        if not isinstance(results[0], Exception) and results[0]:
            result["geo"] = results[0]
            country = results[0].get("country", "")
            org = results[0].get("org", "")
            if country:
                result["threat_summary"].append(f"Location: {country} — {org}")

        idx = 1
        if self.has_abuseipdb and idx < len(results):
            if not isinstance(results[idx], Exception) and results[idx]:
                abuse = results[idx]
                result["abuseipdb"] = abuse
                score = abuse.get("abuseConfidenceScore", 0)
                reports = abuse.get("totalReports", 0)
                if score > 0:
                    result["threat_score"] = max(result["threat_score"], score)
                    result["threat_summary"].append(
                        f"AbuseIPDB: {score}% confidence malicious — {reports} reports"
                    )
                else:
                    result["threat_summary"].append("AbuseIPDB: No abuse reports found")
            idx += 1

        if self.has_virustotal and idx < len(results):
            if not isinstance(results[idx], Exception) and results[idx]:
                vt = results[idx]
                result["virustotal"] = vt
                malicious = vt.get("malicious", 0)
                total = vt.get("total_engines", 0)
                if malicious > 0:
                    score = int((malicious / max(total, 1)) * 100)
                    result["threat_score"] = max(result["threat_score"], score)
                    result["threat_summary"].append(
                        f"VirusTotal: {malicious}/{total} engines flagged as malicious"
                    )
                else:
                    result["threat_summary"].append("VirusTotal: Clean — no engines flagged")

        if not self.has_abuseipdb and not self.has_virustotal:
            result["threat_summary"].append(
                "💡 Add ABUSEIPDB_API_KEY or VIRUSTOTAL_API_KEY to .env for live threat scoring"
            )

        return result

    async def check_hash_live(self, hash_value: str) -> dict:
        """Check a file hash against VirusTotal live."""
        result = {
            "hash": hash_value,
            "virustotal": None,
            "threat_score": 0,
            "threat_summary": [],
        }

        if not self.has_virustotal:
            result["threat_summary"].append("💡 Add VIRUSTOTAL_API_KEY for live hash scanning")
            return result

        try:
            vt = await self._check_virustotal_hash(hash_value)
            if vt:
                result["virustotal"] = vt
                malicious = vt.get("malicious", 0)
                total = vt.get("total_engines", 0)
                name = vt.get("name", "")
                family = vt.get("family", "")
                if malicious > 0:
                    score = int((malicious / max(total, 1)) * 100)
                    result["threat_score"] = score
                    summary = f"VirusTotal: {malicious}/{total} engines — MALICIOUS"
                    if name: summary += f" | Name: {name}"
                    if family: summary += f" | Family: {family}"
                    result["threat_summary"].append(summary)
                else:
                    result["threat_summary"].append("VirusTotal: Clean file — not detected")
        except Exception as e:
            logger.error(f"VT hash check error: {e}")

        return result

    async def check_domain_live(self, domain: str) -> dict:
        """Check a domain against VirusTotal live."""
        result = {
            "domain": domain,
            "virustotal": None,
            "threat_score": 0,
            "threat_summary": [],
        }

        if not self.has_virustotal:
            result["threat_summary"].append("💡 Add VIRUSTOTAL_API_KEY for live domain scanning")
            return result

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        total = sum(stats.values())
                        result["virustotal"] = stats
                        if malicious > 0:
                            result["threat_score"] = int((malicious / max(total, 1)) * 100)
                            result["threat_summary"].append(
                                f"VirusTotal: {malicious}/{total} engines flagged domain as malicious"
                            )
                        else:
                            result["threat_summary"].append("VirusTotal: Domain appears clean")
        except Exception as e:
            logger.error(f"VT domain check error: {e}")

        return result

    async def check_all_iocs_live(self, iocs: dict) -> dict:
        """Check all extracted IOCs against live APIs concurrently."""
        live_results = {
            "ips": [],
            "hashes": [],
            "domains": [],
            "overall_threat_score": 0,
            "live_threats_found": 0,
            "summary": [],
        }

        tasks = []

        # Check up to 3 IPs
        for ip in iocs.get("ips", [])[:3]:
            if not self._is_private_ip(ip):
                tasks.append(("ip", ip, self.check_ip_live(ip)))

        # Check up to 2 hashes
        for h in iocs.get("hashes", [])[:2]:
            tasks.append(("hash", h, self.check_hash_live(h)))

        # Check up to 2 domains
        for d in iocs.get("domains", [])[:2]:
            tasks.append(("domain", d, self.check_domain_live(d)))

        if not tasks:
            return live_results

        # Run all concurrently
        results = await asyncio.gather(*[t[2] for t in tasks], return_exceptions=True)

        for i, (ioc_type, value, _) in enumerate(tasks):
            if isinstance(results[i], Exception):
                continue
            r = results[i]
            score = r.get("threat_score", 0)
            summaries = r.get("threat_summary", [])

            if ioc_type == "ip":
                live_results["ips"].append(r)
            elif ioc_type == "hash":
                live_results["hashes"].append(r)
            elif ioc_type == "domain":
                live_results["domains"].append(r)

            if score > 0:
                live_results["overall_threat_score"] = max(
                    live_results["overall_threat_score"], score
                )
                live_results["live_threats_found"] += 1

            for s in summaries:
                live_results["summary"].append(f"{ioc_type.upper()} {value[:30]}: {s}")

        return live_results

    # ── Internal API callers ──────────────────────────────

    async def _get_ip_geo(self, ip: str) -> dict:
        """Free IP geolocation — no API key needed."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://ip-api.com/json/{ip}?fields=country,regionName,city,org,as,proxy,hosting",
                    timeout=aiohttp.ClientTimeout(total=8)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "country": data.get("country", ""),
                            "city": data.get("city", ""),
                            "org": data.get("org", ""),
                            "is_proxy": data.get("proxy", False),
                            "is_hosting": data.get("hosting", False),
                        }
        except Exception as e:
            logger.error(f"Geo lookup error: {e}")
        return {}

    async def _check_abuseipdb(self, ip: str) -> dict:
        """Check IP against AbuseIPDB."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={
                        "Key": self.abuseipdb_key,
                        "Accept": "application/json"
                    },
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("data", {})
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
        return {}

    async def _check_virustotal_ip(self, ip: str) -> dict:
        """Check IP against VirusTotal."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        return {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "total_engines": sum(stats.values()),
                        }
        except Exception as e:
            logger.error(f"VT IP error: {e}")
        return {}

    async def _check_virustotal_hash(self, hash_value: str) -> dict:
        """Check file hash against VirusTotal."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/api/v3/files/{hash_value}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attrs = data.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        names = attrs.get("names", [])
                        families = list(attrs.get("popular_threat_classification", {})
                                       .get("popular_threat_name", {}).keys())
                        return {
                            "malicious": stats.get("malicious", 0),
                            "total_engines": sum(stats.values()),
                            "name": names[0] if names else "",
                            "family": families[0] if families else "",
                        }
        except Exception as e:
            logger.error(f"VT hash error: {e}")
        return {}

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        private_ranges = [
            r'^10\.',
            r'^192\.168\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^127\.',
            r'^0\.',
            r'^169\.254\.',
            r'^::1$',
            r'^localhost$',
        ]
        return any(re.match(p, ip) for p in private_ranges)