"""
ALERT ENRICHER - with Claude AI integration
"""

import re
import uuid
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

MITRE_PATTERNS = [
    (r'powershell|pwsh', 'T1059.001', 'PowerShell Execution'),
    (r'cmd\.exe|command prompt', 'T1059.003', 'Windows Command Shell'),
    (r'mimikatz|sekurlsa|lsass', 'T1003', 'Credential Dumping'),
    (r'lateral|psexec|wmic|winrm', 'T1021', 'Lateral Movement'),
    (r'ransomware|encrypt|\.locked|\.enc$', 'T1486', 'Data Encrypted for Impact'),
    (r'phish|spear|credential harvest', 'T1566', 'Phishing'),
    (r'persistence|autorun|registry.*run', 'T1547', 'Boot/Logon Autostart'),
    (r'exfil|upload|ftp|dropbox|mega\.nz', 'T1041', 'Exfiltration Over C2'),
    (r'c2|command.and.control|beacon|cobalt', 'T1071', 'C2 Communication'),
    (r'scheduled.task|schtasks|cron', 'T1053', 'Scheduled Task'),
    (r'bypass|uac|privilege|escalat', 'T1548', 'Abuse Elevation Control'),
    (r'inject|hollowing|reflective', 'T1055', 'Process Injection'),
    (r'payload|dropper|downloader|stager', 'T1204', 'User Execution'),
    (r'scan|nmap|masscan|port.scan', 'T1046', 'Network Service Scanning'),
    (r'ssh|rdp|vnc|remote.desktop', 'T1021', 'Remote Services'),
]

CRITICAL_KEYWORDS = ['ransomware', 'mimikatz', 'lsass', 'credential', 'exfil', 'c2', 'beacon', 'cobalt strike']
HIGH_KEYWORDS = ['malware', 'payload', 'dropper', 'backdoor', 'trojan', 'exploit', 'inject', 'powershell']
MEDIUM_KEYWORDS = ['suspicious', 'scan', 'probe', 'brute', 'failed login', 'blocked']


class AlertEnricher:

    def extract_iocs(self, text: str) -> dict:
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        ips = [ip for ip in ips if not ip.startswith('0.')]
        domains = list(set(re.findall(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|xyz|io|ru|cn|tk|pw|cc|biz|info|top|club)\b', text
        )))
        sha256 = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)))
        md5 = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text)))
        urls = list(set(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)))
        return {
            'ips': ips[:10], 'domains': domains[:10],
            'hashes': (sha256 + md5)[:5], 'urls': urls[:5],
            'all': (ips + domains + sha256 + md5 + urls)[:20]
        }

    def check_db_matches(self, iocs: dict) -> list:
        from app.core.database import get_db
        db = get_db()
        matches = []
        try:
            for value in iocs.get('all', []):
                row = db.execute(
                    "SELECT value, ioc_type, risk_score, source, tags FROM iocs WHERE value = ?",
                    (value,)
                ).fetchone()
                if row:
                    matches.append({
                        'value': row['value'], 'ioc_type': row['ioc_type'],
                        'risk_score': row['risk_score'], 'source': row['source'],
                        'tags': json.loads(row['tags']) if row['tags'] else []
                    })
        finally:
            db.close()
        return matches

    def detect_mitre(self, text: str) -> list:
        techniques = []
        seen = set()
        for pattern, tid, name in MITRE_PATTERNS:
            if re.search(pattern, text.lower()) and tid not in seen:
                techniques.append(f"{tid} - {name}")
                seen.add(tid)
        return techniques

    def calculate_severity(self, text: str, matches: list, score: int) -> str:
        text_lower = text.lower()
        if score >= 85 or any(k in text_lower for k in CRITICAL_KEYWORDS) or len(matches) >= 2:
            return 'critical'
        if score >= 65 or any(k in text_lower for k in HIGH_KEYWORDS) or matches:
            return 'high'
        if score >= 40 or any(k in text_lower for k in MEDIUM_KEYWORDS):
            return 'medium'
        return 'low'

    def generate_recommendations(self, matches: list, techniques: list, severity: str) -> list:
        recs = []
        if severity in ['critical', 'high']:
            recs.append("🚨 IMMEDIATE: Isolate affected host from network")
            recs.append("🔍 Capture memory dump before remediation")
        for m in matches[:2]:
            if m['ioc_type'] == 'ip':
                recs.append(f"🔒 Block IP {m['value']} at firewall and proxy")
            elif m['ioc_type'] == 'domain':
                recs.append(f"🔒 Block domain {m['value']} via DNS sinkhole")
            elif m['ioc_type'] == 'hash':
                recs.append(f"🗑️ Quarantine file with hash {m['value'][:16]}...")
        for t in techniques:
            if 'T1003' in t: recs.append("🔑 Reset all credentials on affected system")
            if 'T1486' in t: recs.append("💾 Restore from clean backup — do NOT pay ransom")
            if 'T1059' in t: recs.append("📜 Review PowerShell logs (Event ID 4104)")
            if 'T1071' in t: recs.append("📡 Check firewall for unusual outbound connections")
        if not recs:
            recs.append("📋 Log event and monitor for related activity")
        return list(dict.fromkeys(recs))[:6]

    async def enrich_alert(self, alert) -> dict:
        raw_log = alert.get('raw_log', '') if isinstance(alert, dict) else alert.raw_log
        source = alert.get('source_system', 'manual') if isinstance(alert, dict) else alert.source_system

        iocs = self.extract_iocs(raw_log)
        matches = self.check_db_matches(iocs)
        techniques = self.detect_mitre(raw_log)

        base_score = max([m['risk_score'] for m in matches], default=0)
        keyword_boost = 20 if any(k in raw_log.lower() for k in CRITICAL_KEYWORDS) else \
                        10 if any(k in raw_log.lower() for k in HIGH_KEYWORDS) else 0
        risk_score = min(99, base_score + keyword_boost) if base_score > 0 else min(50, 20 + keyword_boost)

        severity = self.calculate_severity(raw_log, matches, risk_score)
        recommendations = self.generate_recommendations(matches, techniques, severity)

        # Use Claude AI for summary if available
        try:
            from app.services.llm.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            summary = await analyzer.analyze_threat(raw_log, iocs, matches, techniques)
        except Exception as e:
            logger.error(f"LLM error: {e}")
            summary = "Analysis unavailable — check backend logs"

        now = datetime.utcnow().isoformat()
        return {
            'id': str(uuid.uuid4()),
            'raw_log': raw_log,
            'source_system': source,
            'severity': severity,
            'risk_score': risk_score,
            'extracted_iocs': iocs['all'],
            'db_matches': matches,
            'llm_summary': summary,
            'recommended_actions': recommendations,
            'mitre_techniques': techniques,
            'created_at': now,
            'enriched_at': now,
        }