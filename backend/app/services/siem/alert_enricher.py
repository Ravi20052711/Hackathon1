"""
ALERT ENRICHER - with Real-time Threat Checking + Claude AI
Checks IOCs against:
1. Local SQLite database (instant)
2. Live external APIs - AbuseIPDB, VirusTotal (real-time)
3. Free geo lookup - ip-api.com (always works, no key needed)
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

# Known brands for typosquatting detection
BRAND_PATTERNS = [
    # Brand         # Legit domains
    ('facebook',    ['facebook.com', 'fb.com']),
    ('google',      ['google.com', 'googleapis.com', 'google.co.in']),
    ('microsoft',   ['microsoft.com', 'live.com', 'outlook.com', 'azure.com']),
    ('apple',       ['apple.com', 'icloud.com']),
    ('amazon',      ['amazon.com', 'amazon.in', 'aws.amazon.com']),
    ('paypal',      ['paypal.com']),
    ('netflix',     ['netflix.com']),
    ('instagram',   ['instagram.com']),
    ('twitter',     ['twitter.com', 'x.com']),
    ('linkedin',    ['linkedin.com']),
    ('whatsapp',    ['whatsapp.com', 'whatsapp.net']),
    ('gmail',       ['gmail.com', 'google.com']),
    ('yahoo',       ['yahoo.com', 'yahoo.co.in']),
    ('dropbox',     ['dropbox.com']),
    ('github',      ['github.com', 'githubusercontent.com']),
    ('bankofamerica', ['bankofamerica.com']),
    ('chase',       ['chase.com', 'jpmorgan.com']),
    ('hdfc',        ['hdfcbank.com']),
    ('sbi',         ['sbi.co.in', 'onlinesbi.com']),
    ('icici',       ['icicibank.com']),
]

def detect_typosquatting(domains: list, urls: list) -> list:
    """Detect typosquatting/phishing domains impersonating known brands."""
    findings = []
    all_hosts = list(domains)
    for url in urls:
        import re as _re
        m = _re.search(r'https?://([^/\s:?#]+)', url)
        if m:
            all_hosts.append(m.group(1))

    for host in all_hosts:
        host_clean = host.lower().strip()
        for brand, legit_domains in BRAND_PATTERNS:
            # Skip if it IS a legit domain
            if any(host_clean == d or host_clean.endswith('.' + d) for d in legit_domains):
                continue
            # Check if brand name appears in domain (with number/char substitutions)
            normalized = host_clean.replace('0', 'o').replace('1', 'i').replace('3', 'e').replace('@', 'a')
            if brand in normalized and not any(host_clean == d for d in legit_domains):
                findings.append({
                    'domain': host,
                    'impersonating': brand,
                    'type': 'typosquatting',
                    'risk_score': 85,
                    'description': f"Domain '{host}' appears to impersonate '{brand}' — likely phishing"
                })
                break
    return findings

CRITICAL_KEYWORDS = ['ransomware', 'mimikatz', 'lsass', 'credential', 'exfil', 'c2', 'beacon', 'cobalt strike']
HIGH_KEYWORDS = ['malware', 'payload', 'dropper', 'backdoor', 'trojan', 'exploit', 'inject', 'powershell']
MEDIUM_KEYWORDS = ['suspicious', 'scan', 'probe', 'brute', 'failed login', 'blocked']


class AlertEnricher:

    def extract_iocs(self, text: str) -> dict:
        # IPs
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        ips = [ip for ip in ips if not ip.startswith('0.')]

        # URLs - catch ALL http/https regardless of TLD
        urls = list(set(re.findall(r'https?://[^\s<>\'"{}|\\^`\[\]\)\(,;]+', text)))

        # Domains - extract from URLs first
        domains = []
        for url in urls:
            import re as _re
            m = _re.search(r'https?://([^/\s:?#]+)', url)
            if m:
                host = m.group(1)
                if '.' in host and not _re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                    domains.append(host)

        # Also catch bare domains with expanded TLD list
        extra_domains = re.findall(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:'
            r'com|net|org|xyz|io|ru|cn|tk|pw|cc|biz|info|top|club|site|online|'
            r'shop|store|live|click|link|work|fun|space|tech|app|dev|sh|ly|'
            r'to|in|me|us|uk|de|fr|jp|br|au|ca|eu|gov|edu|mil'
            r')\b', text
        )
        domains = list(set(domains + extra_domains))

        # Hashes
        sha256 = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text)))
        md5 = list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text)))

        all_iocs = list(dict.fromkeys(ips + urls + domains + sha256 + md5))
        return {
            'ips': ips[:10],
            'domains': domains[:10],
            'hashes': (sha256 + md5)[:5],
            'urls': urls[:5],
            'all': all_iocs[:25]
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
                        'tags': json.loads(row['tags']) if row['tags'] else [],
                        'match_source': 'local_db'
                    })
        finally:
            db.close()
        return matches

    def detect_mitre(self, text: str, typosquat_findings: list = None) -> list:
        techniques = []
        seen = set()
        for pattern, tid, name in MITRE_PATTERNS:
            if re.search(pattern, text.lower()) and tid not in seen:
                techniques.append(f"{tid} - {name}")
                seen.add(tid)
        # If typosquatting found, add phishing technique
        if typosquat_findings:
            if 'T1566' not in seen:
                techniques.append('T1566 - Phishing / Typosquatting')
            if 'T1598' not in seen:
                techniques.append('T1598 - Spearphishing via Fake Domain')
        return techniques

    def calculate_severity(self, text: str, matches: list, score: int, live_score: int = 0) -> str:
        text_lower = text.lower()
        effective_score = max(score, live_score)
        if effective_score >= 85 or any(k in text_lower for k in CRITICAL_KEYWORDS) or len(matches) >= 2:
            return 'critical'
        if effective_score >= 65 or any(k in text_lower for k in HIGH_KEYWORDS) or matches:
            return 'high'
        if effective_score >= 40 or any(k in text_lower for k in MEDIUM_KEYWORDS):
            return 'medium'
        return 'low'

    def generate_recommendations(self, matches: list, techniques: list, severity: str, live_results: dict = None) -> list:
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
        # Add recommendations from live results
        if live_results and live_results.get('live_threats_found', 0) > 0:
            recs.append("🌐 Live threat APIs confirmed malicious activity — escalate immediately")
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

        # Step 1: Extract IOCs
        iocs = self.extract_iocs(raw_log)

        # Step 2: Check local DB
        matches = self.check_db_matches(iocs)

        # Step 2b: Typosquatting detection
        typosquat_findings = detect_typosquatting(iocs.get('domains', []), iocs.get('urls', []))
        for t in typosquat_findings:
            matches.append({
                'value': t['domain'],
                'ioc_type': 'domain',
                'risk_score': t['risk_score'],
                'source': f"Typosquatting — impersonates {t['impersonating']}",
                'tags': ['phishing', 'typosquatting'],
                'match_source': 'typosquat_detection'
            })

        # Step 3: Check live external APIs concurrently
        live_results = {}
        try:
            from app.services.siem.realtime_checker import RealtimeChecker
            checker = RealtimeChecker()
            live_results = await checker.check_all_iocs_live(iocs)
            logger.info(f"Live check: {live_results.get('live_threats_found', 0)} threats found externally")
        except Exception as e:
            logger.error(f"Live check error: {e}")

        # Step 4: MITRE mapping (pass typosquat findings)
        techniques = self.detect_mitre(raw_log, typosquat_findings)

        # Step 5: Calculate risk score
        base_score = max([m['risk_score'] for m in matches], default=0)
        live_score = live_results.get('overall_threat_score', 0)
        keyword_boost = 20 if any(k in raw_log.lower() for k in CRITICAL_KEYWORDS) else \
                        10 if any(k in raw_log.lower() for k in HIGH_KEYWORDS) else 0
        risk_score = min(99, max(base_score, live_score) + keyword_boost) if (base_score > 0 or live_score > 0) \
                     else min(50, 20 + keyword_boost)

        severity = self.calculate_severity(raw_log, matches, risk_score, live_score)
        recommendations = self.generate_recommendations(matches, techniques, severity, live_results)

        # Step 6: Build live intel summary
        live_intel = []
        if live_results.get('summary'):
            live_intel = live_results['summary']

        # Step 7: AI summary
        try:
            from app.services.llm.llm_analyzer import LLMAnalyzer
            analyzer = LLMAnalyzer()
            summary = await analyzer.analyze_threat(raw_log, iocs, matches, techniques)
        except Exception as e:
            logger.error(f"LLM error: {e}")
            summary = self._template_summary(iocs, matches, techniques, live_results)

        now = datetime.utcnow().isoformat()
        return {
            'id': str(uuid.uuid4()),
            'raw_log': raw_log,
            'source_system': source,
            'severity': severity,
            'risk_score': risk_score,
            'extracted_iocs': iocs['all'],
            'db_matches': matches,
            'live_intel': live_intel,
            'live_threats_found': live_results.get('live_threats_found', 0),
            'llm_summary': summary,
            'recommended_actions': recommendations,
            'mitre_techniques': techniques,
            'created_at': now,
            'enriched_at': now,
        }

    def _template_summary(self, iocs, matches, techniques, live_results=None) -> str:
        lines = []
        if matches:
            lines.append(f"⚠️ {len(matches)} known threat(s) matched in local database:")
            for m in matches[:3]:
                lines.append(f"  • {m['ioc_type'].upper()} {m['value']} — Risk {m['risk_score']}/100 ({m['source']})")
        if live_results and live_results.get('live_threats_found', 0) > 0:
            lines.append(f"\n🌐 {live_results['live_threats_found']} live threat(s) detected via external APIs:")
            for s in live_results.get('summary', [])[:3]:
                lines.append(f"  • {s}")
        elif not matches:
            lines.append("✅ No threat indicators matched. This log appears legitimate.")
        if iocs.get('ips'): lines.append(f"\n🌐 IPs: {', '.join(iocs['ips'][:5])}")
        if iocs.get('domains'): lines.append(f"🔗 Domains: {', '.join(iocs['domains'][:5])}")
        if techniques: lines.append(f"\n🎯 MITRE: {', '.join(techniques[:3])}")
        return '\n'.join(lines)