"""
HUNT ENGINE - Auto threat hunting query generator
"""

import uuid
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class HuntEngine:

    TEMPLATES = {
        "ip": {
            "splunk": 'index=* ({value}) | stats count by src_ip, dest_ip, process_name | sort -count',
            "elastic": '{"query": {"term": {"ip": "{value}"}}}',
            "sigma": 'title: Hunt for IP {value}\ndetection:\n  keywords:\n    - "{value}"',
        },
        "domain": {
            "splunk": 'index=dns query="{value}" | stats count by src_ip, query | sort -count',
            "elastic": '{"query": {"wildcard": {"dns.question.name": "*{value}*"}}}',
            "sigma": 'title: Hunt for Domain {value}\ndetection:\n  keywords:\n    - "{value}"',
        },
        "hash": {
            "splunk": 'index=* (md5="{value}" OR sha256="{value}") | stats count by host, file_path',
            "elastic": '{"query": {"term": {"file.hash.sha256": "{value}"}}}',
            "sigma": 'title: Hunt for Hash {value}\ndetection:\n  keywords:\n    - "{value}"',
        },
        "url": {
            "splunk": 'index=proxy url="{value}" | stats count by src_ip, url, user',
            "elastic": '{"query": {"wildcard": {"url.full": "*{value}*"}}}',
            "sigma": 'title: Hunt for URL {value}\ndetection:\n  keywords:\n    - "{value}"',
        },
    }

    def generate_queries(self, ioc_value: str, ioc_type: str, context: str = "") -> dict:
        """Generate Splunk, Elastic and Sigma hunt queries for an IOC."""
        templates = self.TEMPLATES.get(ioc_type, self.TEMPLATES["ip"])
        return {
            "id": str(uuid.uuid4()),
            "name": f"Hunt: {ioc_type.upper()} {ioc_value[:40]}",
            "hypothesis": f"Hosts may have communicated with known-bad {ioc_type} {ioc_value}",
            "query_splunk": templates["splunk"].replace("{value}", ioc_value),
            "query_elastic": templates["elastic"].replace("{value}", ioc_value),
            "query_sigma": templates["sigma"].replace("{value}", ioc_value),
            "data_sources": self._get_data_sources(ioc_type),
            "triggered_by_ioc": ioc_value,
            "created_at": datetime.utcnow().isoformat(),
        }

    def _get_data_sources(self, ioc_type: str) -> list:
        sources = {
            "ip": ["firewall_logs", "proxy_logs", "netflow", "edr_logs"],
            "domain": ["dns_logs", "proxy_logs", "edr_logs"],
            "hash": ["edr_logs", "av_logs", "file_integrity"],
            "url": ["proxy_logs", "web_gateway", "edr_logs"],
        }
        return sources.get(ioc_type, ["edr_logs"])

    def get_prebuilt_hunts(self) -> list:
        """Return pre-built hunt queries for common threat scenarios."""
        return [
            {
                "id": "hunt-001",
                "name": "C2 Beaconing Detection",
                "hypothesis": "Compromised hosts beacon to C2 at regular intervals",
                "query_splunk": 'index=firewall | bucket _time span=1h | stats count by src_ip, dest_ip | eventstats avg(count) as avg stdev(count) as std by src_ip, dest_ip | where count > avg+std',
                "query_elastic": '{"aggs": {"beaconing": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}}}',
                "query_sigma": 'title: C2 Beaconing\ndetection:\n  condition: timeframe\ntimeframe: 1h',
                "data_sources": ["firewall_logs", "netflow"],
                "created_at": datetime.utcnow().isoformat(),
            },
            {
                "id": "hunt-002",
                "name": "Ransomware File Activity",
                "hypothesis": "Ransomware encrypts files rapidly across multiple directories",
                "query_splunk": 'index=edr event_type=file_write | stats count by host, file_extension | where count > 100 AND (file_extension=".locked" OR file_extension=".enc" OR file_extension=".crypt")',
                "query_elastic": '{"query": {"bool": {"must": [{"wildcard": {"file.extension": "*.locked"}}, {"range": {"event.count": {"gte": 100}}}]}}}',
                "query_sigma": 'title: Ransomware File Encryption\ndetection:\n  file_extension:\n    - ".locked"\n    - ".enc"\n    - ".crypt"',
                "data_sources": ["edr_logs", "file_integrity"],
                "created_at": datetime.utcnow().isoformat(),
            },
            {
                "id": "hunt-003",
                "name": "PowerShell Encoded Commands",
                "hypothesis": "Attackers use encoded PowerShell to evade detection",
                "query_splunk": 'index=winevent EventCode=4104 | search Message="*-EncodedCommand*" OR Message="*-enc *" | stats count by host, user, Message',
                "query_elastic": '{"query": {"match": {"process.command_line": "-EncodedCommand"}}}',
                "query_sigma": 'title: PowerShell Encoded Command\ndetection:\n  powershell:\n    CommandLine|contains:\n      - "-EncodedCommand"\n      - "-enc "',
                "data_sources": ["windows_event_logs", "edr_logs"],
                "created_at": datetime.utcnow().isoformat(),
            },
            {
                "id": "hunt-004",
                "name": "Lateral Movement via PsExec",
                "hypothesis": "Attackers use PsExec or similar tools for lateral movement",
                "query_splunk": 'index=winevent EventCode=7045 | search Service_Name=PSEXESVC | stats count by host, user',
                "query_elastic": '{"query": {"match": {"winlog.event_id": "7045"}}}',
                "query_sigma": 'title: PsExec Lateral Movement\ndetection:\n  service:\n    ServiceName: PSEXESVC',
                "data_sources": ["windows_event_logs", "edr_logs"],
                "created_at": datetime.utcnow().isoformat(),
            },
            {
                "id": "hunt-005",
                "name": "DGA Domain Detection",
                "hypothesis": "Malware uses Domain Generation Algorithms to contact C2",
                "query_splunk": 'index=dns | eval domain_len=len(query) | where domain_len > 20 AND query_count < 3 | stats count by query | sort -count',
                "query_elastic": '{"query": {"range": {"dns.question.name.length": {"gt": 20}}}}',
                "query_sigma": 'title: DGA Domain Detection\ndetection:\n  dns:\n    QueryName|re: "[a-z0-9]{15,}"',
                "data_sources": ["dns_logs"],
                "created_at": datetime.utcnow().isoformat(),
            },
        ]