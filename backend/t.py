import asyncio, sys
sys.path.insert(0, '.')

async def test():
    from app.services.siem.alert_enricher import AlertEnricher
    enricher = AlertEnricher()
    
    # This log contains 185.220.101.45 which SHOULD be in your DB from Feodo
    result = await enricher.enrich_alert({
        "raw_log": "blocked connection to 185.220.101.45:4444 process: powershell.exe",
        "source_system": "test"
    })
    
    print("Risk Score:", result['risk_score'])
    print("Severity:", result['severity'])
    print("DB Matches:", result['db_matches'])
    print("MITRE:", result['mitre_techniques'])
    print("Extracted IOCs:", result['extracted_iocs'])

asyncio.run(test())