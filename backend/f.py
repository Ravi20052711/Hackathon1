import asyncio
import sys
sys.path.insert(0, '.')

async def test():
    from app.api.feed import fetch_urlhaus, fetch_feodo, fetch_malwarebazaar, insert_iocs

    print('Fetching URLhaus malware URLs...')
    urls = await fetch_urlhaus(50)
    print(f'Got {len(urls)} URLs')

    print('Fetching Feodo botnet C2 IPs...')
    ips = await fetch_feodo(50)
    print(f'Got {len(ips)} IPs')

    print('Fetching MalwareBazaar hashes...')
    hashes = await fetch_malwarebazaar(30)
    print(f'Got {len(hashes)} hashes')

    all_iocs = urls + ips + hashes
    print(f'\nTotal fetched: {len(all_iocs)}')

    inserted = insert_iocs(all_iocs)
    print(f'New IOCs inserted into database: {inserted}')
    print('\nDone! Refresh your dashboard now.')

asyncio.run(test())