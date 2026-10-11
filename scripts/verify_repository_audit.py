"""Actual public artifacts + databases + SLIM workers; no mocked data."""
import asyncio
import json
from pathlib import Path
import time
import httpx


async def main():
    report = {'scope': 'Real workspace artifacts and an explicitly historical Apache Airflow constraint snapshot; live public advisory APIs', 'cases': [], 'validated': False}
    output = Path(__file__).resolve().parents[1] / 'docs/repository-audit-verification.json'
    async with httpx.AsyncClient(base_url='http://127.0.0.1:8000', timeout=15, trust_env=False) as client:
        report['health'] = (await client.get('/api/health')).json()
        assert report['health']['transport'] == 'slim'
        for request in [{'source': 'github', 'repository': 'apache/airflow', 'ref': 'constraints-2.6.0', 'paths': ['constraints-3.9.txt'], 'model_assisted': True}, {'source': 'workspace', 'model_assisted': True}]:
            response = await client.post('/api/audits', json=request)
            response.raise_for_status()
            run = response.json()
            deadline = time.monotonic() + 220
            while run['state'] in {'queued', 'running'}:
                assert time.monotonic() < deadline, 'Live audit exceeded its deadline'
                await asyncio.sleep(.5)
                run = (await client.get('/api/audits/' + run['run_id'])).json()
            report['cases'].append(run)
            output.write_text(json.dumps(report, indent=2))
            assert run['state'] == 'completed', run['error']
            assert run['coverage']['packages_queried'] > 0
            assert all(len(a['sha256']) == 64 for a in run['artifacts'])
            assert len(run['positions']) == 6 and run['peer_receipts'] > 0
            if report['health']['reasoning'] == 'llm':
                assert run['model_calls'] == 6
            refs = {e['evidence_id'] for e in run['evidence']}
            assert all(set(p['evidence_ids']) <= refs for p in run['positions'])
            assert all(f['exploitability'] == 'NOT_ASSESSED' for f in run['findings'])
            assert any(r['url'] == 'https://api.osv.dev/v1/querybatch' and r['status'] == 200 for r in run['http_requests'])
            if request['source'] == 'github':
                assert len(run['commit_sha']) == 40
                assert run['coverage']['advisory_hits'] > 0
                assert any(f['github_verified'] for f in run['findings']), 'No historical affected-version match corroborated; inspect public API availability'
            print(f"PASS {request['source']}: {run['coverage']['packages_queried']} real package versions, {run['coverage']['advisory_hits']} advisory hits, {run['model_calls']} model calls, {run['peer_receipts']} peer receipts", flush=True)
        report['validated'] = True
        output.write_text(json.dumps(report, indent=2))
        print(f'Saved real public API acceptance: {output}', flush=True)


if __name__ == '__main__':
    asyncio.run(main())
