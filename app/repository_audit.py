"""Audits actual immutable artifacts against live public databases; no fixture outcomes."""
import asyncio
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import quote
from packaging.utils import canonicalize_name
from packaging.version import Version, InvalidVersion
from app.capability_discovery import ROOT
from schemas.models import Evidence, now, uid
from schemas.audit import AuditRequest
from tools.advisory_client import AdvisoryClient

MAX_PACKAGES = 500
MAX_FINDINGS = 8


def parse_artifact(path, content):
    packages, skipped = [], []
    if path.endswith('package-lock.json'):
        data = json.loads(content)
        if not isinstance(data.get('packages'), dict):
            raise ValueError('Use npm package-lock version 2 or 3; version 1 is not supported')
        for location, item in data['packages'].items():
            if not location or 'node_modules/' not in location:
                continue
            name = item.get('name') or location.rsplit('node_modules/', 1)[-1]
            version = item.get('version')
            if version and re.fullmatch(r'\d[^\s/]*', version):
                packages.append({'ecosystem': 'npm', 'name': name, 'version': version, 'artifact': path, 'location': location})
            else:
                skipped.append({'artifact': path, 'entry': location, 'reason': 'No exact registry version'})
    elif path.endswith(('.txt', '.lock')):
        for line_number, raw in enumerate(content.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            match = re.match(r'^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.+!-]+)(?:\s|;|$)', line)
            if match:
                packages.append({'ecosystem': 'PyPI', 'name': canonicalize_name(match[1]), 'version': match[2], 'artifact': path, 'location': f'line {line_number}', 'marker': line.split(';', 1)[1].strip() if ';' in line else None})
            else:
                skipped.append({'artifact': path, 'entry': line[:120], 'reason': 'Only exact == version pins are supported; includes and ranges are not resolved'})
    else:
        raise ValueError('Supported artifacts are pinned requirements/constraints .txt or .lock, and npm package-lock.json')
    return packages, skipped


class AuditGateway:
    def __init__(self, service, run, client):
        self.service, self.run, self.client = service, run, client
        self.evidence = []
        self.lock = asyncio.Lock()
        self.completed = set()

    async def check(self, agent_id, name, finding_id=None):
        cap = next((a for a in self.service.registry.agents if a.agent_id == agent_id), None)
        if cap is None or name not in cap.allowed_checks or self.run['state'] != 'running':
            raise ValueError('Audit check not allowed for this worker or state')
        async with self.lock:
            if name in self.completed:
                raise ValueError('Audit check already executed')
            self.completed.add(name)
            if name == 'query_osv':
                facts = await self.query_osv()
            elif name == 'verify_github':
                facts = await self.verify_github()
            elif name == 'check_releases':
                facts = await self.check_releases()
            else:
                raise ValueError('Unknown public audit check')
            item = Evidence(run_id=self.run['run_id'], agent_id=agent_id, finding_id=self.run['run_id'], target_id=self.run['source_label'], tool_name=name,
                test_description='Live public dependency/advisory observation', route={'query_osv': '/v1/querybatch', 'verify_github': '/advisories', 'check_releases': '/registry-version'}[name],
                method='POST' if name == 'query_osv' else 'GET', result='inventory', status_code=200,
                snippet=json.dumps(facts, sort_keys=True)[:600], response_hash=hashlib.sha256(json.dumps(facts, sort_keys=True).encode()).hexdigest(), facts=facts)
            self.evidence.append(item)
            self.run['evidence'].append(item.model_dump(mode='json'))
            self.service.save(self.run)
            return item

    async def query_osv(self):
        packages = self.run['packages']
        pending = [{'index': i, 'query': {'package': {'ecosystem': p['ecosystem'], 'name': p['name']}, 'version': p['version']}} for i, p in enumerate(packages)]
        hits = {}
        for page in range(3):
            if not pending:
                break
            body = await self.client.json('POST', 'https://api.osv.dev/v1/querybatch', json={'queries': [p['query'] for p in pending]})
            if len(body.get('results', [])) != len(pending):
                raise ValueError('OSV response did not cover the submitted packages')
            remaining = []
            for p, result in zip(pending, body['results']):
                for vuln in result.get('vulns', []):
                    hits[(p['index'], vuln['id'])] = vuln
                if result.get('next_page_token'):
                    remaining.append({'index': p['index'], 'query': {**p['query'], 'page_token': result['next_page_token']}})
            pending = remaining
        self.run['coverage']['osv_pagination_complete'] = not pending
        self.run['coverage']['advisory_hits'] = len(hits)
        self.run['coverage']['matched_packages'] = len({index for index, _ in hits})
        self.run['advisory_matches'] = [{'package': packages[index]['name'], 'version': packages[index]['version'], 'ecosystem': packages[index]['ecosystem'], 'advisory_id': advisory_id, 'osv_url': 'https://osv.dev/vulnerability/' + advisory_id} for index, advisory_id in sorted(hits)]
        # Prefer records that can be corroborated through the GitHub API.
        selected = sorted(hits, key=lambda pair: (not pair[1].startswith('GHSA-'), pair[0], pair[1]))[:MAX_FINDINGS]
        findings = []
        for index, advisory_id in selected:
            p = packages[index]
            detail = await self.client.json('GET', 'https://api.osv.dev/v1/vulns/' + quote(advisory_id, safe=''))
            fixes = sorted({event['fixed'] for a in detail.get('affected', []) if a.get('package', {}).get('ecosystem') == p['ecosystem'] and canonicalize_name(a.get('package', {}).get('name', '')) == canonicalize_name(p['name']) for r in a.get('ranges', []) for event in r.get('events', []) if 'fixed' in event})
            try:
                fixes = [v for v in fixes if Version(v) > Version(p['version'])]
            except InvalidVersion:
                # Uninterpretable branch boundaries remain a manual review.
                fixes = []
            findings.append({'id': uid('dep'), 'package': p['name'], 'version': p['version'], 'ecosystem': p['ecosystem'], 'artifact': p['artifact'], 'location': p['location'],
                'advisory_id': advisory_id, 'aliases': detail.get('aliases', []), 'summary': detail.get('summary', detail.get('details', '')[:180]),
                'severity': detail.get('database_specific', {}).get('severity', 'UNKNOWN'), 'osv_url': 'https://osv.dev/vulnerability/' + advisory_id,
                'status': 'WITHDRAWN' if detail.get('withdrawn') else 'ADVISORY_MATCH', 'withdrawn': detail.get('withdrawn'), 'github_verified': False,
                'fix_boundaries': fixes, 'release_checks': [], 'exploitability': 'NOT_ASSESSED', 'affected_ranges': [a for a in detail.get('affected', []) if a.get('package', {}).get('name') == p['name']],
                'modified': detail.get('modified'), 'details': detail.get('details', '')[:4000]})
        self.run['findings'] = findings
        self.run['coverage']['detailed_findings'] = len(findings)
        return {'packages_queried': len(packages), 'advisory_hits': len(hits), 'matched_packages': self.run['coverage']['matched_packages'], 'detailed_findings': len(findings), 'pagination_complete': not pending}

    async def verify_github(self):
        observed = {}
        warnings = []
        for finding in self.run['findings']:
            key = (finding['ecosystem'], finding['package'], finding['version'])
            if key not in observed:
                try:
                    rows = await self.client.json('GET', 'https://api.github.com/advisories', params={'ecosystem': 'pip' if key[0] == 'PyPI' else 'npm', 'affects': f'{key[1]}@{key[2]}', 'per_page': 100})
                    if not isinstance(rows, list):
                        raise ValueError('Unexpected GitHub advisory response')
                    observed[key] = rows
                    if len(rows) == 100:
                        warnings.append('GitHub result limit reached; corroboration coverage may be incomplete')
                except Exception as exc:
                    observed[key] = []
                    warnings.append(f'GitHub verification unavailable for {key[1]}: {type(exc).__name__}')
            aliases = {finding['advisory_id'], *finding['aliases']}
            match = next((row for row in observed[key] if row.get('ghsa_id') in aliases or row.get('cve_id') in aliases), None)
            if match and not match.get('withdrawn_at') and not finding['withdrawn']:
                finding['github_verified'] = True
                finding['github_url'] = match.get('html_url')
                finding['status'] = 'AFFECTED_VERSION_VERIFIED'
                finding['github_ranges'] = match.get('vulnerabilities', [])
                finding['severity'] = match.get('severity', finding['severity']).upper()
            elif not finding['withdrawn']:
                finding['status'] = 'REVIEW_REQUIRED'
        self.run['warnings'].extend(warnings)
        return {'verified_affected_versions': sum(f['github_verified'] for f in self.run['findings']), 'needs_review': sum(f['status'] == 'REVIEW_REQUIRED' for f in self.run['findings']), 'warnings': warnings}

    async def check_releases(self):
        checked = {}
        for finding in self.run['findings']:
            # These are range boundaries, not an automatically safe upgrade.
            for version in finding['fix_boundaries'][:2]:
                key = (finding['ecosystem'], finding['package'], version)
                if key not in checked:
                    url = f'https://pypi.org/pypi/{quote(key[1], safe="")}/{quote(version, safe="")}/json' if key[0] == 'PyPI' else f'https://registry.npmjs.org/{quote(key[1], safe="")}/{quote(version, safe="")}'
                    try:
                        data = await self.client.json('GET', url)
                        actual = data.get('info', {}).get('version') if key[0] == 'PyPI' else data.get('version')
                        checked[key] = {'version': version, 'published': actual == version, 'registry_url': url}
                    except Exception as exc:
                        checked[key] = {'version': version, 'published': None, 'registry_url': url, 'error': type(exc).__name__}
                finding['release_checks'].append(checked[key])
        candidates = []
        grouped = {}
        for finding in self.run['findings']:
            grouped.setdefault((finding['ecosystem'], finding['package']), set()).update(finding['fix_boundaries'])
        for (ecosystem, package), boundaries in grouped.items():
            if not boundaries:
                continue
            version = max(boundaries, key=Version)
            release = checked.get((ecosystem, package, version))
            if not release or release['published'] is not True:
                continue
            candidate = {'ecosystem': ecosystem, 'package': package, 'version': version, 'basis': 'Highest parsed fix boundary among the detailed findings', 'published': True, 'known_match_count': None, 'pagination_complete': None, 'compatibility': 'NOT_ASSESSED'}
            try:
                result = await self.client.json('POST', 'https://api.osv.dev/v1/querybatch', json={'queries': [{'package': {'ecosystem': ecosystem, 'name': package}, 'version': version}]})
                row = result['results'][0]
                candidate['known_match_count'] = len(row.get('vulns', []))
                candidate['pagination_complete'] = not bool(row.get('next_page_token'))
                candidate['advisory_ids'] = [v['id'] for v in row.get('vulns', [])]
            except Exception as exc:
                candidate['error'] = type(exc).__name__
            candidates.append(candidate)
        self.run['upgrade_candidates'] = candidates
        return {'release_versions_checked': len(checked), 'published_versions': sum(v['published'] is True for v in checked.values()), 'unknown_versions': sum(v['published'] is None for v in checked.values()), 'candidate_version_queries': candidates, 'compatibility': 'NOT_ASSESSED'}


class RepositoryAuditService:
    def __init__(self, registry, transport, data_dir=None, client_factory=AdvisoryClient):
        self.registry, self.transport = registry, transport
        self.data_dir = Path(data_dir or ROOT / 'data/audits')
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.runs, self.tasks, self.gateways = {}, {}, {}
        self.client_factory = client_factory

    def save(self, run):
        run['http_requests'] = self.gateways[run['run_id']].client.requests if run['run_id'] in self.gateways else []
        path = self.data_dir / (run['run_id'] + '.json')
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(run, indent=2))
        temporary.replace(path)

    def get(self, run_id):
        if not re.fullmatch(r'audit-[a-f0-9]{12}', run_id):
            raise KeyError(run_id)
        if run_id in self.runs:
            return self.runs[run_id]
        path = self.data_dir / (run_id + '.json')
        if not path.exists():
            raise KeyError(run_id)
        return json.loads(path.read_text())

    def list(self):
        return [json.loads(p.read_text()) for p in sorted(self.data_dir.glob('audit-*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:30]]

    async def open(self, request, background=True):
        if any(r['state'] in {'queued', 'running'} for r in self.runs.values()):
            raise ValueError('A repository audit is already active')
        if any(part in {'.', '..'} for part in request.repository.split('/')):
            raise ValueError('Invalid GitHub repository name')
        for path in request.paths:
            if path.startswith('/') or '..' in path.split('/') or not re.fullmatch(r'[A-Za-z0-9_./-]+', path):
                raise ValueError('Use a relative repository artifact path without traversal')
        run = {'run_id': uid('audit'), 'state': 'queued', 'created_at': now(), 'completed_at': None, 'source': request.model_dump(), 'source_label': 'This workspace' if request.source == 'workspace' else request.repository,
            'transport': self.transport.mode, 'reasoning': 'llm' if request.model_assisted and os.getenv('AGENT_REASONING') == 'llm' else 'rules',
            'reasoning_model': os.getenv('LLM_MODEL') if request.model_assisted and os.getenv('AGENT_REASONING') == 'llm' else None,
            'artifacts': [], 'packages': [], 'findings': [], 'evidence': [], 'events': [], 'positions': [], 'warnings': [], 'coverage': {}, 'http_requests': [], 'model_calls': 0, 'model_tokens': 0, 'peer_receipts': 0, 'error': None}
        self.runs[run['run_id']] = run
        self.gateways[run['run_id']] = AuditGateway(self, run, self.client_factory())
        self.save(run)
        if background:
            self.tasks[run['run_id']] = asyncio.create_task(self.execute(run))
        else:
            await self.execute(run)
        return run

    async def load_source(self, run):
        request = AuditRequest.model_validate(run['source'])
        client = self.gateways[run['run_id']].client
        if request.source == 'github':
            commit = await client.json('GET', f'https://api.github.com/repos/{request.repository}/commits/{quote(request.ref, safe="")}')
            sha = commit.get('sha', '')
            if not re.fullmatch(r'[a-f0-9]{40}', sha):
                raise ValueError('GitHub did not resolve an immutable commit')
            run['commit_sha'] = sha
            run['source_url'] = f'https://github.com/{request.repository}/tree/{sha}'
            paths = request.paths
        else:
            paths = ['requirements.lock', 'frontend/package-lock.json']
        packages, skipped = [], []
        for path in paths:
            if request.source == 'github':
                url = f'https://raw.githubusercontent.com/{request.repository}/{run["commit_sha"]}/{quote(path, safe="/")}'
                content = (await client.request('GET', url)).decode('utf-8')
            else:
                url = None
                content = (ROOT / path).read_text()
            found, omitted = parse_artifact(path, content)
            packages.extend(found)
            skipped.extend(omitted)
            run['artifacts'].append({'path': path, 'sha256': hashlib.sha256(content.encode()).hexdigest(), 'source_url': url, 'exact_pins': len(found)})
        unique = {}
        for p in packages:
            unique.setdefault((p['ecosystem'], p['name'], p['version']), p)
        run['packages'] = list(unique.values())[:MAX_PACKAGES]
        run['coverage'] = {'exact_pins': len(packages), 'unique_packages': len(unique), 'packages_queried': len(run['packages']), 'package_limit': MAX_PACKAGES, 'over_limit': max(0, len(unique) - MAX_PACKAGES), 'skipped_entries': skipped}
        if not run['packages']:
            raise ValueError('No exact supported dependency versions found; unresolved ranges are not guessed')
        if skipped or len(unique) > MAX_PACKAGES:
            run['warnings'].append('Partial artifact coverage: inspect skipped entries and the package limit')
        run['warnings'].append('Declared lockfile/constraint versions are not proof of installation or runtime reachability. No exploit was executed.')
        self.save(run)

    async def exchange(self, run, phase, agent_ids):
        context = {'domain': 'repository_audit', 'run_id': run['run_id'], 'finding_id': run['run_id'], 'round': 0 if phase == 'gather' else 1 if phase == 'review' else 2,
            'model_assisted': run['reasoning'] == 'llm', 'source_label': run['source_label'], 'coverage': {k: v for k, v in run['coverage'].items() if k != 'skipped_entries'},
            'evidence': run['evidence'], 'audit_findings': [{k: f.get(k) for k in ('id', 'package', 'version', 'advisory_id', 'summary', 'severity', 'status', 'github_verified', 'release_checks')} for f in run['findings'][:6]],
            'warnings': run['warnings'][:3], 'peer_positions': run['positions']}
        packets = await self.transport.exchange(phase, context, agent_ids)
        for packet in packets:
            if packet.error:
                raise RuntimeError(packet.error)
            run['model_calls'] += packet.model_calls
            run['model_tokens'] += packet.model_tokens
            receipts = run.setdefault('peer_receipts_by_agent', {})
            receipts[packet.agent_id] = max(receipts.get(packet.agent_id, 0), packet.peer_receipts)
            run['peer_receipts'] = sum(receipts.values())
            for event in packet.events:
                row = event.model_dump(mode='json')
                run['events'].append(row)
                if row['event_type'] == 'BELIEF_UPDATED':
                    run['positions'].append({'agent_id': packet.agent_id, **row['data'], 'reason': row['claim']})
        self.save(run)

    async def execute(self, run):
        run['state'] = 'running'
        self.save(run)
        try:
            async with asyncio.timeout(210):
                await self.load_source(run)
                # Each named tool is executed by its separately addressed worker.
                for agent_id in ['dependency_investigator', 'advisory_verifier', 'remediation_reviewer']:
                    await self.exchange(run, 'gather', [agent_id])
                participants = [a.agent_id for a in self.registry.agents]
                await self.exchange(run, 'review', participants)
                await self.exchange(run, 'challenge', participants)
                await self.exchange(run, 'observe', participants)
            run['state'] = 'completed'
        except asyncio.CancelledError:
            run['state'] = 'stopped'
            run['error'] = 'Audit stopped; completed observations retained'
        except Exception as exc:
            run['state'] = 'failed'
            run['error'] = f'{type(exc).__name__}: {str(exc)[:240]}'
        finally:
            run['completed_at'] = now()
            self.save(run)

    async def stop(self, run_id):
        run = self.get(run_id)
        task = self.tasks.get(run_id)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            if run['state'] == 'queued':
                run['state'], run['error'], run['completed_at'] = 'stopped', 'Stopped before audit execution', now()
                self.save(run)
        return run
