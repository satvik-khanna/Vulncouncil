import json
import httpx
import pytest
from app.capability_discovery import CapabilityDiscovery, ROOT
from app.repository_audit import RepositoryAuditService, parse_artifact
from app.transports.memory_test import MemoryTestTransport
from schemas.audit import AuditRequest
from tools.advisory_client import AdvisoryClient


def test_exact_pins_and_unresolved_requirements_are_separate():
    packages, skipped = parse_artifact('requirements.txt', 'Requests==2.19.1 ; python_version < "3.10"\nflask>=2\n-r another.txt\n# note\n')
    assert packages[0]['name'] == 'requests' and packages[0]['version'] == '2.19.1'
    assert packages[0]['marker']
    assert len(skipped) == 2


def test_npm_nested_versions_and_scoped_names():
    content = json.dumps({'lockfileVersion': 3, 'packages': {'': {'name': 'root', 'version': '1'}, 'node_modules/@scope/name': {'version': '1.2.3'}, 'node_modules/parent/node_modules/foo': {'version': '2.0.0'}, 'node_modules/link': {'link': True}}})
    pins, skipped = parse_artifact('package-lock.json', content)
    assert [(p['name'], p['version']) for p in pins] == [('@scope/name', '1.2.3'), ('foo', '2.0.0')]
    assert len(skipped) == 1


@pytest.mark.parametrize('url', ['http://api.osv.dev/v1/querybatch', 'https://api.osv.dev.evil.test/v1/querybatch', 'https://user:pass@api.osv.dev/v1/querybatch', 'https://api.osv.dev:8443/v1/querybatch'])
async def test_public_api_origin_boundary(url):
    with pytest.raises(ValueError, match='allowlist'):
        await AdvisoryClient().request('GET', url)


def build_service(tmp_path, handler):
    registry = CapabilityDiscovery(ROOT / 'config/audit_agents.yaml')
    service = RepositoryAuditService(registry, None, tmp_path, lambda: AdvisoryClient(httpx.MockTransport(handler)))
    service.transport = MemoryTestTransport(registry, lambda run_id: service.gateways[run_id], allow_model=False)
    return service


def responses(request, github_status=200, fail_osv=False):
    path, host = request.url.path, request.url.host
    if host == 'api.github.com' and '/commits/' in path:
        return httpx.Response(200, json={'sha': 'a' * 40})
    if host == 'raw.githubusercontent.com':
        assert '/'+('a'*40)+'/' in path
        return httpx.Response(200, text='requests==2.19.1\nunknown>=1\n')
    if path == '/v1/querybatch':
        submitted = json.loads(request.content)['queries']
        if submitted[0]['version'] == '2.20.0':
            return httpx.Response(200, json={'results': [{}]})
        assert submitted[0]['version'] == '2.19.1'
        return httpx.Response(503 if fail_osv else 200, json={'results': [{'vulns': [{'id': 'GHSA-test-record'}]}]})
    if '/v1/vulns/' in path:
        return httpx.Response(200, json={'id': 'GHSA-test-record', 'summary': 'Test advisory', 'aliases': ['CVE-TEST'], 'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'requests'}, 'ranges': [{'events': [{'introduced': '0'}, {'fixed': '2.20.0'}]}]}]})
    if path == '/advisories':
        assert request.url.params['affects'] == 'requests@2.19.1'
        return httpx.Response(github_status, json=[{'ghsa_id': 'GHSA-test-record', 'cve_id': 'CVE-TEST', 'html_url': 'https://github.com/advisories/GHSA-test-record', 'severity': 'high'}] if github_status==200 else {'message': 'rate limit'})
    if host == 'pypi.org':
        return httpx.Response(200, json={'info': {'version': '2.20.0'}})
    raise AssertionError(str(request.url))


async def test_real_artifact_pipeline_does_not_conflate_match_with_exploit(tmp_path):
    service = build_service(tmp_path, responses)
    run = await service.open(AuditRequest(source='github', repository='example/repo', paths=['requirements.txt']), background=False)
    assert run['state'] == 'completed', run['error']
    assert run['commit_sha'] == 'a'*40 and len(run['artifacts'][0]['sha256']) == 64
    assert run['findings'][0]['status'] == 'AFFECTED_VERSION_VERIFIED'
    assert run['findings'][0]['exploitability'] == 'NOT_ASSESSED'
    assert run['findings'][0]['release_checks'][0]['published']
    assert run['upgrade_candidates'][0]['version'] == '2.20.0'
    assert run['upgrade_candidates'][0]['known_match_count'] == 0
    assert run['upgrade_candidates'][0]['compatibility'] == 'NOT_ASSESSED'
    assert len(run['coverage']['skipped_entries']) == 1
    assert len(run['positions']) == 6
    assert service.get(run['run_id'])['http_requests']


async def test_failed_osv_request_is_not_reported_as_no_vulnerabilities(tmp_path):
    service = build_service(tmp_path, lambda r: responses(r, fail_osv=True))
    run = await service.open(AuditRequest(source='github', paths=['requirements.txt']), background=False)
    assert run['state'] == 'failed' and run['error']
    assert 'advisory_hits' not in run['coverage']


async def test_rate_limited_corroboration_stays_unknown(tmp_path):
    service = build_service(tmp_path, lambda r: responses(r, github_status=403))
    run = await service.open(AuditRequest(source='github', paths=['requirements.txt']), background=False)
    assert run['state'] == 'completed'
    assert run['findings'][0]['status'] == 'REVIEW_REQUIRED'
    assert not run['findings'][0]['github_verified']
    assert any('unavailable' in w for w in run['warnings'])


@pytest.mark.parametrize('path', ['../requirements.txt', '/etc/passwd', 'folder/../requirements.txt', 'requirements.txt?url=evil'])
async def test_repository_path_traversal_rejected(tmp_path, path):
    service = build_service(tmp_path, responses)
    with pytest.raises(ValueError):
        await service.open(AuditRequest(source='github', paths=[path]), background=False)
