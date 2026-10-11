"""Bounded public API access. No arbitrary origins, redirects, code execution or install."""
import hashlib
import json
from urllib.parse import urlsplit
import httpx


class AdvisoryClient:
    ORIGINS = {'api.github.com', 'raw.githubusercontent.com', 'api.osv.dev', 'pypi.org', 'registry.npmjs.org'}

    def __init__(self, transport=None):
        self.transport = transport
        self.requests = []

    async def request(self, method, url, **kwargs):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in self.ORIGINS or parsed.port not in {None, 443} or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Public audit request is outside the fixed API origin allowlist')
        if method not in {'GET', 'POST'} or (method == 'POST' and url != 'https://api.osv.dev/v1/querybatch'):
            raise ValueError('Public audit method is not allowed')
        if len(self.requests) >= 60:
            raise ValueError('Public audit HTTP budget exhausted')
        record = {'method': method, 'url': url, 'status': None}
        if kwargs.get('params'):
            record['params'] = kwargs['params']
        if kwargs.get('json'):
            record['request_sha256'] = hashlib.sha256(json.dumps(kwargs['json'], sort_keys=True).encode()).hexdigest()
        self.requests.append(record)
        async with httpx.AsyncClient(transport=self.transport, timeout=12, follow_redirects=False, trust_env=False) as client:
            async with client.stream(method, url, headers={'User-Agent': 'VulnCouncil-local-audit', 'Accept': 'application/json'}, **kwargs) as response:
                record['status'] = response.status_code
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > 2_000_000:
                        raise ValueError('Public API response exceeds the 2 MB audit limit')
                    chunks.append(chunk)
                body = b''.join(chunks)
                record['response_sha256'] = hashlib.sha256(body).hexdigest()
                record['bytes'] = size
                response.raise_for_status()
                return body

    async def json(self, method, url, **kwargs):
        return json.loads(await self.request(method, url, **kwargs))
