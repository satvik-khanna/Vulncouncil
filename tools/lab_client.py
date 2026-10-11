import hashlib
import httpx


class LabClient:
    def __init__(self, base_url: str, transport=None):
        self.base_url = base_url.rstrip("/")
        self.transport = transport

    async def check(self, name: str, scenario: str, patched: bool, variant: str = "standard"):
        # No redirects or environment proxy: only the gateway's validated origin.
        async with httpx.AsyncClient(transport=self.transport, timeout=4, follow_redirects=False, trust_env=False) as client:
            response = await client.post(self.base_url + "/checks", json={"check": name, "scenario": scenario, "patched": patched, "variant": variant})
            response.raise_for_status()
            return response.json()

    async def invoice_probe(self, name: str, patched: bool, authorize):
        """Three real HTTP reads. No canned vulnerability result or raw invoice persistence."""
        invoice_id = "INV-2001" if name == "cross_user_access" else "INV-2002"
        deployment = "patched" if patched else "vulnerable"
        route = f"/demo/{deployment}/invoices/{invoice_id}"
        observations = {}
        async with httpx.AsyncClient(transport=self.transport, timeout=4, follow_redirects=False, trust_env=False) as client:
            for role, token in (("owner", "demo-bob-harbor"), ("colleague", "demo-beth-harbor"), ("outsider", "demo-alice-northstar")):
                authorize(self.base_url + route, "GET")
                response = await client.get(self.base_url + route, headers={"Authorization": "Bearer " + token})
                body = response.json()
                observations[role] = {"status": response.status_code, "body": body, "hash": hashlib.sha256(response.content).hexdigest()}
        owner, colleague, outsider = (observations[r] for r in ("owner", "colleague", "outsider"))
        controls_ok = all(o["status"] == 200 and o["body"].get("id") == invoice_id and o["body"].get("tenant") == "harbor" for o in (owner, colleague))
        exposed = outsider["status"] == 200 and outsider["body"] == owner["body"]
        denied = outsider["status"] == 403
        result = "positive" if controls_ok and exposed else "negative" if controls_ok and denied else "incomplete"
        return {"result": result, "status_code": outsider["status"], "reproducible": result != "incomplete", "reproduction_failed": result == "negative",
                "record_visible": exposed, "guard_enabled": patched, "actor": "alice", "record_owner": "bob",
                "actor_tenant": "northstar", "resource_tenant": "harbor", "invoice_id": invoice_id,
                "owner_status": owner["status"], "same_tenant_status": colleague["status"], "controls_passed": controls_ok,
                "response_matches_owner": exposed,
                "owner_response_hash": owner["hash"], "outsider_response_hash": outsider["hash"], "http_requests": 3,
                "sensitive_fields": ["customer", "billing_email", "amount_usd", "payment_reference"] if exposed else [],
                "policy": "Authenticated users may read invoices belonging to their server-assigned tenant; other tenants must be denied.",
                "observed_route": route}

