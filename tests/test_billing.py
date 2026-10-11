import httpx
import pytest
from lab_target.app import app
from lab_target.scenarios import fixture_check
from schemas.models import AssessmentRequest, Status
from app.safety_gate import SafetyGate, SafetyBlocked
from tools.lab_client import LabClient


@pytest.mark.parametrize("deployment,token,status", [
    ("vulnerable", "demo-alice-northstar", 200),
    ("patched", "demo-alice-northstar", 403),
    ("patched", "demo-bob-harbor", 200),
    ("patched", "demo-beth-harbor", 200),
    ("vulnerable", "made-up", 401),
    ("patched", "", 401),
])
async def test_billing_authorization(deployment, token, status):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://lab-target:8001") as client:
        response = await client.get(f"/demo/{deployment}/invoices/INV-2001", headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": "harbor"})
    assert response.status_code == status
    if status == 200:
        assert response.json()["id"] == "INV-2001"
        assert response.json()["tenant"] == "harbor"
    else:
        assert "billing_email" not in response.text


@pytest.mark.parametrize("scenario,patched,expected", [
    ("tenant_invoice", False, Status.CONFIRMED),
    ("tenant_invoice", True, Status.NOT_REPRODUCED),
    ("tenant_invoice_change", False, Status.DISPUTED),
])
async def test_billing_council(service, scenario, patched, expected):
    run = await service.open(AssessmentRequest(scenario=scenario, patched=patched), background=False)
    assert run.state == "completed", run.error
    assert run.findings[0].status == expected
    probes = [e for e in run.evidence if e.tool_name in {"cross_user_access", "access_reproduce"}]
    assert len({e.agent_id for e in probes}) >= 2
    assert {e.facts["invoice_id"] for e in probes} == {"INV-2001", "INV-2002"}
    assert all(e.method == "GET" and e.route.startswith("/demo/") for e in probes)
    assert all(e.facts["owner_status"] == e.facts["same_tenant_status"] == 200 for e in probes)
    assert run.metrics.tool_requests == sum(e.facts.get("http_requests", 1) for e in run.evidence)
    assert all("billing@harbor.example" not in e.snippet and "demo-alice" not in e.snippet for e in probes)
    if scenario == "tenant_invoice_change":
        assert any(e.result == "positive" and e.facts["environment_version"] == 0 for e in probes)
        assert any(e.result == "negative" and e.facts["environment_version"] == 1 for e in probes)


def test_invoice_result_cannot_be_generated_by_fixture():
    with pytest.raises(ValueError, match="billing HTTP API"):
        fixture_check("cross_user_access", "tenant_invoice")


@pytest.mark.parametrize("route,method,check", [
    ("/demo/vulnerable/invoices/INV-9999", "GET", "cross_user_access"),
    ("/demo/patched/invoices/INV-2001", "POST", "cross_user_access"),
    ("/demo/patched/invoices/INV-2001", "GET", "inventory"),
    ("/checks", "GET", "inventory"),
])
def test_invoice_scope_is_finite(route, method, check):
    with pytest.raises(SafetyBlocked):
        SafetyGate().validate("http://lab-target:8001" + route, method, check, "test-agent", [check])


@pytest.mark.parametrize("failure", ["controls_denied", "wrong_invoice"])
async def test_unexpected_http_responses_cannot_establish_patch_or_leak(failure):
    def response(request):
        outsider = request.headers["Authorization"] == "Bearer demo-alice-northstar"
        if failure == "controls_denied":
            return httpx.Response(403, json={"detail": "broken application denies everyone"})
        return httpx.Response(200, json={"id": "INV-9999" if outsider else "INV-2001", "tenant": "harbor"})
    client = LabClient("http://lab-target:8001", transport=httpx.MockTransport(response))
    result = await client.invoice_probe("cross_user_access", False, lambda url, method: None)
    assert result["result"] == "incomplete"
    assert not result["reproducible"] and not result["reproduction_failed"]
