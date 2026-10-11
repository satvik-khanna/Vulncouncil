"""Real HTTP + SLIM acceptance for the executable billing use case."""
import asyncio
import json
from pathlib import Path
import time
import httpx


async def main():
    report = {"scope": "Local executable billing API; fictional tenants, invoices and demo credentials", "direct_http": [], "assessments": []}
    async with httpx.AsyncClient(timeout=15, trust_env=False) as client:
        for deployment, identity, expected in [("vulnerable", "alice-northstar", 200), ("patched", "alice-northstar", 403), ("patched", "bob-harbor", 200), ("patched", "beth-harbor", 200)]:
            route = f"/demo/{deployment}/invoices/INV-2001"
            response = await client.get("http://127.0.0.1:8001" + route, headers={"Authorization": "Bearer demo-" + identity})
            assert response.status_code == expected, response.text
            report["direct_http"].append({"route": route, "identity": identity, "status": response.status_code})
        health = (await client.get("http://127.0.0.1:8000/api/health")).json()
        report["health"] = health
        assert health["transport"] == "slim", health
        for scenario, patched, expected in [("tenant_invoice", False, "CONFIRMED"), ("tenant_invoice", True, "NOT_REPRODUCED"), ("tenant_invoice_change", False, "DISPUTED")]:
            response = await client.post("http://127.0.0.1:8000/api/runs", json={"scenario": scenario, "patched": patched})
            response.raise_for_status()
            run = response.json()
            deadline = time.monotonic() + 130
            while run["state"] in {"running", "queued"}:
                assert time.monotonic() < deadline, "Billing assessment exceeded deadline"
                await asyncio.sleep(.5)
                run = (await client.get(f"http://127.0.0.1:8000/api/runs/{run['run_id']}")).json()
            events = (await client.get(f"http://127.0.0.1:8000/api/runs/{run['run_id']}/events")).json()
            case = {"scenario": scenario, "initially_patched": patched, "expected": expected, "run": run, "events": events}
            report["assessments"].append(case)
            path = Path(__file__).resolve().parents[1] / "docs/billing-verification.json"
            path.write_text(json.dumps(report, indent=2))
            assert run["state"] == "completed", run.get("error")
            assert run["findings"][0]["status"] == expected, run["findings"][0]
            assert run["metrics"]["peer_receipts"] > 0
            if health["reasoning"] == "llm":
                assert run["metrics"]["model_calls"] > 0
            probes = [e for e in run["evidence"] if e["tool_name"] in {"cross_user_access", "access_reproduce"}]
            assert len({e["agent_id"] for e in probes}) >= 2
            assert all(e["method"] == "GET" and e["facts"]["controls_passed"] for e in probes)
            assert run["metrics"]["tool_requests"] == sum(e["facts"].get("http_requests", 1) for e in run["evidence"])
            if scenario == "tenant_invoice_change":
                assert any(e["result"] == "positive" and e["facts"]["environment_version"] == 0 for e in probes)
                assert any(e["result"] == "negative" and e["facts"]["environment_version"] == 1 for e in probes)
            print(f"PASS {scenario} patched={patched}: {expected}, {run['metrics']['tool_requests']} HTTP requests, {run['metrics']['model_calls']} model calls", flush=True)
        report["validated"] = True
        path.write_text(json.dumps(report, indent=2))
        print(f"Saved {path}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
