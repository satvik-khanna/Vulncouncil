"""Verify real SLIM behavior through the public API; stores judge-reviewable proof."""
import asyncio
import json
from pathlib import Path
import time
import httpx

CASES = [("ambiguous_injection", False, "NOT_REPRODUCED"), ("access_control", False, "CONFIRMED"),
         ("patched_access", True, "NOT_REPRODUCED"), ("scope_violation", False, "NEEDS_HUMAN"), ("changing_access", False, "DISPUTED")]


async def main():
    results = []
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000", timeout=15, trust_env=False) as client:
        health = (await client.get("/api/health")).json()
        assert health["transport"] == "slim", "This check requires real SLIM mode"
        ui = await client.get("/")
        assert ui.status_code == 200 and "VulnCouncil" in ui.text
        for scenario, patched, expected in CASES:
            response = await client.post("/api/runs", json={"scenario": scenario, "patched": patched})
            response.raise_for_status()
            run = response.json()
            deadline = time.monotonic() + 125
            while run["state"] in {"queued", "running"}:
                assert time.monotonic() < deadline, "Live assessment exceeded deadline"
                await asyncio.sleep(.3)
                run = (await client.get(f"/api/runs/{run['run_id']}")).json()
            assert run["state"] in {"completed", "stopped"}, run.get("error")
            assert run["findings"][0]["status"] == expected, run
            events = (await client.get(f"/api/runs/{run['run_id']}/events")).json()
            assert events[-1]["event_type"] == "ASSESSMENT_COMPLETED", "Terminal state must include its durable final event"
            if scenario != "scope_violation":
                kinds = ["CHALLENGE", "BELIEF_UPDATED", "FINDING_RESOLVED"] + (["PLAN_UPDATED", "TOOL_RESULT"] if health["reasoning"] == "llm" else ["COUNTEREVIDENCE"])
                for kind in kinds:
                    assert any(e["event_type"] == kind for e in events), kind
                assert run["metrics"]["peer_receipts"] > 0
                if health["reasoning"] == "llm":
                    assert run["metrics"]["model_calls"] > 0
                    refs = {e["evidence_id"] for e in run["evidence"]}
                    assert all(set(v["evidence_ids"]) <= refs for v in run["findings"][0]["votes"])
                else:
                    assert run["metrics"]["belief_revisions"] > 0
            if scenario == "changing_access":
                assert run["environment_version"] == 1
                if health["reasoning"] == "rules":
                    assert "hardening_agent" in run["selected_agents"]
                    assert any(e["event_type"] == "COLLABORATOR_REQUESTED" for e in events)
                assert any(e["result"] == "positive" and e["facts"]["environment_version"] == 0 for e in run["evidence"])
                assert any(e["result"] == "negative" and e["facts"]["environment_version"] == 1 for e in run["evidence"])
            results.append({"scenario": scenario, "expected": expected, "run": run, "events": events})
            print(f"PASS {scenario}: {expected}; {run['metrics']['peer_receipts']} peer receipts", flush=True)
        response = await client.post("/api/evaluation", timeout=120)
        response.raise_for_status()
        evaluation = response.json()
        assert len(evaluation["cases"]) == 13
    path = Path(__file__).resolve().parents[1] / ("docs/model-slim-verification.json" if health["reasoning"] == "llm" else "docs/live-verification.json")
    path.write_text(json.dumps({"health": health, "cases": results, "evaluation": evaluation}, indent=2))
    print(f"Saved real transport proof: {path}")


if __name__ == "__main__":
    asyncio.run(main())
