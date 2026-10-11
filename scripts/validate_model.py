"""Real provider acceptance; no mock responses and no stored credentials.

Use --local to try the existing qwen3:8b Ollama model against the fixture.
Otherwise set AGENT_REASONING=llm and LLM_* in .env. --benchmark costs
39 separately executed model assessments and is deliberately opt-in.
"""
import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import httpx
from dotenv import load_dotenv
from app.capability_discovery import CapabilityDiscovery
from app.run_service import RunService
from app.storage import Storage
from app.transports.memory_test import MemoryTestTransport
from lab_target.app import app as fixture
from schemas.models import AssessmentRequest
from tools.lab_client import LabClient


async def main(args):
    load_dotenv(ROOT / ".env")
    if args.local:
        os.environ.update(AGENT_REASONING="llm", LLM_API_KEY="local-ollama", LLM_BASE_URL="http://127.0.0.1:11434/v1", LLM_MODEL=args.local_model)
        os.environ["LLM_PROVIDER"] = "ollama"
        print("Warming the existing local model before the bounded assessment…", flush=True)
        async with httpx.AsyncClient(timeout=120, trust_env=False) as client:
            warm = await client.post("http://127.0.0.1:11434/api/chat", json={"model":args.local_model, "messages":[{"role":"user", "content":"Respond READY."}], "think":False, "stream":False, "options":{"num_predict":10, "num_ctx":4096}, "keep_alive":"10m"})
            warm.raise_for_status()
    if os.getenv("AGENT_REASONING") != "llm" or not all(os.getenv(k) for k in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL")):
        print("PENDING: configure AGENT_REASONING=llm and all LLM_* settings, or use --local. No real provider validation claimed.")
        return 2
    logging.getLogger("httpx").setLevel(logging.WARNING)
    registry = CapabilityDiscovery()
    storage = Storage(":memory:")
    service = RunService(storage, registry, LabClient("http://lab-target:8001", transport=httpx.ASGITransport(app=fixture)))
    service.transport = MemoryTestTransport(registry, lambda run_id: service.gateways[run_id], allow_model=True)
    report = {"model": os.environ["LLM_MODEL"], "provider": "local Ollama" if args.local else "configured provider", "transport":"memory", "mocked":False, "requested_scenarios":args.scenarios, "cases":[], "limitations":"Real inference with synthetic fixture and memory transport; does not establish real-world accuracy or validate model inference over SLIM."}
    try:
        for scenario in args.scenarios:
            print(f"Running real model assessment: {scenario}", flush=True)
            run = await service.open(AssessmentRequest(scenario=scenario), background=False)
            events = storage.events(run.run_id)
            expected = {"ambiguous_injection":"NOT_REPRODUCED", "access_control":"CONFIRMED", "changing_access":"DISPUTED"}.get(scenario)
            report["cases"].append({"expected":expected, "correct_status": run.findings[0].status.value == expected if expected else None, "run":run.model_dump(mode="json"), "events":events})
            print(f"{run.state}: {run.findings[0].status}; {run.metrics.model_calls} calls, {run.metrics.model_tokens} tokens; {run.error or ''}", flush=True)
            if run.state != "completed":
                report["validated"] = False
                continue
            assert run.metrics.model_calls > 0
            ids = {e.evidence_id for e in run.evidence}
            assert all(set(v.evidence_ids) <= ids for f in run.findings for v in f.votes)
            assert any(e["event_type"] == "PLAN_UPDATED" for e in events)
            if scenario == "changing_access":
                assert run.findings[0].status.value in {"DISPUTED", "NEEDS_HUMAN"}, "Unsupported confirmation under conflict"
        else:
            report["execution_validated"] = all(case["run"]["state"] == "completed" for case in report["cases"])
            report["validated"] = report["execution_validated"] and all(case["correct_status"] is True for case in report["cases"])
            if not report["validated"]:
                report["failure_reason"] = "Real inference completed but did not match every requested acceptance disposition"
        if args.benchmark and report["validated"]:
            from app.evaluation import evaluate
            report["evaluation"] = await evaluate(service)
    finally:
        path = ROOT / "docs/model-verification.json"
        history_path = ROOT / "docs/model-attempts.json"
        attempts = json.loads(history_path.read_text()) if history_path.exists() else []
        attempts.append(report)
        history_path.write_text(json.dumps(attempts, indent=2))
        path.write_text(json.dumps(report, indent=2))
        storage.db.close()
    print(f"Saved real provider evidence: {path}")
    return 0 if report.get("validated") else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--local-model", default="qwen3:8b", help="An already installed Ollama model")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--scenarios", nargs="+", default=["ambiguous_injection", "access_control", "changing_access"])
    sys.exit(asyncio.run(main(parser.parse_args())))
