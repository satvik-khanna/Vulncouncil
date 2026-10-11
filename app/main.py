import asyncio
from contextlib import asynccontextmanager
import json
import logging
import os
from pathlib import Path
import secrets

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from app.capability_discovery import CapabilityDiscovery, ROOT
from app.deliberation import POLICY
from app.evaluation import evaluate
from app.run_service import RunService
from app.safety_gate import SafetyBlocked
from app.storage import Storage
from app.transports.memory_test import MemoryTestTransport
from schemas.models import AssessmentRequest, GatewayRequest, InterventionRequest
from tools.lab_client import LabClient
from schemas.audit import AuditRequest
from app.repository_audit import RepositoryAuditService

load_dotenv(ROOT / ".env")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
registry = CapabilityDiscovery()
audit_registry = CapabilityDiscovery(ROOT / "config/audit_agents.yaml")
storage = Storage(os.getenv("DATABASE_PATH", str(ROOT / "data/vulncouncil.sqlite3")))
service = RunService(storage, registry, LabClient(os.getenv("LAB_BASE_URL", "http://127.0.0.1:8001")), float(os.getenv("EVENT_DELAY", ".08")))
transport_mode = os.getenv("AGNTCY_TRANSPORT", "slim")
if transport_mode == "slim":
    from app.transports.agntcy_slim import AgntcySlimTransport
    worker_registry = CapabilityDiscovery()
    worker_registry.agents.extend(audit_registry.agents)
    service.transport = AgntcySlimTransport(worker_registry)
elif transport_mode == "memory":
    service.transport = MemoryTestTransport(registry, lambda run_id: service.gateways[run_id])
else:
    raise RuntimeError("AGNTCY_TRANSPORT must be explicitly slim or memory")

audit_service = RepositoryAuditService(audit_registry, service.transport)
if transport_mode == "memory":
    audit_service.transport = MemoryTestTransport(audit_registry, lambda run_id: audit_service.gateways[run_id])


@asynccontextmanager
async def lifespan(app):
    # A restart cannot honestly resume an interrupted distributed assessment.
    for saved in storage.list():
        if saved["state"] in {"queued", "running"}:
            stale = service.get(saved["run_id"])
            stale.state = "failed"
            stale.error = "Server restarted during the assessment; start a new run"
            storage.save(stale)
    if transport_mode == "slim":
        await service.transport.start()
    for saved in audit_service.list():
        if saved["state"] in {"queued", "running"}:
            saved["state"], saved["error"] = "failed", "Server restarted; start a new live audit"
            audit_service.save(saved)
    yield
    for run_id, task in list(audit_service.tasks.items()):
        if not task.done():
            await audit_service.stop(run_id)
    for run_id, task in list(service.tasks.items()):
        if not task.done():
            await service.stop(run_id)
    await service.transport.close()


app = FastAPI(title="VulnCouncil", lifespan=lifespan)


@app.get("/api/health")
def health():
    return {"status": "ok", "transport": transport_mode, "reasoning": os.getenv("AGENT_REASONING", "rules"), "discovery": registry.mode}


@app.get("/api/config")
def config():
    from app.safety_gate import SafetyGate
    return {"transport": transport_mode, "discovery": registry.mode, "reasoning": os.getenv("AGENT_REASONING", "rules"), "scenarios": service.scenarios,
            "agents": [a.model_dump() for a in registry.agents], "safety": SafetyGate().policy, "deliberation": POLICY}


@app.get("/api/agents/manifests")
def manifests():
    return registry.manifests()


@app.get("/api/agents/{agent_id}/.well-known/agent-card.json")
def agent_card(agent_id: str):
    from a2a.types import AgentCard, AgentCapabilities, AgentSkill, AgentInterface
    from agntcy_app_sdk.semantic.a2a.server.card_bootstrap import InterfaceTransport
    try:
        cap = registry.get(agent_id)
    except StopIteration:
        raise HTTPException(404, "Unknown agent")
    card = AgentCard(name=f"vulncouncil/agents/{agent_id}", description=cap.description, version=cap.version,
        url=f"slim://127.0.0.1:46357/vulncouncil/agents/{agent_id}", defaultInputModes=["text"], defaultOutputModes=["text"], capabilities=AgentCapabilities(),
        skills=[AgentSkill(id=skill, name=skill, description=cap.objective, tags=[skill]) for skill in cap.skills],
        preferredTransport=InterfaceTransport.SLIM_PATTERNS,
        additional_interfaces=[AgentInterface(transport=InterfaceTransport.SLIM_PATTERNS, url=f"slim://127.0.0.1:46357/vulncouncil/agents/{agent_id}")])
    return card.model_dump(mode="json")


@app.get("/api/runs")
def runs():
    return storage.list()


@app.post("/api/runs", status_code=202)
async def create(request: AssessmentRequest):
    try:
        if any(r["state"] in {"queued", "running"} for r in audit_service.runs.values()):
            raise ValueError("A live repository audit is active; wait or stop it before starting a lab assessment")
        return await service.open(request)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/runs/{run_id}")
def detail(run_id: str):
    run = service.get(run_id)
    if not run:
        raise HTTPException(404, "Assessment not found")
    return run


@app.post("/api/runs/{run_id}/stop")
async def stop(run_id: str):
    try:
        return await service.stop(run_id)
    except KeyError as exc:
        raise HTTPException(404, "Assessment not found") from exc


@app.post("/api/runs/{run_id}/intervene")
async def intervene(run_id: str, request: InterventionRequest):
    try:
        return await service.intervene(run_id, request.action)
    except KeyError as exc:
        raise HTTPException(404, "Assessment not found") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/runs/{run_id}/events")
def events(run_id: str, after: int = 0):
    detail(run_id)
    return storage.events(run_id, after)


@app.get("/api/runs/{run_id}/stream")
async def stream(run_id: str, last_event_id: str | None = Header(default=None), after: int = 0):
    detail(run_id)
    try:
        cursor = max(after, int(last_event_id or 0))
    except ValueError:
        raise HTTPException(400, "Invalid event cursor")
    async def generate():
        nonlocal cursor
        heartbeat = 0
        while True:
            rows = storage.events(run_id, cursor)
            for row in rows:
                cursor = row["seq"]
                yield f"id: {cursor}\nevent: council\ndata: {json.dumps(row)}\n\n"
            run = service.get(run_id)
            if run.state not in {"queued", "running"}:
                yield f"event: done\ndata: {json.dumps({'state': run.state})}\n\n"
                break
            heartbeat += 1
            if heartbeat % 40 == 0:
                yield ": heartbeat\n\n"
            await asyncio.sleep(.25)
    return StreamingResponse(generate(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/internal/check")
async def check(request: GatewayRequest, x_worker_key: str = Header(default="")):
    key = getattr(service.transport, "gateway_keys", {}).get(request.agent_id, "")
    if not key or not secrets.compare_digest(x_worker_key, key):
        raise HTTPException(403, "Internal gateway authentication required")
    gateway = service.gateways.get(request.run_id)
    if not gateway or gateway.run.state != "running":
        raise HTTPException(409, "No active assessment for this request")
    try:
        return await gateway.check(request.agent_id, request.check, request.finding_id)
    except SafetyBlocked as exc:
        raise HTTPException(403, str(exc)) from exc


evaluation_lock = asyncio.Lock()


@app.get("/api/audits/config")
def audit_config():
    return {"agents": [a.model_dump() for a in audit_registry.agents], "max_packages": 500, "max_detailed_findings": 8,
            "providers": ["OSV", "GitHub Advisory Database", "PyPI", "npm"], "transport": transport_mode}


@app.get("/api/audits")
def audits():
    return audit_service.list()


@app.post("/api/audits", status_code=202)
async def create_audit(request: AuditRequest):
    try:
        if any(r.state in {"queued", "running"} for r in service.runs.values()):
            raise ValueError("A lab assessment is active; wait or stop it before starting a live audit")
        return await audit_service.open(request)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/audits/{run_id}")
def audit_detail(run_id: str):
    try:
        return audit_service.get(run_id)
    except KeyError:
        raise HTTPException(404, "Live audit not found")


@app.post("/api/audits/{run_id}/stop")
async def stop_audit(run_id: str):
    try:
        return await audit_service.stop(run_id)
    except KeyError:
        raise HTTPException(404, "Live audit not found")


@app.post("/api/internal/audit-check")
async def audit_check(request: GatewayRequest, x_worker_key: str = Header(default="")):
    key = getattr(service.transport, "gateway_keys", {}).get(request.agent_id, "")
    if not key or not secrets.compare_digest(x_worker_key, key):
        raise HTTPException(403, "Internal gateway authentication required")
    gateway = audit_service.gateways.get(request.run_id)
    if not gateway:
        raise HTTPException(409, "No active live audit")
    try:
        return await gateway.check(request.agent_id, request.check, request.finding_id)
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc


@app.post("/api/evaluation")
async def benchmark(use_model: bool = False):
    if evaluation_lock.locked():
        raise HTTPException(409, "Evaluation is already running")
    async with evaluation_lock:
        if use_model and (os.getenv("AGENT_REASONING", "rules") != "llm" or not all(os.getenv(k) for k in ("LLM_API_KEY", "LLM_MODEL", "LLM_BASE_URL"))):
            raise HTTPException(409, "Model evaluation requires configured llm mode")
        # Benchmark uses a fresh in-process test bus and real fixture requests.
        # Clearly label the mode; it is not evidence of a live SLIM evaluation.
        benchmark_storage = Storage(":memory:")
        benchmark_service = RunService(benchmark_storage, registry, service.lab_client)
        benchmark_service.transport = MemoryTestTransport(registry, lambda run_id: benchmark_service.gateways[run_id], allow_model=use_model)
        try:
            result = await evaluate(benchmark_service)
            (ROOT / "data/evaluation.json").write_text(json.dumps(result, indent=2))
            return result
        finally:
            benchmark_storage.db.close()


@app.get("/api/evaluation")
def benchmark_result():
    path = ROOT / "data/evaluation.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


dist = ROOT / "frontend/dist"
if dist.exists():
    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
    @app.get("/")
    def index():
        return FileResponse(dist / "index.html")

    @app.get("/favicon.svg")
    def favicon():
        return FileResponse(dist / "favicon.svg", media_type="image/svg+xml")
