import asyncio
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import httpx
from app.capability_discovery import CapabilityDiscovery
from app.evaluation import evaluate
from app.run_service import RunService
from app.storage import Storage
from app.transports.memory_test import MemoryTestTransport
from lab_target.app import app as fixture
from tools.lab_client import LabClient


async def main():
    service = RunService(Storage(":memory:"), CapabilityDiscovery(), LabClient("http://lab-target:8001", transport=httpx.ASGITransport(app=fixture)))
    service.transport = MemoryTestTransport(service.registry, lambda run_id: service.gateways[run_id], allow_model=False)
    result = await evaluate(service)
    output = Path(__file__).resolve().parents[1] / "docs/evaluation-results.json"
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps({"scores": result["scores"], "belief_revisions": result["belief_revisions"], "blocked_requests": result["blocked_requests"], "transport": result["transport"]}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
