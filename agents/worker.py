"""One independently addressable specialist per process in the SLIM demo."""
import argparse
import asyncio
import json
import os
from pathlib import Path

import httpx
from a2a.types import SendMessageRequest, SendMessageResponse
from a2a.utils import new_agent_text_message
from agntcy_app_sdk.factory import AgntcyFactory
from agntcy_app_sdk.semantic.message import Message

from agents.factory import create_agent
from agents.reasoning import run_specialist
from app.capability_discovery import CapabilityDiscovery
from schemas.models import AgentPacket, Evidence


async def serve(agent_id: str, ready_file: str):
    try:
        cap = CapabilityDiscovery().get(agent_id)
    except StopIteration:
        cap = CapabilityDiscovery(Path(__file__).resolve().parents[1] / "config/audit_agents.yaml").get(agent_id)
    agent = create_agent(cap)
    factory = AgntcyFactory(enable_tracing=False)
    transport = factory.create_transport("SLIM", endpoint=os.getenv("SLIM_ENDPOINT", "http://127.0.0.1:46357"),
                                         name=f"vulncouncil/agents/{agent_id}", shared_secret_identity=os.getenv("SLIM_SHARED_SECRET", "vulncouncil-local-demo-shared-secret-32-chars"))
    await transport.setup()

    async def callback(message, **kwargs):
        payload = json.loads(message.payload)
        if "result" in payload:
            result = payload["result"]
            parts = result.get("parts", [])
            if parts:
                packet_data = json.loads(parts[0]["text"])
                if packet_data.get("kind") == "agent_packet":
                    agent.observe(packet_data["run_id"], AgentPacket.model_validate(packet_data["packet"]))
            return None  # Peer events are observed, never echoed into a message loop.
        request = SendMessageRequest.model_validate(payload)
        context_data = json.loads(request.params.message.parts[0].root.text)
        phase, context = context_data["phase"], context_data["context"]
        async def check(name, finding_id):
            async with httpx.AsyncClient(timeout=45 if context.get("domain") == "repository_audit" else 8, trust_env=False) as client:
                route = "/api/internal/audit-check" if context.get("domain") == "repository_audit" else "/api/internal/check"
                r = await client.post(os.getenv("GATEWAY_BASE_URL", "http://127.0.0.1:8000") + route,
                                      json={"run_id": context["run_id"], "agent_id": agent_id, "check": name, "finding_id": finding_id},
                                      headers={"X-Worker-Key": os.environ["WORKER_GATEWAY_KEY"]})
                r.raise_for_status()
                return Evidence.model_validate(r.json())
        try:
            from app.telemetry import tracer
            with tracer.start_as_current_span("agent.step", attributes={"agent.id": agent_id, "run.id": context["run_id"], "phase": phase}):
                packet = await run_specialist(agent, phase, context, check)
            packet.peer_receipts = agent.receipts_by_run.get(context["run_id"], 0)
        except Exception as exc:
            packet = AgentPacket(agent_id=agent_id, error=f"{type(exc).__name__}: specialist check failed; inspect gateway audit")
        response = SendMessageResponse(root={"jsonrpc": "2.0", "id": request.id, "result": new_agent_text_message(json.dumps({"kind": "agent_packet", "run_id": context["run_id"], "packet": packet.model_dump(mode="json")})).model_dump(mode="json")})
        return Message(type="A2A", payload=response.model_dump_json().encode())

    transport.set_callback(callback)
    Path(ready_file).write_text(agent_id)
    try:
        await asyncio.Event().wait()
    finally:
        await transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True)
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()
    asyncio.run(serve(args.agent, args.ready_file))

