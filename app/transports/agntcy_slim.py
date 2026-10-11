"""Verified App SDK 0.5.5 A2A group chat, with six independent worker processes."""
import asyncio
import json
import os
from pathlib import Path
import sys
from uuid import uuid4

from app.transports.base import CouncilTransport
from schemas.models import AgentPacket


class AgntcySlimTransport(CouncilTransport):
    mode = "slim"

    def __init__(self, registry):
        self.registry = registry
        self.processes = []
        self.handles = []
        self.transport = None
        self.client = None
        self.lock = asyncio.Lock()
        self.gateway_keys = {cap.agent_id: uuid4().hex + uuid4().hex for cap in registry.agents}
        self.logs = Path("data/workers")

    async def start(self):
        from agntcy_app_sdk.factory import AgntcyFactory
        from agntcy_app_sdk.semantic.a2a.client.config import ClientConfig
        from agntcy_app_sdk.semantic.a2a.server.card_bootstrap import InterfaceTransport
        from a2a.types import AgentCard, AgentCapabilities
        self.logs.mkdir(parents=True, exist_ok=True)
        for cap in self.registry.agents:
            ready = self.logs / f"{cap.agent_id}.ready"
            ready.unlink(missing_ok=True)
            handle = (self.logs / f"{cap.agent_id}.log").open("w")
            self.handles.append(handle)
            process = await asyncio.create_subprocess_exec(sys.executable, "-m", "agents.worker", "--agent", cap.agent_id, "--ready-file", str(ready),
                            stdout=handle, stderr=handle, env={**os.environ, "WORKER_GATEWAY_KEY": self.gateway_keys[cap.agent_id]})
            self.processes.append(process)
        try:
            async with asyncio.timeout(30):
                while not all((self.logs / f"{cap.agent_id}.ready").exists() for cap in self.registry.agents):
                    if any(p.returncode is not None for p in self.processes):
                        raise RuntimeError("SLIM worker failed to start; inspect data/workers/*.log")
                    await asyncio.sleep(.2)
            factory = AgntcyFactory(enable_tracing=False)
            self.transport = factory.create_transport("SLIM", endpoint=os.getenv("SLIM_ENDPOINT", "http://127.0.0.1:46357"), name="vulncouncil/agents/facilitator",
                                 shared_secret_identity=os.getenv("SLIM_SHARED_SECRET", "vulncouncil-local-demo-shared-secret-32-chars"))
            await self.transport.setup()
            card = AgentCard(name="vulncouncil/agents/evidence_skeptic", description="Evidence council", url="slim://127.0.0.1:46357/vulncouncil/agents/evidence_skeptic", version="1.0.0", defaultInputModes=["text"], defaultOutputModes=["text"], capabilities=AgentCapabilities(), skills=[], preferredTransport=InterfaceTransport.SLIM_PATTERNS)
            self.client = await factory.a2a(ClientConfig(slim_transport=self.transport)).create(card)
        except BaseException:
            await self.close()
            raise

    async def exchange(self, phase, context, agent_ids):
        from a2a.types import SendMessageRequest, MessageSendParams, Message, TextPart, Part
        request = SendMessageRequest(id=str(uuid4()), params=MessageSendParams(message=Message(messageId=str(uuid4()), role="user", parts=[Part(root=TextPart(text=json.dumps({"phase": phase, "context": context})))])))
        packets = {}
        # SDK 0.5.5 uses a process-global SLIM app; workers must stay separate.
        async with self.lock:
            stream = self.client.start_streaming_groupchat(init_message=request, group_channel=f"vulncouncil/council/{uuid4().hex}",
                        participants=[f"vulncouncil/agents/{i}" for i in agent_ids], end_message="__UNUSED_END_MARKER__", timeout=65 if os.getenv("AGENT_REASONING", "rules") == "llm" else 20)
            try:
                async for response in stream:
                    content = response.root.model_dump(mode="json")
                    if "error" in content:
                        raise RuntimeError("A2A group conversation returned an error")
                    text = content["result"]["parts"][0]["text"]
                    data = json.loads(text)
                    if data.get("kind") != "agent_packet":
                        continue
                    packet = AgentPacket.model_validate(data["packet"])
                    if packet.agent_id not in agent_ids:
                        raise RuntimeError("Unexpected participant in SLIM group")
                    packets[packet.agent_id] = packet
                    if len(packets) == len(agent_ids):
                        # Allow peers to consume the last broadcast before closing the session.
                        await asyncio.sleep(.1)
                        break
            finally:
                await stream.aclose()
        if len(packets) != len(agent_ids):
            raise RuntimeError("SLIM did not deliver a response from every selected participant")
        return list(packets.values())

    async def close(self):
        for process in self.processes:
            if process.returncode is None:
                process.terminate()
        for process in self.processes:
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    process.kill()
                    await process.wait()
        for handle in self.handles:
            handle.close()
        if self.transport:
            await self.transport.close()
