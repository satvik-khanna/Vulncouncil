import asyncio
from agents.factory import create_agent
from agents.reasoning import run_specialist
from app.transports.base import CouncilTransport


class MemoryTestTransport(CouncilTransport):
    mode = "memory"

    def __init__(self, registry, gateway_lookup, allow_model=True):
        self.agents = {cap.agent_id: create_agent(cap) for cap in registry.agents}
        self.gateway_lookup = gateway_lookup
        self.allow_model = allow_model

    async def exchange(self, phase, context, agent_ids):
        async def invoke(agent_id):
            gateway = self.gateway_lookup(context["run_id"])
            async def check(name, finding_id):
                return await gateway.check(agent_id, name, finding_id)
            agent = self.agents[agent_id]
            from app.telemetry import tracer
            with tracer.start_as_current_span("agent.step", attributes={"agent.id": agent_id, "run.id": context["run_id"], "phase": phase}):
                local = context
                if context.get("independent"):
                    local = {**context, "evidence": [e for e in context["evidence"] if e["agent_id"] == agent_id],
                             "positions": [p for p in context.get("positions", []) if p["agent_id"] == agent_id], "peer_claims": []}
                packet = await run_specialist(agent, phase, local, check, self.allow_model)
            return packet
        tasks = [asyncio.create_task(invoke(agent_id)) for agent_id in agent_ids]
        try:
            packets = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        # Deliver actual agent packets to every other participant, never a canned transcript.
        for agent_id in ([] if context.get("independent") else agent_ids):
            for packet in packets:
                self.agents[agent_id].observe(context["run_id"], packet)
        for packet in packets:
            packet.peer_receipts = self.agents[packet.agent_id].receipts_by_run.get(context["run_id"], 0)
        return packets

