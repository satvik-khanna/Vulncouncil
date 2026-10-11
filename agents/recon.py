from agents.base import Specialist
from schemas.models import AgentPacket, EventType


class ReconAgent(Specialist):
    async def step(self, phase, context, check):
        if phase == "discover":
            evidence = await check("inventory", None)
            return AgentPacket(agent_id=self.agent_id, evidence=[evidence], events=[self.event(context, EventType.TOOL_RESULT, "Inventory contains only the declared synthetic fixture surface. Scope remains fixed.", [evidence])])
        return await super().step(phase, context, check)

