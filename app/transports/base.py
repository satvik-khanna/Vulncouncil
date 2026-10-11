from abc import ABC, abstractmethod
from schemas.models import AgentPacket


class CouncilTransport(ABC):
    mode: str

    @abstractmethod
    async def exchange(self, phase: str, context: dict, agent_ids: list[str]) -> list[AgentPacket]: ...

    async def close(self):
        pass

