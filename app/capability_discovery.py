from pathlib import Path
import yaml
from schemas.models import AgentCapability

ROOT = Path(__file__).resolve().parents[1]


class CapabilityDiscovery:
    """Explicit local OASF-shaped registry; not a live AGNTCY Directory."""
    mode = "local OASF-shaped registry"

    def __init__(self, path: Path = ROOT / "config/agents.yaml"):
        self.agents = [AgentCapability.model_validate(item) for item in yaml.safe_load(path.read_text())["agents"]]

    def select(self, skills: set[str]) -> list[AgentCapability]:
        return [agent for agent in self.agents if skills.intersection(agent.skills)]

    def get(self, agent_id: str) -> AgentCapability:
        return next(agent for agent in self.agents if agent.agent_id == agent_id)

    def manifests(self) -> list[dict]:
        return [{"name": a.name, "version": a.version, "schema_version": a.schema_version,
                 "description": a.description, "skills": [{"name": s} for s in a.skills],
                 "modules": [{"name": "vulncouncil/synthetic-tools", "data": {"agent_id": a.agent_id, "allowed_checks": a.allowed_checks, "objective": a.objective}}]} for a in self.agents]

