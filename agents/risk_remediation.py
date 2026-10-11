from agents.base import Specialist
from schemas.models import AgentPacket, EventType, VoteChoice


class RiskRemediationAgent(Specialist):
    async def step(self, phase, context, check):
        evidence = self.evidence_for(context)
        if phase == "discover":
            return self.cast(context, VoteChoice.ABSTAIN, .4, evidence, "Premature confirmation creates remediation cost; wait for observable impact.")
        if phase == "challenge":
            return AgentPacket(agent_id=self.agent_id, events=[self.event(context, EventType.CHALLENGE, "What direct observation demonstrates impact? Synthetic data limits severity; a parser error alone does not justify urgent remediation.", evidence)])
        if phase in {"review", "vote"}:
            direct = {e.agent_id for e in evidence if e.result == "positive" and e.reproducible}
            neg = any(e.reproduction_failed or e.decisive_counterexample for e in evidence)
            after = .9 if len(direct) >= 2 and not neg else .1 if neg else .4
            if phase == "review":
                return AgentPacket(agent_id=self.agent_id, events=[self.revision(context, evidence, .4, after, "Independent direct evidence justifies a bounded fix." if after > .8 else "Avoid an unsupported escalation; current evidence cannot justify the original impact claim.")])
            return self.cast(context, VoteChoice.CONFIRM if after > .8 else VoteChoice.REJECT if after < .2 else VoteChoice.ABSTAIN, after, evidence, "Fix observable authorization/configuration gaps; preserve uncertainty for incomplete facts. Synthetic records cap the demonstrated impact.")
        return await super().step(phase, context, check)

