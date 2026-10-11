from agents.base import Specialist
from schemas.models import AgentPacket, EventType, VoteChoice


class EvidenceSkeptic(Specialist):
    async def step(self, phase, context, check):
        if phase == "discover":
            return self.cast(context, VoteChoice.DISPUTED, .6, [], "A specialist's claim needs an independent reproduction before I support it.")
        if phase == "challenge":
            category = context["category"]
            challenge = self.event(context, EventType.CHALLENGE, "If a benign malformed-input control yields the same signal, the signal does not establish causation. Repeat the named causal check." if category == "injection" else "Repeat the same bounded check independently. A denied or incomplete response would defeat the proposed finding.", self.evidence_for(context))
            if category == "injection":
                control = await check("benign_control", context["finding_id"])
                signal = next((e.facts.get("signal") for e in self.evidence_for(context) if e.tool_name == "injection_signal"), None)
                control.decisive_counterexample = bool(signal and control.facts.get("signal") == signal)
                reproduction = await check("injection_reproduce", context["finding_id"])
                evidence = [control, reproduction]
            else:
                name = "access_reproduce" if category == "broken_access_control" else "headers_reproduce"
                evidence = [await check(name, context["finding_id"])]
            reason = "Matched benign control and failed causal reproduction weaken the original claim." if any(e.decisive_counterexample for e in evidence) else "My independent fixture check returned: " + ", ".join(e.result for e in evidence)
            return AgentPacket(agent_id=self.agent_id, evidence=evidence, events=[challenge, self.event(context, EventType.COUNTEREVIDENCE, reason, evidence)])
        if phase in {"review", "vote"}:
            evidence = self.evidence_for(context)
            pos = any(e.result == "positive" and e.agent_id == self.agent_id for e in evidence)
            neg = any(e.reproduction_failed or e.decisive_counterexample for e in evidence)
            confidence = .96 if pos and not neg else .05 if neg and not pos else .35
            if phase == "review":
                return AgentPacket(agent_id=self.agent_id, requested_skills=["guard_configuration"] if len({e.facts.get("environment_version", 0) for e in evidence}) > 1 and context["category"] == "broken_access_control" else [], events=[self.revision(context, evidence, .6, confidence, "My independent check changes my position: " + ("direct reproduction supports the claim." if pos else "counterevidence rejects the claim." if neg else "evidence is incomplete; abstain."))])
            return self.cast(context, VoteChoice.DISPUTED if pos and neg else VoteChoice.CONFIRM if pos else VoteChoice.REJECT if neg else VoteChoice.ABSTAIN, confidence, evidence, "Require reproducible, independently observed evidence; preserve unresolved conflict.")
        return await super().step(phase, context, check)

