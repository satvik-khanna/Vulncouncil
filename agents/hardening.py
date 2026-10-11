from agents.base import Specialist
from schemas.models import AgentPacket, EventType, Finding, VoteChoice


class HardeningAgent(Specialist):
    async def step(self, phase, context, check):
        if phase == "orient":
            e = await check("guard_config", context["finding_id"])
            return AgentPacket(agent_id=self.agent_id, evidence=[e], events=[self.event(context, EventType.TOOL_RESULT, "Guard configuration independently observed; earlier visibility remains part of the finding history.", [e])])
        if phase == "discover":
            relevant = context["category"] == "misconfiguration"
            e = await check("headers", context["finding_id"] if relevant else None)
            if not relevant:
                return AgentPacket(agent_id=self.agent_id, evidence=[e], events=[self.event(context, EventType.TOOL_RESULT, "Configuration context checked; a missing header does not establish this finding's exploitability.", [e])])
            confidence = .88 if e.result == "positive" else .4
            f = Finding(finding_id=context["finding_id"], run_id=context["run_id"], title="Synthetic policy header absent", category="misconfiguration", route="/checks · headers", confidence=confidence, initial_confidence=confidence, impact_band="low", evidence_ids=[e.evidence_id], remediation="Set a Content-Security-Policy appropriate to the application's actual content.")
            v = self.cast(context, VoteChoice.CONFIRM if e.result == "positive" else VoteChoice.DISPUTED, confidence, [e], "Header presence is directly observable; impact remains limited to fixture configuration.")
            return AgentPacket(agent_id=self.agent_id, evidence=[e], findings=[f], votes=v.votes, events=[self.event(context, EventType.FINDING_PROPOSED, "The declared security header is absent." if e.result == "positive" else "Reassessing policy header presence after the patch.", [e], confidence_after=confidence), *v.events])
        if context["category"] == "broken_access_control" and phase == "vote":
            guards = [e for e in self.evidence_for(context) if e.tool_name == "guard_config"]
            if guards:
                return self.cast(context, VoteChoice.ABSTAIN, .3, guards, "I independently verified the current guard configuration. Configuration alone cannot erase earlier observed access, so I defer the access verdict to direct record checks.")
        if context["category"] == "misconfiguration" and phase in {"review", "vote"}:
            own = [await check("headers_reproduce", context["finding_id"])] if phase == "review" else []
            evidence = self.evidence_for(context) + own
            negative = any(e.result == "negative" for e in evidence)
            positive = any(e.result == "positive" for e in evidence)
            if phase == "review":
                return AgentPacket(agent_id=self.agent_id, evidence=own, events=[self.revision(context, evidence, context.get("initial_confidence", .88), .4 if positive and negative else .95 if positive else .05, "Independent header observations determine my updated configuration confidence.")])
            return self.cast(context, VoteChoice.DISPUTED if positive and negative else VoteChoice.CONFIRM if positive else VoteChoice.REJECT, .4 if positive and negative else .95 if positive else .05, evidence, "Bounded header finding; no claim of a broader compromise.")
        return await super().step(phase, context, check)

