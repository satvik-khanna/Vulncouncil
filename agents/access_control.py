from agents.base import Specialist
from schemas.models import AgentPacket, EventType, Finding, VoteChoice


class AccessControlAgent(Specialist):
    async def step(self, phase, context, check):
        if context["category"] != "broken_access_control":
            return await super().step(phase, context, check)
        if phase == "discover":
            e = await check("cross_user_access", context["finding_id"])
            initial = context.get("prior_confidence") or (0.94 if e.result == "positive" else 0.6)
            finding = Finding(finding_id=context["finding_id"], run_id=context["run_id"], title="Cross-user profile access", category="broken_access_control", route="/checks · cross_user_access", confidence=initial, initial_confidence=initial, evidence_ids=[e.evidence_id], remediation="Enforce object-level authorization against the authenticated identity on every profile read.")
            positive_reason = "Alice from Northstar can read Harbor's invoice; owner and same-tenant colleague controls both succeed." if context.get("authorization_policy") else "Synthetic Alice can view Bob's record."
            vote = self.cast(context, VoteChoice.CONFIRM if e.result == "positive" else VoteChoice.DISPUTED, initial, [e], positive_reason if e.result == "positive" else "Prior authorization hypothesis is being reassessed against the current fixture.")
            return AgentPacket(agent_id=self.agent_id, evidence=[e], findings=[finding], votes=vote.votes,
                               events=[self.event(context, EventType.FINDING_PROPOSED, "Cross-user fixture access is observable." if e.result == "positive" else "Reassessing the authorization claim; current evidence requires checking the prior belief.", [e], confidence_after=initial), *vote.events])
        if phase == "review":
            own = await check("access_reproduce", context["finding_id"])
            evidence = self.evidence_for(context) + [own]
            after = .4 if any(e.result == "positive" for e in evidence) and any(e.result == "negative" for e in evidence) else 0.97 if evidence and all(e.result == "positive" for e in evidence) else 0.05 if any(e.result == "negative" for e in evidence) else 0.4
            before = context.get("initial_confidence", 0.6)
            reason = "Independent observation reproduces cross-user access." if after > .9 else "The authorization guard denies the same named check; I revise the prior access claim." if after < .1 else "Visibility observations conflict or are incomplete; preserve the historical evidence and withhold confirmation."
            return AgentPacket(agent_id=self.agent_id, evidence=[own], events=[self.revision(context, evidence, before, after, reason)])
        if phase == "vote":
            evidence = self.evidence_for(context)
            positive = [e for e in evidence if e.result == "positive"]
            negative = [e for e in evidence if e.result == "negative"]
            choice = VoteChoice.DISPUTED if positive and negative else VoteChoice.CONFIRM if positive else VoteChoice.REJECT if negative else VoteChoice.ABSTAIN
            return self.cast(context, choice, .97 if positive and not negative else .05 if negative and not positive else .4, evidence, "Vote follows observed record visibility, not the earlier hypothesis.")
        return await super().step(phase, context, check)

