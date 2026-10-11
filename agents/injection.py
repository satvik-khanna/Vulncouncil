from agents.base import Specialist
from schemas.models import AgentPacket, EventType, Finding, VoteChoice


class InjectionAgent(Specialist):
    async def step(self, phase, context, check):
        if context["category"] != "injection":
            return await super().step(phase, context, check)
        if phase == "discover":
            e = await check("injection_signal", context["finding_id"])
            confidence = 0.78 if e.facts.get("signal") else 0.15
            finding = Finding(finding_id=context["finding_id"], run_id=context["run_id"], title="Ambiguous parser signal", category="injection", route="/checks · injection_signal", confidence=confidence, initial_confidence=confidence, evidence_ids=[e.evidence_id], remediation="Use typed input validation and parameterized queries; verify causal behavior before escalating.")
            vote = self.cast(context, VoteChoice.CONFIRM if confidence > 0.55 else VoteChoice.REJECT, confidence, [e], "The observed signal warrants investigation; an independent control is still needed.")
            return AgentPacket(agent_id=self.agent_id, findings=[finding], evidence=[e], votes=vote.votes,
                               events=[self.event(context, EventType.FINDING_PROPOSED, "A parser-like error suggests a possible issue. I advocate testing it before dismissal.", [e], confidence_after=confidence), *vote.events])
        if phase == "review":
            own = [await check("benign_control", context["finding_id"]), await check("injection_reproduce", context["finding_id"])]
            all_e = self.evidence_for(context) + own
            signal = next((e.facts.get("signal") for e in all_e if e.tool_name == "injection_signal"), None)
            controls = [e for e in all_e if e.tool_name == "benign_control" and e.facts.get("signal") == signal]
            reproduced = [e for e in all_e if e.tool_name == "injection_reproduce"]
            after = 0.12 if any(e.reproduction_failed for e in reproduced) else .95 if any(e.result == "positive" for e in reproduced) and not controls else .55
            return AgentPacket(agent_id=self.agent_id, evidence=own, events=[self.revision(context, controls + reproduced, context.get("initial_confidence", .78), after, "The causal check fails; my initial error-based hypothesis loses support." if after < .2 else "The causal check is independently observable." if after > .9 else "Counterevidence is incomplete; preserve the hypothesis with lower confidence.")])
        if phase == "vote":
            evidence = self.evidence_for(context)
            failed = any(e.reproduction_failed for e in evidence)
            return self.cast(context, VoteChoice.REJECT if failed else VoteChoice.CONFIRM if any(e.result == "positive" for e in evidence) else VoteChoice.ABSTAIN, 0.12 if failed else .95 if any(e.result == "positive" for e in evidence) else .55, evidence, "Failed reproduction and matched control do not support a causal injection claim." if failed else "A signal remains unverified.")
        return await super().step(phase, context, check)

