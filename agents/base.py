from collections.abc import Awaitable, Callable
from schemas.models import AgentCapability, AgentMessage, AgentPacket, Evidence, EventType, Finding, Vote, VoteChoice

Check = Callable[[str, str | None], Awaitable[Evidence]]


class Specialist:
    def __init__(self, capability: AgentCapability):
        self.capability = capability
        self.agent_id = capability.agent_id
        self.mailboxes: dict[str, dict[str, AgentPacket]] = {}
        self.peer_receipts = 0
        self.receipts_by_run: dict[str, int] = {}

    def observe(self, run_id: str, packet: AgentPacket):
        if packet.agent_id != self.agent_id:
            self.mailboxes.setdefault(run_id, {})[packet.agent_id] = packet
            self.peer_receipts += 1
            self.receipts_by_run[run_id] = self.receipts_by_run.get(run_id, 0) + 1
        # Keep bounded worker state across repeatable assessments.
        if len(self.mailboxes) > 32:
            oldest = next(iter(self.mailboxes))
            self.mailboxes.pop(oldest)
            self.receipts_by_run.pop(oldest, None)

    def event(self, context: dict, kind: EventType, claim: str, evidence=(), **kwargs) -> AgentMessage:
        return AgentMessage(run_id=context["run_id"], agent_id=self.agent_id, finding_id=context.get("finding_id"),
                            event_type=kind, round=context.get("round", 0), claim=claim,
                            evidence_ids=[e.evidence_id for e in evidence], **kwargs)

    def evidence_for(self, context: dict) -> list[Evidence]:
        collected = {e["evidence_id"]: Evidence.model_validate(e) for e in context.get("evidence", [])}
        for packet in self.mailboxes.get(context["run_id"], {}).values():
            for item in packet.evidence:
                collected[item.evidence_id] = item
        return [e for e in collected.values() if e.finding_id == context.get("finding_id")]

    def cast(self, context: dict, vote: VoteChoice, confidence: float, evidence: list[Evidence], reason: str) -> AgentPacket:
        item = Vote(agent_id=self.agent_id, finding_id=context["finding_id"], vote=vote, confidence=confidence,
                    evidence_ids=[e.evidence_id for e in evidence], reason=reason, round=context.get("round", 1))
        msg = self.event(context, EventType.VOTE_CAST, reason, evidence, vote=vote, confidence_after=confidence)
        return AgentPacket(agent_id=self.agent_id, events=[msg], votes=[item])

    async def step(self, phase: str, context: dict, check: Check) -> AgentPacket:
        if phase == "vote":
            return self.cast(context, VoteChoice.ABSTAIN, 0.3, self.evidence_for(context), "Outside my specialist's test family; defer to direct observations.")
        return AgentPacket(agent_id=self.agent_id)

    def revision(self, context: dict, evidence: list[Evidence], before: float, after: float, reason: str) -> AgentMessage:
        return self.event(context, EventType.BELIEF_UPDATED, reason, evidence, confidence_before=before, confidence_after=after)

