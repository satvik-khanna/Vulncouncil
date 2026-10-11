"""Pure resolution. A facilitator cannot override these evidence rules."""
from pathlib import Path
import yaml
from schemas.models import Evidence, Status, Vote, VoteChoice

POLICY = yaml.safe_load((Path(__file__).resolve().parents[1] / "config/deliberation.yaml").read_text())


def resolve(evidence: list[Evidence], votes: list[Vote], safety_blocked: bool = False, policy: dict | None = None) -> tuple[Status, str]:
    p = policy or POLICY
    if safety_blocked or any(e.result == "blocked" for e in evidence):
        return Status.NEEDS_HUMAN, "SAFETY_STOP: safety boundaries take precedence over all votes"
    latest = {v.agent_id: v for v in sorted(votes, key=lambda v: v.round)}
    evidence_by_id = {e.evidence_id: e for e in evidence}
    supporters = {v.agent_id for v in latest.values() if v.vote == VoteChoice.CONFIRM and v.confidence >= p["credible_confidence"] and any(i in evidence_by_id for i in v.evidence_ids)}
    # A copied observation retains its evidence ID, and cannot count twice.
    unique_evidence = {e.evidence_id: e for e in evidence}
    positives = [e for e in unique_evidence.values() if e.observable and e.result == "positive"]
    independent = {e.agent_id for e in positives if e.reproducible}
    counter = [e for e in evidence if e.decisive_counterexample]
    failures = [e for e in evidence if e.reproduction_failed and e.observable]
    if positives and (counter or failures):
        return Status.DISPUTED, "CONFLICTING_DIRECT_EVIDENCE: support and counterevidence remain unresolved"
    if failures and not positives:
        return Status.NOT_REPRODUCED, "FAILED_REPRODUCTION: approved check failed; original signal is insufficient"
    if counter and not positives:
        return Status.NOT_REPRODUCED, "BENIGN_CONTROL: matched benign signal defeats the proposed causal claim"
    if len(supporters) >= p["min_supporters"] and len(independent) >= p["min_independent_observers"]:
        return Status.CONFIRMED, "INDEPENDENT_REPRODUCTION: two supporting agents and independent direct observations; no decisive counterexample"
    if len(supporters) >= p["min_supporters"] and positives:
        return Status.LIKELY, "MISSING_INDEPENDENT_REPRODUCTION: supported claim has insufficient independent observations"
    if any(e.result == "incomplete" for e in evidence):
        return Status.NEEDS_HUMAN, "INCOMPLETE_EVIDENCE: required fixture facts are unavailable"
    return Status.DISPUTED, "INSUFFICIENT_EVIDENCE: preserve uncertainty after bounded deliberation"


def majority(votes: list[Vote]) -> Status:
    latest = {v.agent_id: v for v in sorted(votes, key=lambda v: v.round)}
    confirm = sum(v.vote == VoteChoice.CONFIRM for v in latest.values())
    reject = sum(v.vote == VoteChoice.REJECT for v in latest.values())
    if confirm > reject:
        return Status.CONFIRMED
    if reject > confirm:
        return Status.NOT_REPRODUCED
    return Status.DISPUTED

