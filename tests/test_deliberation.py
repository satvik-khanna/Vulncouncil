from schemas.models import Evidence, Vote, VoteChoice, Status
from app.deliberation import resolve


def ev(agent="a", result="positive", **kwargs):
    return Evidence(run_id="r", agent_id=agent, finding_id="f", tool_name="cross_user_access", test_description="synthetic", result=result, status_code=200, snippet="{}", response_hash="h", reproducible=True, **kwargs)


def votes(evidence):
    return [Vote(agent_id=agent, finding_id="f", vote=VoteChoice.CONFIRM, confidence=.9, evidence_ids=[e.evidence_id for e in evidence], reason="support") for agent in ("a", "b", "c")]


def test_majority_without_evidence_cannot_confirm():
    assert resolve([], votes([]))[0] == Status.DISPUTED


def test_independent_observations_required():
    one = ev()
    assert resolve([one], votes([one]))[0] == Status.LIKELY
    duplicate = one.model_copy()
    assert resolve([one, duplicate], votes([one]))[0] == Status.LIKELY
    independent = ev("b")
    assert resolve([one, independent], votes([one, independent]))[0] == Status.CONFIRMED


def test_claims_not_direct_observations():
    evidence = [ev("a", observable=False), ev("b", observable=False)]
    assert resolve(evidence, votes(evidence))[0] != Status.CONFIRMED


def test_conflicting_evidence_preserves_dissent():
    evidence = [ev(), ev("b", "negative", reproduction_failed=True)]
    assert resolve(evidence, votes(evidence))[0] == Status.DISPUTED


def test_failed_reproduction_and_benign_control():
    assert resolve([ev("b", "negative", reproduction_failed=True)], [])[0] == Status.NOT_REPRODUCED
    assert resolve([ev("b", "signal", decisive_counterexample=True)], [])[0] == Status.NOT_REPRODUCED


def test_safety_overrides_every_vote():
    evidence = [ev(), ev("b")]
    assert resolve(evidence, votes(evidence), safety_blocked=True)[0] == Status.NEEDS_HUMAN


def test_incomplete_abstains():
    assert resolve([ev("b", "incomplete")], [])[0] == Status.NEEDS_HUMAN


def test_latest_vote_replaces_earlier_position():
    evidence = [ev(), ev("b")]
    initial = votes(evidence)
    updated = [v.model_copy(update={"round": 2, "vote": VoteChoice.REJECT}) for v in initial]
    assert resolve(evidence, initial + updated)[0] != Status.CONFIRMED

