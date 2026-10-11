import asyncio
import pytest
from app.evaluation import evaluate
from schemas.models import AssessmentRequest, Status


@pytest.mark.parametrize("scenario,patched,status", [
    ("ambiguous_injection", False, Status.NOT_REPRODUCED),
    ("access_control", False, Status.CONFIRMED),
    ("patched_access", True, Status.NOT_REPRODUCED),
    ("access_control", True, Status.NOT_REPRODUCED),
    ("hardening", False, Status.CONFIRMED),
    ("hardening", True, Status.NOT_REPRODUCED),
    ("incomplete_access", False, Status.NEEDS_HUMAN),
    ("scope_violation", False, Status.NEEDS_HUMAN),
])
async def test_end_to_end(service, scenario, patched, status):
    run = await service.open(AssessmentRequest(scenario=scenario, patched=patched), background=False)
    assert run.state in {"completed", "stopped"}, run.error
    assert run.findings[0].status == status
    assert len(run.selected_agents) == 3
    assert service.storage.get(run.run_id).findings[0].status == status
    assert run.metrics.tool_requests <= 48
    if scenario != "scope_violation":
        events = service.storage.events(run.run_id)
        for kind in ("FINDING_PROPOSED", "CHALLENGE", "COUNTEREVIDENCE", "BELIEF_UPDATED", "VOTE_CAST", "FINDING_RESOLVED"):
            assert any(e["event_type"] == kind for e in events)
        assert run.metrics.belief_revisions > 0
        refs = {e.evidence_id for e in run.evidence}
        assert all(set(e["evidence_ids"]) <= refs for e in events)
    else:
        assert run.metrics.blocked_requests == 1
        assert any(e["event_type"] == "SAFETY_BLOCKED" for e in service.storage.events(run.run_id))


async def test_patch_revises_prior_live_belief(service):
    before = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    after = await service.open(AssessmentRequest(scenario="patched_access"), background=False)
    assert before.findings[0].status == Status.CONFIRMED
    assert after.findings[0].status == Status.NOT_REPRODUCED
    updates = [e for e in service.storage.events(after.run_id) if e["event_type"] == "BELIEF_UPDATED" and e["agent_id"] == "access_control_agent"]
    assert updates[0]["confidence_before"] == before.findings[0].confidence
    assert updates[0]["confidence_after"] < .1 and updates[0]["evidence_ids"]


async def test_evaluation_is_measured(service):
    results = await evaluate(service)
    assert len(results["cases"]) == 13
    assert set(results["split_scores"]) == {"development", "holdout"}
    assert len(results["dataset_sha256"]) == 64
    assert all(len(set(c["run_ids"].values())) == 3 for c in results["cases"])
    assert all(c["mode_metrics"]["single_agent"]["peer_receipts"] == 0 for c in results["cases"])
    assert all(c["mode_metrics"]["simple_majority"]["peer_receipts"] == 0 for c in results["cases"])
    assert all(case["council"] == case["expected"] for case in results["cases"])
    assert results["scores"]["council"]["false_positives"] == 0
    assert results["scores"]["single_agent"]["tool_requests"] > 0
    assert results["scores"]["council"]["tool_requests"] > results["scores"]["single_agent"]["tool_requests"]
    assert results["blocked_requests"] == 1


async def test_global_stop_and_concurrent_start(service):
    service.delay = .03
    run = await service.open(AssessmentRequest(scenario="access_control"))
    await asyncio.sleep(.06)
    with pytest.raises(ValueError, match="already active"):
        await service.open(AssessmentRequest())
    await service.stop(run.run_id)
    assert run.state == "stopped"
    assert service.gateways[run.run_id].gate.stopped
    assert run.findings[0].status == Status.NEEDS_HUMAN


async def test_peer_packets_are_delivered(service):
    run = await service.open(AssessmentRequest(), background=False)
    for agent_id in run.selected_agents:
        agent = service.transport.agents[agent_id]
        assert agent.peer_receipts > 0
        assert len(agent.mailboxes[run.run_id]) == 2
    assert service.transport.agents["recon_agent"].peer_receipts == 0


async def test_immediate_stop_before_execution(service):
    run = await service.open(AssessmentRequest())
    await service.stop(run.run_id)
    assert run.state == "stopped"
    assert run.metrics.tool_requests == 0


async def test_terminal_state_has_durable_completion_event(service):
    run = await service.open(AssessmentRequest(), background=False)
    assert run.state == "completed"
    assert service.storage.events(run.run_id)[-1]["event_type"] == "ASSESSMENT_COMPLETED"

