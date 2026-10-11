import asyncio
import pytest
from schemas.models import AssessmentRequest, Status


async def test_surprise_recruits_guard_expert_and_retains_history(service):
    run = await service.open(AssessmentRequest(scenario="changing_access"), background=False)
    assert run.state == "completed", run.error
    assert run.environment_version == 1
    assert run.findings[0].status == Status.DISPUTED
    assert len(run.selected_agents) == 4
    assert "hardening_agent" in run.selected_agents and "recon_agent" not in run.selected_agents
    direct = [e for e in run.evidence if e.result in {"positive", "negative"}]
    assert any(e.result == "positive" and e.facts["environment_version"] == 0 for e in direct)
    assert any(e.result == "negative" and e.facts["environment_version"] == 1 for e in direct)
    assert any(e.tool_name == "guard_config" and e.facts["guard_enabled"] for e in run.evidence)
    events = service.storage.events(run.run_id)
    kinds = [e["event_type"] for e in events]
    assert kinds.index("FINDING_PROPOSED") < kinds.index("ENVIRONMENT_CHANGED") < kinds.index("COLLABORATOR_REQUESTED") < kinds.index("FINDING_RESOLVED")
    assert {v.vote.value for v in run.findings[0].votes} >= {"REJECT", "DISPUTED"}


async def test_manual_intervention_during_assessment(service):
    service.delay = .02
    run = await service.open(AssessmentRequest(scenario="access_control"))
    for _ in range(100):
        if any(e.result == "positive" for e in run.evidence):
            break
        await asyncio.sleep(.005)
    assert any(e.result == "positive" for e in run.evidence)
    await service.intervene(run.run_id, "enable_guard")
    await service.tasks[run.run_id]
    assert run.findings[0].status == Status.DISPUTED
    with pytest.raises(ValueError, match="before final voting"):
        await service.intervene(run.run_id, "disable_guard")


async def test_independent_majority_has_no_peer_observations(service):
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False, decision_mode="simple_majority", fixture_variant="replica_incomplete")
    assert run.metrics.peer_receipts == 0
    for agent_id in run.selected_agents:
        assert run.run_id not in service.transport.agents[agent_id].mailboxes
    risk = next(v for v in run.findings[0].votes if v.agent_id == "risk_remediation_agent")
    skeptic = next(v for v in run.findings[0].votes if v.agent_id == "evidence_skeptic")
    assert not risk.evidence_ids
    own_ids = {e.evidence_id for e in run.evidence if e.agent_id == "evidence_skeptic"}
    assert set(skeptic.evidence_ids) <= own_ids


async def test_selection_varies_with_required_capability(service):
    injection = await service.open(AssessmentRequest(scenario="ambiguous_injection"), background=False)
    access = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    assert "injection_agent" in injection.selected_agents and "access_control_agent" not in injection.selected_agents
    assert "access_control_agent" in access.selected_agents and "injection_agent" not in access.selected_agents


async def test_late_environment_change_cannot_confirm_stale_evidence(service):
    original = service.exchange
    async def exchange(run, phase, context):
        packets = await original(run, phase, context)
        if phase == "review":
            await service.intervene(run.run_id, "enable_guard")
        return packets
    service.exchange = exchange
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    assert run.state == "completed"
    assert run.findings[0].status == Status.NEEDS_HUMAN
    assert run.findings[0].rule.startswith("STALE_EVIDENCE")


async def test_unrelated_positive_check_cannot_count_for_authorization(service):
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    gateway = service.gateways[run.run_id]
    evidence = await gateway.check("hardening_agent", "headers", run.findings[0].finding_id)
    assert evidence.result == "positive"
    assert evidence.finding_id is None


async def test_missing_required_capability_rejected_without_dangling_run(service):
    service.registry.agents = [a for a in service.registry.agents if a.agent_id != "evidence_skeptic"]
    with pytest.raises(ValueError, match="verification"):
        await service.open(AssessmentRequest(), background=False)
    assert not service.runs


async def test_rule_benchmark_attribution_does_not_inherit_server_model_mode(service, monkeypatch):
    monkeypatch.setenv("AGENT_REASONING", "llm")
    monkeypatch.setenv("LLM_MODEL", "a-model-that-must-not-be-called")
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    assert run.state == "completed"
    assert run.reasoning == "rules" and run.reasoning_model is None
    assert run.metrics.model_calls == 0
