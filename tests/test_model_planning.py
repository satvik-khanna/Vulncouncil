import json
import httpx
import pytest
from agents.factory import create_agent
from agents.reasoning import run_specialist
from app.capability_discovery import CapabilityDiscovery
from schemas.models import AssessmentRequest, VoteChoice


def provider(monkeypatch, handler):
    for k, v in {"AGENT_REASONING":"llm", "LLM_API_KEY":"test-key", "LLM_MODEL":"test-model", "LLM_BASE_URL":"http://model-fixture/v1"}.items():
        monkeypatch.setenv(k, v)
    original = httpx.AsyncClient
    monkeypatch.setattr("agents.reasoning.httpx.AsyncClient", lambda **kw: original(transport=httpx.MockTransport(handler), **kw))


async def test_model_selects_checks_and_owns_discovery_position(service, monkeypatch):
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    ctx = service.context(run, "broken_access_control", run.findings[0].finding_id)
    ctx["evidence"], ctx["positions"], ctx["peer_claims"] = [], [], []
    agent = create_agent(CapabilityDiscovery().get("access_control_agent"))
    evidence = next(e for e in run.evidence if e.agent_id == agent.agent_id)
    captured = []
    def handler(request):
        prompt = json.loads(json.loads(request.content)["messages"][1]["content"])
        captured.append(prompt)
        reply = {"checks":["cross_user_access"], "requested_skills":[], "evidence_ids":[], "reason":"Test record visibility, not scanner confidence."} if "allowed_checks" in prompt else {"vote":"DISPUTED", "confidence":.61, "evidence_ids":[evidence.evidence_id], "reason":"Visibility is concerning, but independent authorization evidence is absent."}
        return httpx.Response(200, json={"choices":[{"message":{"content":json.dumps(reply)}}], "usage":{"total_tokens":50}})
    provider(monkeypatch, handler)
    checks = []
    async def check(name, finding_id):
        checks.append(name)
        return evidence
    packet = await run_specialist(agent, "discover", ctx, check)
    assert checks == ["cross_user_access"]
    assert packet.votes[0].vote == VoteChoice.DISPUTED  # policy discovery would confirm
    assert packet.findings[0].confidence == .61
    assert packet.model_calls == 2 and packet.model_tokens == 100
    assert packet.events[0].event_type.value == "PLAN_UPDATED"
    assert all(not {"scenario", "patched", "variant", "expected", "policy_position"} & p.keys() for p in captured)
    assert captured[1]["evidence"][0]["evidence_id"] == evidence.evidence_id


@pytest.mark.parametrize("reply", [
    {"checks":["external_url"], "requested_skills":[], "evidence_ids":[], "reason":"Inspect elsewhere"},
    {"checks":[], "requested_skills":["shell"], "evidence_ids":[], "reason":"Need a shell"},
    {"checks":[], "requested_skills":[], "evidence_ids":["fabricated"], "reason":"Invented observation"},
])
async def test_invalid_model_plan_fails_before_tool_execution(monkeypatch, reply):
    provider(monkeypatch, lambda req: httpx.Response(200, json={"choices":[{"message":{"content":json.dumps(reply)}}]}))
    agent = create_agent(CapabilityDiscovery().get("access_control_agent"))
    called = []
    async def check(*args):
        called.append(args)
    with pytest.raises(ValueError):
        await run_specialist(agent, "challenge", {"run_id":"r", "finding_id":"f", "category":"broken_access_control", "available_skills":["verification"], "evidence":[]}, check)
    assert not called


async def test_distinct_objectives_can_preserve_model_disagreement(service, monkeypatch):
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    ctx = service.context(run, "broken_access_control", run.findings[0].finding_id, 2)
    def handler(request):
        prompt = json.loads(json.loads(request.content)["messages"][1]["content"])
        skeptical = "false positives" in prompt["objective"]
        reply = {"vote":"DISPUTED" if skeptical else "CONFIRM", "confidence":.49 if skeptical else .91, "evidence_ids":[prompt["evidence"][0]["evidence_id"]], "reason":"Require another authorization context." if skeptical else "A cross-user record is directly observed."}
        return httpx.Response(200,json={"choices":[{"message":{"content":json.dumps(reply)}}]})
    provider(monkeypatch, handler)
    async def no_check(*args):
        raise AssertionError("Voting must not execute tools")
    advocate = await run_specialist(create_agent(service.registry.get("access_control_agent")), "vote", ctx, no_check)
    skeptic = await run_specialist(create_agent(service.registry.get("evidence_skeptic")), "vote", ctx, no_check)
    assert advocate.votes[0].vote == VoteChoice.CONFIRM
    assert skeptic.votes[0].vote == VoteChoice.DISPUTED


async def test_model_position_reused_only_for_identical_observed_record(service, monkeypatch):
    run = await service.open(AssessmentRequest(scenario="access_control"), background=False)
    ctx = service.context(run, "broken_access_control", run.findings[0].finding_id, 2)
    agent = create_agent(service.registry.get("access_control_agent"))
    evidence = agent.evidence_for(ctx)
    own_review = next(p for p in ctx["positions"] if p["agent_id"] == agent.agent_id and p["event_type"] == "BELIEF_UPDATED")
    own_review["vote"] = "DISPUTED"
    own_review["data"] = {"observed_evidence_ids": [e.evidence_id for e in evidence], "reasoning": "configured model", "environment_version": 0}
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"choices":[{"message":{"content":json.dumps({"vote":"CONFIRM", "confidence":.9, "evidence_ids":[evidence[0].evidence_id], "reason":"Fresh evidence supports visibility."})}}]})
    provider(monkeypatch, handler)
    async def no_check(*args):
        raise AssertionError("Voting cannot execute tools")
    retained = await run_specialist(agent, "vote", ctx, no_check)
    assert not calls and retained.model_calls == 0
    assert retained.votes[0].vote == VoteChoice.DISPUTED
    ctx["evidence"] = ctx["evidence"][:-1]
    fresh = await run_specialist(agent, "vote", ctx, no_check)
    assert len(calls) == 1 and fresh.model_calls == 1


async def test_historical_observation_cannot_alone_ground_current_model_position(service, monkeypatch):
    run = await service.open(AssessmentRequest(scenario="changing_access"), background=False)
    ctx = service.context(run, "broken_access_control", run.findings[0].finding_id, 2)
    old = next(e for e in run.evidence if e.facts["environment_version"] == 0)
    prompts = []
    def handler(request):
        prompt = json.loads(json.loads(request.content)["messages"][1]["content"])
        prompts.append(prompt)
        return httpx.Response(200, json={"choices":[{"message":{"content":json.dumps({"vote":"CONFIRM", "probability_issue_true":.95, "evidence_ids":[old.evidence_id], "reason":"The old read proves current access."})}}]})
    provider(monkeypatch, handler)
    async def no_check(*args):
        raise AssertionError("Voting cannot execute tools")
    with pytest.raises(ValueError, match="outside"):
        await run_specialist(create_agent(service.registry.get("access_control_agent")), "vote", ctx, no_check)
    assert prompts[0]["historical_evidence"][0]["evidence_id"] == old.evidence_id
    assert all(e["facts"]["environment_version"] == 1 for e in prompts[0]["evidence"])
