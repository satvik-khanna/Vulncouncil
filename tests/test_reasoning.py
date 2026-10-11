import json
import httpx
import pytest
from agents.reasoning import reason
from app.capability_discovery import CapabilityDiscovery
from schemas.models import AgentPacket, AgentMessage, EventType, Vote, VoteChoice


@pytest.mark.parametrize("evidence_ids,valid", [(["ev-real"], True), (["ev-invented"], False), ([], False)])
async def test_model_votes_cannot_invent_evidence(monkeypatch, evidence_ids, valid):
    for k,v in {"AGENT_REASONING":"llm", "LLM_API_KEY":"synthetic-test-key", "LLM_MODEL":"synthetic-test-model", "LLM_BASE_URL":"http://model-fixture/v1"}.items():
        monkeypatch.setenv(k,v)
    captured=[]
    def handler(request):
        captured.append(json.loads(request.content))
        position={"vote":"CONFIRM", "confidence":.9, "evidence_ids":evidence_ids, "reason":"Synthetic model position based on the supplied observation."}
        return httpx.Response(200,json={"choices":[{"message":{"content":json.dumps(position)}}]})
    original_client=httpx.AsyncClient
    monkeypatch.setattr("agents.reasoning.httpx.AsyncClient", lambda **kwargs:original_client(transport=httpx.MockTransport(handler), **kwargs))
    capability=CapabilityDiscovery().get("access_control_agent")
    packet=AgentPacket(agent_id=capability.agent_id,
        votes=[Vote(agent_id=capability.agent_id, finding_id="f", vote=VoteChoice.ABSTAIN, confidence=.3, reason="Initial position")],
        events=[AgentMessage(run_id="r", agent_id=capability.agent_id, event_type=EventType.VOTE_CAST, claim="Initial position")])
    context={"category":"broken_access_control", "evidence":[{"evidence_id":"ev-real", "result":"positive"}]}
    if valid:
        result=await reason(capability,"vote",context,packet)
        assert result.votes[0].vote==VoteChoice.CONFIRM
        assert result.events[0].data["reasoning"]=="configured model"
    else:
        with pytest.raises(ValueError):
            await reason(capability,"vote",context,packet)
    assert captured[0]["messages"][0]["content"]==capability.system_prompt

