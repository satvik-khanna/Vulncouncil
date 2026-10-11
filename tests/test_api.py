import importlib
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AGNTCY_TRANSPORT", "memory")
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "api.sqlite3"))
    import app.main
    module = importlib.reload(app.main)
    with TestClient(module.app) as client:
        yield client
    module.storage.db.close()


def test_config_health_and_validation(client):
    assert client.get("/api/health").json()["transport"] == "memory"
    config = client.get("/api/config").json()
    assert len(config["agents"]) == 6
    assert client.post("/api/runs", json={"target_id": "external-target"}).status_code == 422
    assert client.post("/api/runs", json={"scenario": "unknown"}).status_code == 422
    assert client.get("/api/runs/missing").status_code == 404
    assert client.post("/api/runs/missing/stop").status_code == 404


def test_gateway_is_not_public(client):
    assert client.post("/api/internal/check", json={"run_id": "r", "agent_id": "recon_agent", "check": "inventory"}).status_code == 403


def test_worker_identity_cannot_claim_another_specialists_permissions(client):
    import app.main
    app.main.service.transport.gateway_keys = {"recon_agent": "synthetic-recon-key", "access_control_agent": "synthetic-access-key"}
    body = {"run_id": "missing", "agent_id": "access_control_agent", "check": "cross_user_access"}
    assert client.post("/api/internal/check", json=body, headers={"X-Worker-Key": "synthetic-recon-key"}).status_code == 403
    assert client.post("/api/internal/check", json=body, headers={"X-Worker-Key": "synthetic-access-key"}).status_code == 409


def test_agent_manifests_and_a2a_cards(client):
    assert len(client.get("/api/agents/manifests").json()) == 6
    from a2a.types import AgentCard
    card = AgentCard.model_validate(client.get("/api/agents/evidence_skeptic/.well-known/agent-card.json").json())
    assert card.name == "vulncouncil/agents/evidence_skeptic"

