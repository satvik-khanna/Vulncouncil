import pytest
from app.safety_gate import SafetyGate, SafetyBlocked
from tools.lab_gateway import sanitize


@pytest.mark.parametrize("url,method,check", [
    ("https://example.com/checks", "POST", "inventory"),
    ("http://127.0.0.1:9999/checks", "POST", "inventory"),
    ("http://lab-target:8001/checks?destination=external", "POST", "inventory"),
    ("http://lab-target:8001/checks#fragment", "POST", "inventory"),
    ("http://user:pass@lab-target:8001/checks", "POST", "inventory"),
    ("http://lab-target:8001/admin", "POST", "inventory"),
    ("http://lab-target:8001/checks", "DELETE", "inventory"),
    ("http://lab-target:8001/checks", "POST", "external_destination"),
    ("http://127.0.0.1.evil.example:8001/checks", "POST", "inventory"),
])
def test_fail_closed(url, method, check):
    gate = SafetyGate()
    with pytest.raises(SafetyBlocked):
        gate.validate(url, method, check, "recon_agent", ["inventory"])
    assert gate.stopped and gate.blocked == 1
    assert sum(gate.counts.values()) == 0


def test_permissions_cannot_be_expanded_by_agent():
    with pytest.raises(SafetyBlocked):
        SafetyGate().validate("http://lab-target:8001/checks", "POST", "cross_user_access", "recon_agent", ["inventory"])


def test_budget_and_stop_and_deadline():
    gate = SafetyGate()
    gate.policy = {**gate.policy, "per_agent_requests": 1}
    gate.validate("http://lab-target:8001/checks", "POST", "inventory", "recon", ["inventory"])
    with pytest.raises(SafetyBlocked, match="budget"):
        gate.validate("http://lab-target:8001/checks", "POST", "inventory", "recon", ["inventory"])
    deadline = SafetyGate()
    deadline.started -= 121
    with pytest.raises(SafetyBlocked, match="deadline"):
        deadline.validate("http://lab-target:8001/checks", "POST", "inventory", "recon", ["inventory"])


def test_redaction_and_truncation():
    redacted = sanitize('token=PRIVATE password=PRIVATE cookie=PRIVATE ' + 'a' * 1000)
    assert "PRIVATE" not in redacted
    assert len(redacted) <= 600

