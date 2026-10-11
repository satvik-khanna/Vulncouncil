import httpx
import pytest
from lab_target.app import app
from lab_target.scenarios import fixture_check


def test_benign_signal_matches_candidate():
    signal = fixture_check("injection_signal", "ambiguous_injection")
    control = fixture_check("benign_control", "ambiguous_injection")
    assert signal["signal"] == control["signal"]
    assert fixture_check("injection_reproduce", "ambiguous_injection")["reproduction_failed"]


def test_guard_changes_authorization_response():
    assert fixture_check("cross_user_access", "access_control")["record_visible"] is True
    patched = fixture_check("cross_user_access", "access_control", True)
    assert patched["status_code"] == 403
    assert patched["record_visible"] is False


@pytest.mark.parametrize("check,scenario", [("arbitrary_payload", "access_control"), ("inventory", "unknown")])
async def test_unknown_fixture_commands_rejected(check, scenario):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://lab-target:8001") as client:
        r = await client.post("/checks", json={"check": check, "scenario": scenario})
        assert r.status_code == 400

