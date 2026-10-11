import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from schemas.models import Evidence
from app.safety_gate import SafetyGate, SafetyBlocked
from tools.lab_client import LabClient


def sanitize(value: str) -> str:
    value = re.sub(r'(?i)(token|password|cookie|authorization|secret)["\s]*[:=][^,\s}]+', r'\1=[REDACTED]', value)
    return value[:600]


class LabToolGateway:
    def __init__(self, run, registry, client: LabClient, on_block: Callable[[str, str], Awaitable[None]]):
        self.run = run
        self.registry = registry
        self.client = client
        self.gate = SafetyGate()
        self.on_block = on_block
        self.evidence: list[Evidence] = []

    async def check(self, agent_id: str, name: str, finding_id: str | None = None) -> Evidence:
        try:
            cap = self.registry.get(agent_id)
            invoice_probe = self.run.scenario.startswith("tenant_invoice") and name in {"cross_user_access", "access_reproduce"}
            if not invoice_probe:
                self.gate.validate(self.client.base_url + "/checks", "POST", name, agent_id, cap.allowed_checks)
            version, patched = self.run.environment_version, self.run.patched
            from app.telemetry import tracer
            with tracer.start_as_current_span("lab.named_check", attributes={"agent.id": agent_id, "run.id": self.run.run_id, "check.name": name}):
                if invoice_probe:
                    result = await self.client.invoice_probe(name, patched, lambda url, method: self.gate.validate(url, method, name, agent_id, cap.allowed_checks))
                else:
                    result = await self.client.check(name, self.run.scenario, patched, self.run.fixture_variant)
        except (SafetyBlocked, StopIteration) as exc:
            await self.on_block(agent_id, str(exc))
            raise SafetyBlocked(str(exc)) from exc
        # Fixture facts have a strict scalar allowlist: raw HTTP bodies are never persisted.
        allowed = {"signal", "control", "query_changed", "record_visible", "guard_enabled", "actor", "record_owner", "header", "present", "routes", "identities", "actor_tenant", "resource_tenant", "invoice_id", "owner_status", "same_tenant_status", "controls_passed", "response_matches_owner", "owner_response_hash", "outsider_response_hash", "http_requests", "sensitive_fields", "policy"}
        facts = {k: v for k, v in result.items() if k in allowed}
        facts["environment_version"] = version
        canonical = json.dumps(facts, sort_keys=True)
        relevant = {"hardening": {"headers", "headers_reproduce"}, "ambiguous_injection": {"injection_signal", "benign_control", "injection_reproduce"}}.get(self.run.scenario, {"cross_user_access", "access_reproduce", "guard_config"})
        if name not in relevant:
            finding_id = None
        item = Evidence(run_id=self.run.run_id, agent_id=agent_id, finding_id=finding_id, tool_name=name,
                        test_description=f"Authenticated billing API check: {name}" if invoice_probe else f"Named synthetic check: {name}", method="GET" if invoice_probe else "POST", route=result.get("observed_route", "/checks"), result=result["result"], status_code=result["status_code"],
                        snippet=sanitize(canonical), response_hash=hashlib.sha256(canonical.encode()).hexdigest(),
                        reproducible=result.get("reproducible", False), reproduction_failed=result.get("reproduction_failed", False), facts=facts)
        self.evidence.append(item)
        return item

