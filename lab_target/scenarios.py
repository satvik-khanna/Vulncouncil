"""No payloads or exploit execution: only finite, synthetic named checks."""
from typing import Any

CHECKS = {"inventory", "injection_signal", "benign_control", "injection_reproduce", "cross_user_access", "access_reproduce", "headers", "headers_reproduce", "guard_config"}
SCENARIOS = {"ambiguous_injection", "access_control", "patched_access", "hardening", "incomplete_access", "scope_violation", "changing_access", "tenant_invoice", "tenant_invoice_change"}


def fixture_check(check: str, scenario: str, patched: bool = False, variant: str = "standard") -> dict[str, Any]:
    if check not in CHECKS or scenario not in SCENARIOS:
        raise ValueError("Unknown named fixture check or scenario")
    if variant not in {"standard", "causal_injection", "unmatched_control", "replica_conflict", "replica_incomplete", "unstable_headers"}:
        raise ValueError("Unknown fixture variant")
    if check == "guard_config":
        return {"result": "inventory", "status_code": 200, "guard_enabled": patched, "reproducible": True}
    if scenario.startswith("tenant_invoice") and check in {"cross_user_access", "access_reproduce"}:
        raise ValueError("Invoice checks must execute the billing HTTP API, not fixture outcomes")
    if check == "inventory":
        return {"result": "inventory", "status_code": 200, "routes": ["/checks", "/health"], "identities": ["synthetic-alice", "synthetic-bob"], "reproducible": True}
    if check in {"injection_signal", "benign_control"}:
        return {"result": "signal", "status_code": 422, "signal": "SYNTHETIC_VALIDATION_ERROR" if check == "benign_control" and variant in {"causal_injection", "unmatched_control"} else "SYNTHETIC_PARSE_ERROR", "control": check == "benign_control", "reproducible": True}
    if check == "injection_reproduce":
        if variant == "causal_injection":
            return {"result": "positive", "status_code": 200, "query_changed": True, "reproducible": True}
        if variant == "unmatched_control":
            return {"result": "incomplete", "status_code": 206, "query_changed": None, "reproducible": False}
        return {"result": "negative", "status_code": 200, "query_changed": False, "reproduction_failed": True, "reproducible": True}
    if check in {"cross_user_access", "access_reproduce"}:
        if scenario == "incomplete_access" or (check == "access_reproduce" and variant == "replica_incomplete"):
            return {"result": "incomplete", "status_code": 206, "record_visible": None, "reproducible": False}
        guarded = patched or scenario == "patched_access" or (check == "access_reproduce" and variant == "replica_conflict")
        return {"result": "negative" if guarded else "positive", "status_code": 403 if guarded else 200, "actor": "synthetic-alice", "record_owner": "synthetic-bob", "record_visible": not guarded, "guard_enabled": guarded, "reproduction_failed": guarded, "reproducible": True}
    guarded = patched or (check == "headers_reproduce" and variant == "unstable_headers")
    return {"result": "negative" if guarded else "positive", "status_code": 200, "header": "Content-Security-Policy", "present": guarded, "reproduction_failed": guarded, "reproducible": True}

