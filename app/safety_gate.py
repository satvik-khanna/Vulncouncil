import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
import yaml

from lab_target.scenarios import CHECKS

ROOT = Path(__file__).resolve().parents[1]


class SafetyBlocked(RuntimeError):
    pass


class SafetyGate:
    def __init__(self, policy=None):
        self.policy = policy or yaml.safe_load((ROOT / "config/safety.yaml").read_text())
        self.started = time.monotonic()
        self.counts = Counter()
        self.stopped = False
        self.blocked = 0

    def validate(self, url: str, method: str, check: str, agent_id: str, permissions: list[str]) -> None:
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        reason = None
        if self.stopped:
            reason = "Global stop switch is active"
        elif time.monotonic() - self.started > self.policy["deadline_seconds"]:
            reason = "Assessment deadline exceeded"
        elif origin not in self.policy["allowed_origins"] or p.username or p.password or p.query or p.fragment:
            reason = "Destination is outside the exact local origin allowlist"
        elif p.path not in self.policy["allowed_routes"] or method not in self.policy["allowed_methods"]:
            reason = "Route or method is not allowlisted"
        elif (p.path == "/checks" and method != "POST") or (p.path.startswith("/demo/") and (method != "GET" or check not in {"cross_user_access", "access_reproduce"})):
            reason = "Route, method and named check combination is not allowlisted"
        elif check not in CHECKS or check not in permissions:
            reason = "Named check is unknown or outside this agent's permissions"
        elif sum(self.counts.values()) >= self.policy["max_requests"] or self.counts[agent_id] >= self.policy["per_agent_requests"]:
            reason = "Assessment request budget exhausted"
        if reason:
            self.blocked += 1
            self.stopped = True
            raise SafetyBlocked(reason)
        self.counts[agent_id] += 1

