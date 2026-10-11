from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def uid(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Status(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    DISPUTED = "DISPUTED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class VoteChoice(StrEnum):
    CONFIRM = "CONFIRM"
    REJECT = "REJECT"
    DISPUTED = "DISPUTED"
    ABSTAIN = "ABSTAIN"


class EventType(StrEnum):
    ASSESSMENT_OPENED = "ASSESSMENT_OPENED"
    CAPABILITY_SELECTED = "CAPABILITY_SELECTED"
    FINDING_PROPOSED = "FINDING_PROPOSED"
    CHALLENGE = "CHALLENGE"
    COUNTEREVIDENCE = "COUNTEREVIDENCE"
    BELIEF_UPDATED = "BELIEF_UPDATED"
    VOTE_CAST = "VOTE_CAST"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    ASSESSMENT_COMPLETED = "ASSESSMENT_COMPLETED"
    SAFETY_BLOCKED = "SAFETY_BLOCKED"
    ASSESSMENT_STOPPED = "ASSESSMENT_STOPPED"
    ERROR = "ERROR"
    TOOL_RESULT = "TOOL_RESULT"
    PLAN_UPDATED = "PLAN_UPDATED"
    COLLABORATOR_REQUESTED = "COLLABORATOR_REQUESTED"
    ENVIRONMENT_CHANGED = "ENVIRONMENT_CHANGED"


class AssessmentRequest(Model):
    scenario: Literal["ambiguous_injection", "access_control", "patched_access", "hardening", "incomplete_access", "scope_violation", "changing_access", "tenant_invoice", "tenant_invoice_change"] = "ambiguous_injection"
    patched: bool = False
    target_id: Literal["lab-target"] = "lab-target"


class AgentCapability(Model):
    agent_id: str
    name: str
    description: str
    objective: str
    system_prompt: str
    skills: list[str]
    allowed_checks: list[str]
    version: str = "1.0.0"
    schema_version: str = "0.8.0"


class Evidence(Model):
    evidence_id: str = Field(default_factory=lambda: uid("ev"))
    run_id: str
    agent_id: str
    finding_id: str | None = None
    tool_name: str
    target_id: str = "lab-target"
    test_description: str
    method: str = "POST"
    route: str = "/checks"
    result: Literal["signal", "positive", "negative", "incomplete", "inventory", "blocked"]
    status_code: int
    snippet: str
    response_hash: str
    timestamp: str = Field(default_factory=now)
    reproducible: bool = False
    observable: bool = True
    decisive_counterexample: bool = False
    reproduction_failed: bool = False
    facts: dict[str, Any] = Field(default_factory=dict)


class Vote(Model):
    agent_id: str
    finding_id: str
    vote: VoteChoice
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str
    round: int = Field(default=1, ge=0, le=2)


class AgentMessage(Model):
    event_id: str = Field(default_factory=lambda: uid("evt"))
    run_id: str
    finding_id: str | None = None
    agent_id: str
    event_type: EventType
    round: int = Field(default=0, ge=0, le=2)
    claim: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence_before: float | None = Field(default=None, ge=0, le=1)
    confidence_after: float | None = Field(default=None, ge=0, le=1)
    vote: VoteChoice | None = None
    timestamp: str = Field(default_factory=now)
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(Model):
    finding_id: str
    run_id: str
    title: str
    category: str
    asset: str = "lab-target"
    route: str
    status: Status = Status.DISPUTED
    confidence: float = Field(ge=0, le=1)
    initial_confidence: float = Field(ge=0, le=1)
    impact_band: str = "medium"
    reproducible: bool = False
    evidence_ids: list[str] = Field(default_factory=list)
    supporting_agents: list[str] = Field(default_factory=list)
    challenging_agents: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=lambda: ["Synthetic fixture only; no real-world exploitability claim"])
    remediation: str
    created_at: str = Field(default_factory=now)
    rule: str = "Awaiting deliberation"
    votes: list[Vote] = Field(default_factory=list)
    baseline: dict[str, str] = Field(default_factory=dict)


class AssessmentMetrics(Model):
    evidence_coverage: float = 0
    belief_revisions: int = 0
    blocked_requests: int = 0
    tool_requests: int = 0
    duration_seconds: float = 0
    group_messages: int = 0
    peer_receipts: int = 0
    model_calls: int = 0
    model_tokens: int = 0


class AssessmentRun(Model):
    run_id: str = Field(default_factory=lambda: uid("run"))
    scenario: str
    patched: bool
    target_id: str = "lab-target"
    transport: str
    reasoning: Literal["rules", "llm"] | None = None
    reasoning_model: str | None = None
    state: Literal["queued", "running", "completed", "stopped", "failed"] = "queued"
    created_at: str = Field(default_factory=now)
    completed_at: str | None = None
    selected_agents: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    metrics: AssessmentMetrics = Field(default_factory=AssessmentMetrics)
    error: str | None = None
    environment_version: int = 0
    fixture_variant: str = "standard"
    decision_mode: Literal["council", "single_agent", "simple_majority"] = "council"


class CheckRequest(Model):
    check: str
    scenario: str
    patched: bool = False
    variant: Literal["standard", "causal_injection", "unmatched_control", "replica_conflict", "replica_incomplete", "unstable_headers"] = "standard"


class InterventionRequest(Model):
    action: Literal["enable_guard", "disable_guard"]


class GatewayRequest(Model):
    run_id: str
    agent_id: str
    check: str
    finding_id: str | None = None


class AgentPacket(Model):
    agent_id: str
    events: list[AgentMessage] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    votes: list[Vote] = Field(default_factory=list)
    peer_receipts: int = 0
    error: str | None = None
    requested_skills: list[str] = Field(default_factory=list)
    model_calls: int = 0
    model_tokens: int = 0

