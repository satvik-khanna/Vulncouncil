from typing import Literal
from pydantic import Field
from schemas.models import Model


class AuditRequest(Model):
    source: Literal["workspace", "github"] = "workspace"
    repository: str = Field(default="apache/airflow", pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=160)
    ref: str = Field(default="constraints-2.6.0", min_length=1, max_length=150)
    paths: list[str] = Field(default_factory=lambda: ["constraints-3.9.txt"], min_length=1, max_length=3)
    model_assisted: bool = True


class AuditOpinion(Model):
    stance: Literal["PRIORITIZE", "NEEDS_REVIEW", "NO_KNOWN_MATCHES"]
    reason: str = Field(min_length=1, max_length=500)
    evidence_ids: list[str] = Field(max_length=4)
    next_action: str = Field(min_length=1, max_length=300)
