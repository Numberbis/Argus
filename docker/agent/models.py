from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field


class TriageRequest(BaseModel):
    scan_id: int


class TriageResponse(BaseModel):
    scan_id: int
    findings_count: int
    real_issues_count: int
    false_positives_count: int
    duplicates_count: int
    root_causes_count: int
    cost_usd: float
    duration_ms: int


class RemediateRequest(BaseModel):
    finding_id: int


class RemediateResponse(BaseModel):
    finding_id: int
    remediation: str
    cost_usd: float


class ChatRequest(BaseModel):
    question: str
    context_target: str | None = None


class ChatResponse(BaseModel):
    answer: str
    sql: str | None = None
    rows: list[dict[str, Any]] = Field(default_factory=list)
    cost_usd: float


class BudgetResponse(BaseModel):
    spend_today_usd: float
    daily_cap_usd: float
    remaining_usd: float
    provider: str
    model: str
