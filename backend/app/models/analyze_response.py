from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel

RiskLevel = Literal["low", "medium", "high", "critical"]
Action = Literal["allowed", "masked", "blocked"]


class AnalyzeFinding(BaseModel):
    # High-level category (example: "email", "api_key", "stack_trace", "failed_login")
    kind: str

    # Human-friendly label (example: "Email address")
    title: str

    # Risk contribution (0-10-ish; used by Risk Engine)
    severity: int

    risk_level: RiskLevel

    # Regex/heuristic/AI confidence: 0-1
    confidence: float = 0.5

    # Stable identifier for debugging/policy (example: "EMAIL_REGEX")
    rule_id: str

    # The exact substring or line evidence used for detection.
    matched_text: Optional[str] = None

    # 0-based line number for log/text inputs (when applicable).
    line_number: Optional[int] = None

    # Optional extra context about where it was found.
    details: dict[str, str] = {}


class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: list[AnalyzeFinding]
    risk_score: float
    risk_level: RiskLevel
    action: Action
    insights: list[str]

