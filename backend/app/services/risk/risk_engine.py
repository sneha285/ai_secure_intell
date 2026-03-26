from __future__ import annotations

from typing import Literal

from app.models.analyze_response import AnalyzeFinding, RiskLevel


def compute_risk(findings: list[AnalyzeFinding]) -> tuple[float, RiskLevel]:
    """
    Risk scoring algorithm.

    - Uses finding severities as primary signal.
    - Ensures canonical risk mappings:
      * password -> critical
      * api_key/token/jwt -> high/critical
      * stack_trace -> medium
      * email/phone -> low
    """
    if not findings:
        return 0.0, "low"

    # Canonical overrides from "kind" to avoid drift.
    kind_to_override: dict[str, RiskLevel] = {
        "password": "critical",
        "jwt": "critical",
        "api_key": "high",
        "token": "high",
        "hardcoded_secret": "high",
        "credentials_in_logs": "high",
        "stack_trace": "medium",
        "debug_leak": "medium",
        "failed_login": "high",
        "suspicious_ip_activity": "medium",
        "email": "low",
        "phone": "low",
    }

    # Score: sum of severities (top N) then cap.
    # This makes multiple issues increment risk in a predictable way.
    top = sorted(findings, key=lambda f: f.severity, reverse=True)[:30]
    score = float(sum(min(10, f.severity) for f in top))

    # Cap to keep values stable for UI and policy.
    # Still allows 10+ as requested.
    score = min(score, 30.0)

    # Determine risk level:
    # - If any canonical critical/high exists, prefer that.
    override_levels: list[RiskLevel] = []
    for f in findings:
        if f.kind in kind_to_override:
            override_levels.append(kind_to_override[f.kind])
    if "critical" in override_levels:
        return score, "critical"
    if "high" in override_levels:
        return score, "high"
    if "medium" in override_levels:
        return score, "medium"
    # Fallback to thresholds based on score.
    if score >= 10:
        return score, "critical"
    if score >= 7:
        return score, "high"
    if score >= 4:
        return score, "medium"
    return score, "low"

