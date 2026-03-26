from __future__ import annotations

from collections import Counter
from typing import Any, Optional

from app.models.analyze_response import AnalyzeFinding, AnalyzeResponse, RiskLevel, Action
from app.models.analyze_request import AnalyzeOptions
from app.services.detection.ai_insights import generate_ai_insights
from app.core.config import settings


def _risk_label_hint(risk_level: RiskLevel) -> str:
    if risk_level == "critical":
        return "Critical risk: stop exposure and prevent replay."
    if risk_level == "high":
        return "High risk: rotate/contain exposed secrets."
    if risk_level == "medium":
        return "Medium risk: review logs/config for leakage patterns."
    return "Low risk: no major sensitive artifacts detected."


def _build_deterministic_summary(
    input_type: str, findings: list[AnalyzeFinding], *, stats: Optional[Any] = None
) -> str:
    if not findings:
        return f"No sensitive indicators detected in {input_type}."

    by_kind = Counter([f.kind for f in findings])
    top_kinds = by_kind.most_common(5)
    top_desc = ", ".join([f"{k}({cnt})" for k, cnt in top_kinds])

    base = f"Detected security indicators in {input_type}. Top signal types: {top_desc}."
    if stats and hasattr(stats, "failed_login_total") and stats.failed_login_total:
        base += f" Log anomaly: {stats.failed_login_total} failed login events."
    if stats and hasattr(stats, "debug_leak_count") and stats.debug_leak_count:
        base += f" Debug/stack-leak indicators: {stats.debug_leak_count} lines."
    return base


def _build_deterministic_insights(
    findings: list[AnalyzeFinding], *, stats: Optional[Any] = None, max_items: int = 10
) -> list[str]:
    if not findings and not stats:
        return []

    # Prefer higher severity kinds and attach evidence when available.
    sorted_findings = sorted(findings, key=lambda f: f.severity, reverse=True)
    insights: list[str] = []
    seen_kinds: set[str] = set()

    for f in sorted_findings:
        if f.kind in seen_kinds:
            continue
        if len(insights) >= max_items:
            break
        seen_kinds.add(f.kind)
        evidence = f.matched_text if f.matched_text else (f.details.get("failed_login_total") if f.details else None)
        rule = f.rule_id
        if f.kind in ("password", "api_key", "token", "jwt", "hardcoded_secret", "credentials_in_logs"):
            insights.append(f"{f.title} detected (rule={rule}). Evidence: {evidence or 'present in input'}.")
        elif f.kind in ("stack_trace", "debug_leak"):
            line_part = f" line={f.line_number}" if f.line_number is not None else ""
            insights.append(f"{f.title} detected (rule={rule}){line_part}. This can expose internal implementation details.")
        elif f.kind in ("failed_login", "suspicious_ip_activity"):
            insights.append(f"{f.title} detected (rule={rule}). Details: {f.details}.")
        else:
            insights.append(f"{f.title} detected (rule={rule}).")

    # Log anomalies not represented as direct findings.
    if stats:
        if getattr(stats, "failed_login_total", 0) >= 1:
            insights.append(
                f"Multiple failed login attempts observed (count={stats.failed_login_total}). "
                f"Consider rate limiting and account lockout."
            )
        if getattr(stats, "debug_leak_count", 0) >= 1:
            insights.append(
                f"Debug/stack trace leak indicators observed (lines={stats.debug_leak_count}). "
                f"Ensure debug logs are disabled in production."
            )

    # De-duplicate while preserving order.
    deduped: list[str] = []
    seen: set[str] = set()
    for i in insights:
        if i in seen:
            continue
        seen.add(i)
        deduped.append(i)
    return deduped[:max_items]


def build_response(
    *,
    input_type: str,
    content: str,
    content_type: str,
    findings: list[AnalyzeFinding],
    risk_score: float,
    risk_level: RiskLevel,
    action: Action,
    options: AnalyzeOptions,
    stats: Optional[Any] = None,
) -> AnalyzeResponse:
    summary = _build_deterministic_summary(input_type, findings, stats=stats)

    deterministic_insights = _build_deterministic_insights(findings, stats=stats, max_items=12)
    deterministic_insights.insert(0, _risk_label_hint(risk_level))

    ai_payload: Optional[dict[str, Any]] = None
    enable_ai = options.enable_ai_insights
    if enable_ai is None:
        # Default: enable only when OPENAI_API_KEY is configured.
        enable_ai = settings.openai_api_key is not None

    if enable_ai:
        ai_payload = generate_ai_insights(
            input_type=input_type, content=content, findings=[f.model_dump() for f in findings]
        )

    insights: list[str] = []
    insights.extend(deterministic_insights)
    if ai_payload:
        # AI returns: summary, insights[], risk_explanations[]
        ai_ins = ai_payload.get("insights") or []
        for item in ai_ins[:6]:
            if isinstance(item, str):
                insights.append(item)

        # If AI provided a better summary, prefer it when non-empty.
        ai_summary = ai_payload.get("summary")
        if isinstance(ai_summary, str) and ai_summary.strip():
            summary = ai_summary.strip()

    return AnalyzeResponse(
        summary=summary,
        content_type=content_type,
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,  # decided by policy engine
        insights=insights,
    )

