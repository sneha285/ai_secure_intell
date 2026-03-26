from __future__ import annotations

import json
from typing import Any

from openai import OpenAI

from app.core.config import settings


def _build_prompt(*, input_type: str, content: str, findings: list[dict[str, Any]]) -> str:
    # Meaningful prompt: forces the model to reference concrete finding types and evidence.
    # It also requires a strictly JSON response for predictable parsing.
    findings_preview = []
    for f in findings[:25]:
        findings_preview.append(
            {
                "kind": f.get("kind"),
                "rule_id": f.get("rule_id"),
                "risk_level": f.get("risk_level"),
                "severity": f.get("severity"),
                "line_number": f.get("line_number"),
                "matched_text": (f.get("matched_text")[:80] if f.get("matched_text") else None),
                "details": f.get("details", {}),
            }
        )

    content_preview = content[:4000]
    return f"""
You are a security analyst for the "AI Secure Data Intelligence Platform".
Generate security insights that are specific to the provided input and findings.

Rules:
- Do NOT be generic. Every insight must mention at least one concrete finding (kind/rule_id) and, when available, the evidence (matched_text or line_number).
- If there are credentials/secrets indicators, include a risk explanation and 1-2 mitigation steps (e.g., rotate keys, scrub logs, least privilege).
- If log anomalies are detected (failed logins, suspicious IPs, debug leaks), explain what anomaly was observed and why it matters.
- Keep output concise.
- Return valid JSON only, matching the schema below.

Schema:
{{
  "summary": string,
  "insights": [string],
  "risk_explanations": [string]
}}

Input type: {input_type}
Content preview (may be truncated):
{content_preview}

Detected findings (from regex/heuristics):
{json.dumps(findings_preview, ensure_ascii=False, indent=2)}
""".strip()


def generate_ai_insights(*, input_type: str, content: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not settings.openai_api_key:
        return {"summary": "", "insights": [], "risk_explanations": []}

    client = OpenAI(api_key=settings.openai_api_key)

    prompt = _build_prompt(input_type=input_type, content=content, findings=findings)

    # Use JSON response formatting for predictable parsing.
    completion = client.chat.completions.create(
        model=settings.openai_model,
        messages=[
            {"role": "system", "content": "You produce strict JSON security reports."},
            {"role": "user", "content": prompt},
        ],
        response_format={"type": "json_object"},
        temperature=0.2,
        timeout=settings.ai_timeout_seconds,
    )

    raw = completion.choices[0].message.content or "{}"
    try:
        return json.loads(raw)
    except Exception:
        # Fallback if the model returned non-JSON.
        return {"summary": "", "insights": [], "risk_explanations": []}

