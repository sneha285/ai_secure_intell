from __future__ import annotations

from typing import Literal

from app.models.analyze_request import AnalyzeRequest
from app.models.analyze_response import AnalyzeResponse
from app.services.validation import validate_analyze_request, infer_expected_content_type
from app.services.parsers.extractors import parse_input
from app.services.detection.regex_detector import detect_sensitive_data
from app.services.detection.log_analyzer import analyze_log
from app.services.risk.risk_engine import compute_risk
from app.services.policy.policy_engine import decide_action
from app.services.response.response_generator import build_response


def analyze_content(req: AnalyzeRequest) -> AnalyzeResponse:
    validate_analyze_request(req.input_type, req.content, req.filename)

    parsed = parse_input(
        req.input_type,
        req.content,
        filename=req.filename,
        is_base64=req.is_base64,
    )

    # Detection
    stats = None
    normalized_content = parsed.text
    if req.input_type == "log" or req.options.log_analysis:
        # Mandatory log analyzer path for log and optionally for all inputs.
        log_result = analyze_log(parsed.text)
        findings = log_result.findings
        stats = log_result.stats
        content_type = parsed.content_type
    else:
        findings = detect_sensitive_data(parsed.text)
        content_type = infer_expected_content_type(req.input_type, req.content, req.filename)

    # Risk
    risk_score, risk_level = compute_risk(findings)

    # Policy
    action = decide_action(risk_level, req.options)

    # Response
    resp = build_response(
        input_type=req.input_type,
        content=normalized_content,
        content_type=str(content_type),
        findings=findings,
        risk_score=risk_score,
        risk_level=risk_level,
        action=action,
        options=req.options,
        stats=stats,
    )
    return resp

