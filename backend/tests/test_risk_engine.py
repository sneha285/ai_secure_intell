from app.models.analyze_response import AnalyzeFinding
from app.services.risk.risk_engine import compute_risk


def test_risk_engine_password_is_critical():
    findings = [
        AnalyzeFinding(
            kind="password",
            title="Password exposed",
            severity=10,
            risk_level="critical",
            confidence=0.9,
            rule_id="PASSWORD_REGEX",
            matched_text="supersecret",
            line_number=0,
        )
    ]
    score, level = compute_risk(findings)
    assert level == "critical"
    assert score >= 10

