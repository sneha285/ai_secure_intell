import json

from app.services.detection.log_analyzer import analyze_log


def test_log_analyzer_detects_email_and_failed_login_aggregates():
    log_text = "\n".join(
        [
            "2026-03-26T10:00:00Z login failed for user=alice from 203.0.113.10",
            "2026-03-26T10:00:01Z login failed for user=alice from 203.0.113.10",
            "2026-03-26T10:00:02Z login failed for user=alice from 203.0.113.10",
            "2026-03-26T10:00:03Z login failed for user=bob from 203.0.113.20",
            "2026-03-26T10:00:04Z login failed for user=carol from 203.0.113.30",
            "Contact: alice@example.com for support",
            "DEBUG Exception: Stack trace: at fn (app.js:12:34)",
        ]
    )

    result = analyze_log(log_text)
    kinds = {f.kind for f in result.findings}

    assert "email" in kinds
    assert "failed_login" in kinds
    assert "suspicious_ip_activity" in kinds
    assert "debug_leak" in kinds

