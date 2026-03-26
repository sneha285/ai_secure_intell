from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from app.models.analyze_response import AnalyzeFinding
from app.services.detection.patterns import compiled_regex_patterns
from app.services.detection.regex_detector import dedupe_findings, _extract_match_text  # type: ignore
from app.core.config import settings


_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")


@dataclass(frozen=True)
class LogAnomalyStats:
    failed_login_total: int
    failed_login_by_ip: dict[str, int]
    suspicious_ips: list[tuple[str, int]]
    debug_leak_count: int


@dataclass(frozen=True)
class LogAnalysisResult:
    findings: list[AnalyzeFinding]
    stats: LogAnomalyStats


def _find_ips(line: str) -> list[str]:
    return _IPV4_RE.findall(line) or []


def _is_failed_login(line: str) -> bool:
    s = line.lower()
    return (
        "failed login" in s
        or "login failed" in s
        or "invalid credentials" in s
        or "authentication failed" in s
        or "wrong password" in s
    )


def _is_debug_leak(line: str) -> bool:
    s = line.lower()
    return ("debug" in s or "trace" in s) and (
        "exception" in s or "stack trace" in s or "traceback" in s
    )


def analyze_log(text: str, *, chunk_size: int = 500) -> LogAnalysisResult:
    """
    Mandatory log analyzer: scans line-by-line for sensitive data and security issues,
    plus aggregated anomaly detection (failed logins, suspicious IPs, debug leaks).
    """
    lines = text.splitlines()
    # Defensive guard: avoid exploding memory on huge logs.
    if len(lines) > settings.max_lines:
        # Keep the most relevant portion first.
        lines = lines[: settings.max_lines]

    findings: list[AnalyzeFinding] = []
    failed_login_total = 0
    failed_login_by_ip: dict[str, int] = {}
    debug_leak_count = 0

    compiled = compiled_regex_patterns()
    for line_idx, line in enumerate(lines):
        # Regex-based detection (per line)
        for rp, rgx in compiled:
            for m in rgx.finditer(line):
                matched = _extract_match_text(m)
                findings.append(
                    AnalyzeFinding(
                        kind=rp.kind,
                        title=rp.title,
                        severity=rp.severity,
                        risk_level=rp.risk_level,  # type: ignore[arg-type]
                        confidence=0.9,
                        rule_id=rp.rule_id,
                        matched_text=matched,
                        line_number=line_idx,
                        details={},
                    )
                )

        # Advanced security patterns
        if _is_failed_login(line):
            failed_login_total += 1
            for ip in _find_ips(line):
                failed_login_by_ip[ip] = failed_login_by_ip.get(ip, 0) + 1

        if _is_debug_leak(line):
            debug_leak_count += 1

    # Aggregate anomaly findings.
    suspicious_ips: list[tuple[str, int]] = []
    if failed_login_by_ip:
        suspicious_ips = sorted(failed_login_by_ip.items(), key=lambda kv: kv[1], reverse=True)

    # Thresholds are conservative defaults; can be tuned by options later.
    failed_login_threshold = 5
    suspicious_ip_threshold = 3

    if failed_login_total >= failed_login_threshold:
        findings.append(
            AnalyzeFinding(
                kind="failed_login",
                title="Multiple failed login attempts",
                severity=7,
                risk_level="high",
                confidence=0.8,
                rule_id="FAILED_LOGIN_AGGREGATE",
                matched_text=None,
                line_number=None,
                details={"failed_login_total": str(failed_login_total)},
            )
        )

    top_suspicious = [ip for ip, cnt in suspicious_ips[:5] if cnt >= suspicious_ip_threshold]
    if top_suspicious:
        findings.append(
            AnalyzeFinding(
                kind="suspicious_ip_activity",
                title="Suspicious IP activity detected",
                severity=6,
                risk_level="medium",
                confidence=0.78,
                rule_id="SUSPICIOUS_IP_AGGREGATE",
                matched_text=None,
                line_number=None,
                details={"suspicious_ips": ", ".join([f"{ip}({cnt})" for ip, cnt in suspicious_ips[:5]])},
            )
        )

    if debug_leak_count > 0:
        findings.append(
            AnalyzeFinding(
                kind="debug_leak",
                title="Potential debug/stack trace leak",
                severity=5,
                risk_level="medium",
                confidence=0.75,
                rule_id="DEBUG_LEAK_AGGREGATE",
                matched_text=None,
                line_number=None,
                details={"debug_leak_count": str(debug_leak_count)},
            )
        )

    return LogAnalysisResult(findings=dedupe_findings(findings), stats=LogAnomalyStats(
        failed_login_total=failed_login_total,
        failed_login_by_ip=failed_login_by_ip,
        suspicious_ips=suspicious_ips,
        debug_leak_count=debug_leak_count,
    ))

