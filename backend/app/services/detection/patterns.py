from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RegexPattern:
    kind: str
    title: str
    rule_id: str
    severity: int
    risk_level: str  # low|medium|high|critical (kept as string to decouple modules)
    # Compiled later for speed and to keep this file import-light.
    pattern: str
    flags: int = re.IGNORECASE


REGEX_PATTERNS: list[RegexPattern] = [
    RegexPattern(
        kind="email",
        title="Email address",
        rule_id="EMAIL_REGEX",
        severity=2,
        risk_level="low",
        pattern=r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    ),
    RegexPattern(
        kind="phone",
        title="Phone number",
        rule_id="PHONE_REGEX",
        severity=2,
        risk_level="low",
        pattern=r"\b(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?)?\d{3,4}[\s-]?\d{3,4}\b",
    ),
    # AWS access key id (example: AKIAIOSFODNN7EXAMPLE)
    RegexPattern(
        kind="api_key",
        title="AWS access key id",
        rule_id="AWS_ACCESS_KEY_ID",
        severity=9,
        risk_level="high",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
    ),
    # Google API key (example: AIza...35 chars)
    RegexPattern(
        kind="api_key",
        title="Google API key",
        rule_id="GOOGLE_API_KEY",
        severity=9,
        risk_level="high",
        pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b",
    ),
    # Generic "api key" value patterns.
    RegexPattern(
        kind="api_key",
        title="API key in logs",
        rule_id="GENERIC_API_KEY",
        severity=8,
        risk_level="high",
        pattern=r"\b(?:api[_-]?key|x-api-key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{16,})[\"']?",
    ),
    RegexPattern(
        kind="token",
        title="Bearer token",
        rule_id="BEARER_TOKEN",
        severity=8,
        risk_level="high",
        pattern=r"\bBearer\s+([A-Za-z0-9\-\._~\+\/]+=*)\b",
    ),
    RegexPattern(
        kind="token",
        title="Token in logs",
        rule_id="GENERIC_TOKEN",
        severity=8,
        risk_level="high",
        pattern=r"\b(?:token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{16,})[\"']?",
    ),
    # JWT: header.payload.signature (base64url)
    RegexPattern(
        kind="jwt",
        title="JWT token",
        rule_id="JWT_REGEX",
        severity=10,
        risk_level="critical",
        pattern=r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+?\b",
    ),
    RegexPattern(
        kind="password",
        title="Password exposed",
        rule_id="PASSWORD_REGEX",
        severity=10,
        risk_level="critical",
        pattern=r"\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?([^\"'\s;]{4,})[\"']?",
    ),
    RegexPattern(
        kind="stack_trace",
        title="Stack trace / exception",
        rule_id="STACK_TRACE_REGEX",
        severity=6,
        risk_level="medium",
        pattern=r"(Traceback \(most recent call last\):|Stack trace:|Exception:|at\s+\w+\(.*:\d+:\d+\))",
    ),
    RegexPattern(
        kind="hardcoded_secret",
        title="Hardcoded secret marker",
        rule_id="HARD_CODED_SECRET_MARKER",
        severity=9,
        risk_level="high",
        pattern=r"\b(?:secret|secretd|api[_-]?secret|client[_-]?secret|signing[_-]?key)\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{8,})[\"']?",
    ),
    # Credentials in a single line: user/password co-occurrence.
    RegexPattern(
        kind="credentials_in_logs",
        title="Credentials in logs",
        rule_id="CREDENTIALS_CO_OCCURRENCE",
        severity=9,
        risk_level="high",
        pattern=r"\b(?:user(name)?|username|login)\b.{0,40}?\b(?:password|passwd|pwd|secret|token)\b",
        flags=re.IGNORECASE | re.DOTALL,
    ),
]


def compiled_regex_patterns() -> list[tuple[RegexPattern, re.Pattern[str]]]:
    compiled: list[tuple[RegexPattern, re.Pattern[str]]] = []
    for rp in REGEX_PATTERNS:
        compiled.append((rp, re.compile(rp.pattern, rp.flags)))
    return compiled

