from __future__ import annotations

import re
from typing import Iterable, Optional

from app.models.analyze_response import AnalyzeFinding
from app.services.detection.patterns import compiled_regex_patterns


def _extract_match_text(match: re.Match[str]) -> str:
    # Prefer the first capture group when present (better for "key=value" patterns).
    if match.lastindex and match.lastindex >= 1:
        grp = match.group(1)
        if grp:
            return grp
    return match.group(0)


def detect_sensitive_data(text: str, *, start_line: Optional[int] = None) -> list[AnalyzeFinding]:
    findings: list[AnalyzeFinding] = []
    for rp, rgx in compiled_regex_patterns():
        for m in rgx.finditer(text):
            matched = _extract_match_text(m)
            findings.append(
                AnalyzeFinding(
                    kind=rp.kind,
                    title=rp.title,
                    severity=rp.severity,
                    risk_level=rp.risk_level,  # type: ignore[arg-type]
                    confidence=0.85,
                    rule_id=rp.rule_id,
                    matched_text=matched,
                    line_number=start_line,
                    details={},
                )
            )
    return findings


def dedupe_findings(findings: Iterable[AnalyzeFinding]) -> list[AnalyzeFinding]:
    # Deduplicate exact same (rule_id, kind, matched_text, line_number).
    seen: set[tuple[str, str, Optional[str], Optional[int]]] = set()
    out: list[AnalyzeFinding] = []
    for f in findings:
        key = (f.rule_id, f.kind, f.matched_text, f.line_number)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out

