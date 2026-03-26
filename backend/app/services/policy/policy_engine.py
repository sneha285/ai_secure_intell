from __future__ import annotations

from app.models.analyze_response import Action, RiskLevel
from app.models.analyze_request import AnalyzeOptions


def decide_action(risk_level: RiskLevel, options: AnalyzeOptions) -> Action:
    if risk_level in ("high", "critical"):
        if options.block_high_risk:
            return "blocked"
        if options.mask:
            return "masked"
        return "allowed"

    if options.mask and risk_level in ("medium", "low"):
        # For medium/low we still allow masking if requested.
        return "masked"

    return "allowed"

