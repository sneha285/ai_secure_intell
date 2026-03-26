from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


InputType = Literal["text", "file", "sql", "chat", "log"]


class AnalyzeOptions(BaseModel):
    # Replace sensitive values with placeholders in the returned content.
    mask: bool = True

    # If risk is high/critical, block the request (avoid returning content).
    block_high_risk: bool = True

    # Force log analyzer behavior (line-by-line) even for "text" input.
    log_analysis: bool = False

    # Optional: ask the LLM to produce additional insights beyond regex results.
    enable_ai_insights: Optional[bool] = None


class AnalyzeRequest(BaseModel):
    input_type: InputType
    content: str = Field(..., description="Raw input content or base64 for file inputs.")
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)

    # File metadata (optional; only used when input_type="file").
    filename: Optional[str] = None
    content_type: Optional[str] = None
    is_base64: bool = True

