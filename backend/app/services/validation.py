from __future__ import annotations

from typing import Literal, Optional

from app.core.config import settings
from app.models.analyze_request import InputType


def validate_analyze_request(input_type: InputType, content: str, filename: Optional[str]) -> None:
    if not isinstance(content, str):
        raise ValueError("content must be a string")

    if len(content.encode("utf-8", errors="ignore")) > settings.max_content_bytes:
        raise ValueError(f"content too large (max {settings.max_content_bytes} bytes)")

    if input_type == "file" and not filename:
        raise ValueError("filename is required when input_type='file'")


def infer_expected_content_type(
    input_type: InputType, content: str, filename: Optional[str] = None
) -> Literal[
    "text/plain", "application/sql", "application/log"
]:
    if input_type == "sql":
        return "application/sql"
    if input_type == "log":
        return "application/log"
    if input_type == "file":
        # Best effort; actual extraction produces text/plain.
        return "text/plain"
    return "text/plain"

