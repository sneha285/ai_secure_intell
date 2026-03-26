from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Literal, Optional

from app.services.validation import infer_expected_content_type
from app.core.config import settings


ParsedContentType = Literal["text/plain", "application/sql", "application/log"]


@dataclass(frozen=True)
class ParsedInput:
    text: str
    content_type: ParsedContentType


def _maybe_decode_base64(content: str) -> bytes:
    try:
        return base64.b64decode(content, validate=True)
    except Exception:
        # Fallback: content might be raw text or already decoded bytes-like string.
        return content.encode("utf-8", errors="ignore")


def _extract_text_from_pdf(pdf_bytes: bytes) -> str:
    # Lazy import: avoid native dependency load during app/test startup.
    import pdfplumber

    with pdfplumber.open(io_bytes(pdf_bytes)) as pdf:
        parts: list[str] = []
        for page in pdf.pages:
            txt = page.extract_text() or ""
            if txt.strip():
                parts.append(txt)
        return "\n".join(parts)


def io_bytes(b: bytes):
    import io

    return io.BytesIO(b)


def _extract_text_from_docx(docx_bytes: bytes) -> str:
    # Lazy import: avoid native dependency load during app/test startup.
    from docx import Document

    doc = Document(io_bytes(docx_bytes))
    return "\n".join([p.text for p in doc.paragraphs if p.text is not None])


def parse_input(
    input_type: Literal["text", "file", "sql", "chat", "log"],
    content: str,
    filename: Optional[str] = None,
    is_base64: bool = True,
) -> ParsedInput:
    """
    Convert supported inputs into a normalized `text` representation that detection modules can operate on.
    """
    expected = infer_expected_content_type(input_type, content, filename)

    if input_type in ("text", "sql", "chat", "log"):
        # Normalization: keep original line breaks for accurate log line numbering.
        return ParsedInput(text=content, content_type=expected)

    if input_type != "file":
        raise ValueError(f"Unsupported input_type: {input_type}")

    if not filename:
        raise ValueError("filename is required for file input")

    ext = os.path.splitext(filename)[1].lower()
    raw_bytes = _maybe_decode_base64(content) if is_base64 else content.encode("utf-8", errors="ignore")

    # Guard: ensure file input isn't absurdly large once decoded.
    if len(raw_bytes) > settings.max_content_bytes:
        raise ValueError("file too large")

    if ext in [".txt", ".log"]:
        return ParsedInput(text=raw_bytes.decode("utf-8", errors="ignore"), content_type="text/plain")

    if ext == ".pdf":
        return ParsedInput(text=_extract_text_from_pdf(raw_bytes), content_type="text/plain")

    if ext in [".doc", ".docx"]:
        # `python-docx` only supports docx reliably; `.doc` may fail.
        return ParsedInput(text=_extract_text_from_docx(raw_bytes), content_type="text/plain")

    # Default: treat as bytes-to-text.
    return ParsedInput(text=raw_bytes.decode("utf-8", errors="ignore"), content_type="text/plain")

