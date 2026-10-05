"""
document_engine.py
Layer 2A: Document Engine — routes files to the correct detector

FIX (this version):
- Always returns the full schema (visible_text, hidden_text,
  embedded_scripts, metadata, source_file, file_type).
- Failures are reported via an "error" key AND "parse_failed": True,
  so the server can fail CLOSED instead of scoring an empty doc as SAFE.
- Detector exceptions are caught and reported the same way.
- File type can be inferred from the extension if not supplied.
"""

import os
from typing import Dict, Optional

from .detectors.pdf_detector import detect_pdf_threats
from .detectors.email_detector import detect_email_threats
from .detectors.html_detector import detect_html_threats
from .detectors.docx_detector import detect_docx_threats

MAX_TXT_BYTES = 5 * 1024 * 1024  # 5 MB cap on plain-text reads

# Canonical type for each accepted alias
TYPE_ALIASES = {
    "pdf": "pdf",
    "email": "email", "eml": "email",
    "html": "html", "htm": "html",
    "docx": "docx",
    "txt": "txt",
    # "msg" and "doc" are binary formats; only enable them once your
    # email/docx detectors can actually parse them.
}

DETECTORS = {
    "pdf": detect_pdf_threats,
    "email": detect_email_threats,
    "html": detect_html_threats,
    "docx": detect_docx_threats,
}


def _base_result(file_path: str, file_type: str) -> Dict:
    return {
        "visible_text": "",
        "hidden_text": "",
        "embedded_scripts": [],
        "metadata": {},
        "source_file": file_path,
        "file_type": file_type,
    }


def _failure(file_path: str, file_type: str, message: str) -> Dict:
    result = _base_result(file_path, file_type)
    result["error"] = message
    result["parse_failed"] = True  # server should treat this as BLOCK/REVIEW, not SAFE
    return result


def _resolve_type(file_path: str, file_type: Optional[str]) -> str:
    if file_type:
        return str(file_type).lower().strip().lstrip(".")
    return os.path.splitext(file_path)[1].lower().lstrip(".")


def parse_document(file_path: str, file_type: Optional[str] = None) -> Dict:
    raw_type = _resolve_type(file_path, file_type)

    if not os.path.isfile(file_path):
        return _failure(file_path, raw_type, f"File not found: {file_path}")

    canonical = TYPE_ALIASES.get(raw_type)
    if canonical is None:
        return _failure(file_path, raw_type, f"Unsupported file type: {raw_type}")

    try:
        if canonical == "txt":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read(MAX_TXT_BYTES)
            result = _base_result(file_path, "txt")
            result["visible_text"] = text
            return result

        parsed = DETECTORS[canonical](file_path)
    except Exception as e:
        return _failure(file_path, canonical, f"Parser error ({canonical}): {e}")

    # Guarantee the schema no matter what the detector returned
    result = _base_result(file_path, canonical)
    if isinstance(parsed, dict):
        result.update(parsed)
    result["visible_text"] = result.get("visible_text") or ""
    result["hidden_text"] = result.get("hidden_text") or ""
    result["embedded_scripts"] = result.get("embedded_scripts") or []
    result["metadata"] = result.get("metadata") or {}
    return result


if __name__ == "__main__":
    # Run with: python -m document_engine.document_engine
    print("✓ Document Engine loaded successfully")
    missing = parse_document("does_not_exist.pdf")
    print("Missing file  →", missing.get("parse_failed"), missing.get("error"))
    bad_type = parse_document(__file__, "xyz")
    print("Bad type      →", bad_type.get("parse_failed"), bad_type.get("error"))