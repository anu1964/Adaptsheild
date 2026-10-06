import os
from docx import Document
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

TINY_PT = 2.0   # font size at or below this is treated as hidden


def _run_hidden_reason(run):
    """Return 'white_on_white' or 'invisible_layer' if this run is hidden, else None."""
    try:
        if run.font.hidden:                     # Word "hidden text" (w:vanish)
            return "invisible_layer"
        if run.font.size is not None and run.font.size.pt <= TINY_PT:
            return "invisible_layer"            # tiny font
        color = run.font.color
        if color is not None and color.rgb is not None:
            if str(color.rgb).upper() == "FFFFFF":
                return "white_on_white"
    except Exception:
        pass
    return None


def _iter_paragraphs(doc):
    """Body paragraphs, table cells, headers and footers."""
    for p in doc.paragraphs:
        yield p
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    yield p
    for section in doc.sections:
        for part in (section.header, section.footer):
            for p in part.paragraphs:
                yield p


def detect_docx_threats(file_path: str) -> dict:
    """Detect threats in DOCX files"""
    result = DocumentResult(os.path.basename(file_path), 'docx')
    result.matched_keywords = []
    result.hidden_flags = []

    try:
        doc = Document(file_path)
        visible_text, hidden_text = [], []

        # === PER-RUN HIDDEN TEXT CHECK ===
        for para in _iter_paragraphs(doc):
            for run in para.runs:
                text = run.text.strip()
                if not text:
                    continue
                reason = _run_hidden_reason(run)
                if reason:
                    hidden_text.append(text)
                    result.add_flag(reason)
                else:
                    visible_text.append(text)

        full_visible = "\n".join(visible_text)
        result.visible_text = full_visible[:500]
        if hidden_text:
            result.hidden_text = "\n".join(hidden_text)

        # === KEYWORDS IN VISIBLE TEXT (scan the full text, not the truncated copy) ===
        kw, _ = HiddenTextDetector.detect_attack_keywords(full_visible)
        if kw:
            result.matched_keywords.extend(kw)

        # === KEYWORDS IN HIDDEN TEXT ===
        if result.hidden_text:
            kw, _ = HiddenTextDetector.detect_attack_keywords(result.hidden_text)
            if kw:
                result.matched_keywords.extend(kw)

        # === METADATA: check every field ===
        cp = doc.core_properties
        fields = {
            "author": cp.author, "creator": cp.author,   # keep old key for compatibility
            "last_modified_by": cp.last_modified_by,
            "title": cp.title, "subject": cp.subject,
            "keywords": cp.keywords, "comments": cp.comments,
            "category": cp.category,
        }
        for k, v in fields.items():
            result.metadata[k] = v or ""

        meta_str = " ".join(str(v) for v in fields.values() if v).lower()
        meta_kw, _ = HiddenTextDetector.detect_attack_keywords(meta_str)
        if meta_kw:
            result.matched_keywords.extend(meta_kw)
            result.add_flag('metadata_injection')

        result.error = None

    except Exception as e:
        result.error = f"DOCX error: {str(e)[:100]}"

    return result.to_dict()