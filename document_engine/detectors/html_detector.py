"""
html_detector.py
Splits an HTML page into visible text vs hidden text.

Hidden = comments, elements hidden by inline style, by simple <style>
class/id rules, by the `hidden` attribute, or by <template>/<noscript>.
Hidden elements are REMOVED from the tree, so their text never appears
in visible_text (and is never forwarded to the model).
"""

import os
import re
from bs4 import BeautifulSoup, Comment
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

MAX_VISIBLE_CHARS = 20000
HIDDEN_TAGS = {"template", "noscript"}
# Invisible characters used to split keywords. ZWNJ/ZWJ (U+200C/U+200D) are
# deliberately left alone: they are legitimate in Indic and Persian text.
INVISIBLE_RE = re.compile("[\u200b\u2060\ufeff]")


def _parse_decls(text: str) -> dict:
    props = {}
    for decl in (text or "").lower().replace("!important", "").split(";"):
        if ":" in decl:
            k, v = decl.split(":", 1)
            props[k.strip()] = v.strip()
    return props


def _num(value):
    m = re.match(r"\s*(-?\d*\.?\d+)", value or "")
    return float(m.group(1)) if m else None


def _props_hidden(p: dict):
    """Return a reason string if these CSS properties hide the element."""
    if p.get("display") == "none":
        return "display_none"
    if p.get("visibility") in ("hidden", "collapse"):
        return "visibility_hidden"
    opacity = _num(p.get("opacity"))
    if opacity is not None and opacity <= 0.05:
        return "opacity_zero"
    fs = re.match(r"\s*(-?\d*\.?\d+)\s*(px|pt)?", p.get("font-size", ""))
    if fs and (float(fs.group(1)) == 0 or (fs.group(2) and float(fs.group(1)) <= 2)):
        return "tiny_font"
    for key in ("left", "right", "top", "text-indent", "margin-left"):
        n = _num(p.get(key))
        if n is not None and n <= -1000:
            return "offscreen"
    if p.get("overflow") == "hidden" and (_num(p.get("height")) == 0 or _num(p.get("width")) == 0):
        return "zero_size"
    color = p.get("color")
    bg = p.get("background-color") or p.get("background")
    if color and bg and color == bg:
        return "color_matches_background"
    return None


def _hidden_selectors(css_text: str):
    """Very simple stylesheet scan: single .class and #id selectors only."""
    classes, ids = {}, {}
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css_text):
        reason = _props_hidden(_parse_decls(body))
        if not reason:
            continue
        for sel in selectors.split(","):
            sel = sel.strip()
            if re.fullmatch(r"\.[\w-]+", sel):
                classes[sel[1:]] = reason
            elif re.fullmatch(r"#[\w-]+", sel):
                ids[sel[1:]] = reason
    return classes, ids


def _hidden_reason(tag, hidden_classes, hidden_ids):
    if tag.name in HIDDEN_TAGS or tag.has_attr("hidden"):
        return "hidden_element"
    reason = _props_hidden(_parse_decls(tag.get("style") or ""))
    if reason:
        return reason
    for c in tag.get("class") or []:
        if c in hidden_classes:
            return hidden_classes[c]
    return hidden_ids.get(tag.get("id") or "")


def _add_keywords(result, kw):
    for k in kw or []:
        if k not in result.matched_keywords:
            result.matched_keywords.append(k)


def _add_hidden(result, text: str, flag: str):
    text = INVISIBLE_RE.sub("", text)
    result.hidden_text = (result.hidden_text or "") + f"{text}\n"
    result.add_flag(flag)
    kw, _ = HiddenTextDetector.detect_attack_keywords(text)
    _add_keywords(result, kw)


def detect_html_threats(file_path: str) -> dict:
    """Detect threats in HTML files"""
    result = DocumentResult(os.path.basename(file_path), "html")
    result.matched_keywords = []
    result.hidden_flags = []

    # No try/except on purpose: document_engine catches exceptions and marks
    # the result parse_failed, so a broken parse fails closed.
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        html_content = f.read()
    soup = BeautifulSoup(html_content, "html.parser")

    # 1. Comments
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        text = c.strip()
        if text:
            _add_hidden(result, text, "html_comment")
        c.extract()

    # 2. Scripts and styles: read them first, then remove them
    for script in soup.find_all("script"):
        kw, _ = HiddenTextDetector.detect_attack_keywords(script.string or "")
        if kw:
            result.add_flag("embedded_javascript")
            _add_keywords(result, kw)
    css = " ".join((s.string or "") for s in soup.find_all("style"))
    hidden_classes, hidden_ids = _hidden_selectors(css)
    for tag in soup(["script", "style"]):
        tag.decompose()

    # 3. Hidden elements: capture their text, then remove them from the tree
    removed = set()
    for tag in soup.find_all(True):
        if any(id(p) in removed for p in tag.parents):
            continue  # already inside a removed hidden element
        reason = _hidden_reason(tag, hidden_classes, hidden_ids)
        if reason:
            text = tag.get_text(" ", strip=True)
            if text:
                _add_hidden(result, text, f"html_hidden:{reason}")
            removed.add(id(tag))
            tag.extract()

    # 4. Visible text = whatever is left
    visible = soup.get_text(" ", strip=True)
    if HiddenTextDetector.detect_zero_width_chars(html_content) or \
       HiddenTextDetector.detect_zero_width_chars(visible):
        result.hidden_text = (result.hidden_text or "") + "[ZERO_WIDTH_CHARS_DETECTED]\n"
        result.add_flag("zero_width_char")
    result.visible_text = INVISIBLE_RE.sub("", visible)[:MAX_VISIBLE_CHARS]

    # 5. Final keyword pass over everything
    kw, _ = HiddenTextDetector.detect_attack_keywords(
        f"{result.visible_text} {result.hidden_text or ''}"
    )
    _add_keywords(result, kw)

    result.error = None
    return result.to_dict()