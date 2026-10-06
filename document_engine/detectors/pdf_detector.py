import os
import PyPDF2
from PyPDF2.generic import ContentStream
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

TINY_PT = 2.0


def _is_white(op, operands):
    try:
        v = [float(x) for x in operands]
        if op == "rg" and len(v) == 3:
            return all(c >= 0.95 for c in v)
        if op == "g" and len(v) == 1:
            return v[0] >= 0.95
        if op == "k" and len(v) == 4:
            return all(c <= 0.05 for c in v)   # CMYK 0 0 0 0 = white
    except Exception:
        pass
    return None   # not a colour operator we understand


def _text_of(op, operands):
    try:
        if op in ("Tj", "'", '"'):
            return str(operands[-1])
        if op == "TJ":
            return "".join(str(x) for x in operands[0] if not isinstance(x, (int, float)))
    except Exception:
        pass
    return ""


def _scan_page(page, reader):
    """Walk the decompressed content stream, tracking colour, font size, render mode."""
    hidden, flags = [], set()
    contents = page.get_contents()
    if contents is None:
        return hidden, flags
    ops = getattr(contents, "operations", None)
    if ops is None:
        ops = ContentStream(contents, reader).operations

    white, size, mode = False, 12.0, 0
    stack = []
    for operands, op in ops:
        op = op.decode() if isinstance(op, bytes) else op
        if op == "q":
            stack.append((white, size, mode))
        elif op == "Q" and stack:
            white, size, mode = stack.pop()
        elif op in ("rg", "g", "k"):
            w = _is_white(op, operands)
            if w is not None:
                white = w
        elif op == "Tf" and len(operands) == 2:
            try: size = abs(float(operands[1]))
            except Exception: pass
        elif op == "Tr" and operands:
            try: mode = int(operands[0])
            except Exception: pass
        elif op in ("Tj", "TJ", "'", '"'):
            txt = _text_of(op, operands).strip()
            if not txt:
                continue
            if white:
                hidden.append(txt); flags.add("white_on_white")
            elif size <= TINY_PT:
                hidden.append(txt); flags.add("invisible_layer")
            elif mode == 3:                      # invisible render mode
                hidden.append(txt); flags.add("invisible_layer")
    return hidden, flags


def detect_pdf_threats(file_path: str) -> dict:
    result = DocumentResult(os.path.basename(file_path), 'pdf')
    result.matched_keywords = []
    result.hidden_flags = []

    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)

            # === TEXT + CONTENT-STREAM SCAN ===
            all_text, hidden_text = [], []
            for page in reader.pages:
                try:
                    t = page.extract_text()
                    if t: all_text.append(t)
                except Exception:
                    pass
                try:
                    h, fl = _scan_page(page, reader)
                    hidden_text.extend(h)
                    for flag in fl:
                        result.add_flag(flag)
                except Exception:
                    pass

            # === METADATA: every key, including custom ones ===
            meta = {"author": "", "creator": "", "producer": "", "custom_properties": {}}
            md = reader.metadata or {}
            for k, v in md.items():
                key = str(k).lstrip("/")
                if key.lower() in ("author", "creator", "producer"):
                    meta[key.lower()] = str(v)
                else:
                    meta["custom_properties"][key] = str(v)
            result.metadata = meta

            has_js = "/JavaScript" in str(reader.trailer.get("/Root", {})) or False

        text_extracted = "\n".join(all_text)
        result.visible_text = text_extracted[:1000]
        if hidden_text:
            result.hidden_text = "\n".join(hidden_text)

        # === KEYWORDS: body, hidden text, metadata ===
        kw, _ = HiddenTextDetector.detect_attack_keywords(text_extracted)
        result.matched_keywords.extend(kw)

        meta_vals = " ".join([meta["author"], meta["creator"], meta["producer"]]
                             + list(meta["custom_properties"].values()))
        mkw, _ = HiddenTextDetector.detect_attack_keywords(meta_vals)
        if mkw:
            result.matched_keywords.extend(mkw)
            result.add_flag('metadata_injection')

        if HiddenTextDetector.detect_zero_width_chars(text_extracted):
            result.add_flag('zero_width_char')

        # === JAVASCRIPT ===
        with open(file_path, 'rb') as f:
            raw = f.read()
        if b'/JavaScript' in raw or b'/JS' in raw or b'/OpenAction' in raw:
            result.add_flag('embedded_javascript')

        result.error = None

    except Exception as e:
        result.error = f"PDF error: {str(e)[:100]}"

    return result.to_dict()