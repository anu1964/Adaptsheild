import os
from docx import Document
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_docx_threats(file_path: str) -> dict:
    """Detect threats in DOCX files"""
    result = DocumentResult(os.path.basename(file_path), 'docx')
    result.matched_keywords = []
    result.hidden_flags = []
    
    try:
        doc = Document(file_path)
        
        visible_text = []
        hidden_text = []
        
        # === EXTRACT ALL PARAGRAPHS ===
        for para in doc.paragraphs:
            text = para.text.strip()
            if not text:
                continue
            
            # Check if paragraph is hidden (white font)
            is_hidden = False
            for run in para.runs:
                if run.font.color.rgb:
                    rgb_str = str(run.font.color.rgb).upper()
                    # Check for white (FFFFFF)
                    if 'FFFFFF' in rgb_str or rgb_str == 'FFFFFF':
                        is_hidden = True
                        break
            
            if is_hidden:
                hidden_text.append(text)
                result.add_flag('html_hidden')
            else:
                visible_text.append(text)
        
        result.visible_text = "\n".join(visible_text)[:500]
        if hidden_text:
            result.hidden_text = "\n".join(hidden_text)
        
        # === CHECK FOR KEYWORDS IN VISIBLE ===
        kw, _ = HiddenTextDetector.detect_attack_keywords(result.visible_text)
        if kw:
            result.matched_keywords.extend(kw)
        
        # === CHECK FOR KEYWORDS IN HIDDEN ===
        if result.hidden_text:
            kw, _ = HiddenTextDetector.detect_attack_keywords(result.hidden_text)
            if kw:
                result.matched_keywords.extend(kw)
                if 'html_hidden' not in result.hidden_flags:
                    result.add_flag('html_hidden')
        
        # === CHECK METADATA ===
        result.metadata['author'] = doc.core_properties.author or ""
        result.metadata['creator'] = doc.core_properties.creator or ""
        
        meta_str = str(result.metadata).lower()
        meta_kw, _ = HiddenTextDetector.detect_attack_keywords(meta_str)
        if meta_kw:
            result.add_flag('metadata_injection')
        
        result.error = None
        
    except Exception as e:
        result.error = f"DOCX error: {str(e)[:100]}"
    
    return result.to_dict()