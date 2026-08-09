import os
import re
import PyPDF2
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_pdf_threats(file_path: str) -> dict:
    """Detect threats in PDF files"""
    result = DocumentResult(os.path.basename(file_path), 'pdf')
    result.matched_keywords = []
    result.hidden_flags = []
    
    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # === EXTRACT TEXT ===
        text_extracted = _extract_pdf_text(file_path)
        result.visible_text = text_extracted[:1000]
        
        # === CHECK FOR ATTACK KEYWORDS ===
        keywords, score = HiddenTextDetector.detect_attack_keywords(text_extracted)
        if keywords:
            result.matched_keywords.extend(keywords)
        
        # === EXTRACT METADATA ===
        result.metadata = _extract_pdf_metadata(file_path)
        
        # Check metadata for keywords
        metadata_str = str(result.metadata).lower()
        meta_kw, _ = HiddenTextDetector.detect_attack_keywords(metadata_str)
        if meta_kw:
            result.matched_keywords.extend(meta_kw)
            result.add_flag('metadata_injection')
        
        # === DETECT WHITE-ON-WHITE (SIZE HEURISTIC) ===
        # Strategy: If file is large but extracted text is small, likely has hidden content
        extracted_size = len(text_extracted)
        if file_size > 10000 and extracted_size < 500:
            # Large file with little extracted text = likely hidden content
            result.add_flag('white_on_white')
        
        # === CHECK RAW PDF STREAM FOR ATTACK PATTERNS ===
        raw_threats = _check_raw_pdf_content(file_path)
        if raw_threats:
            result.hidden_text = raw_threats
            if any(kw in raw_threats.lower() for kw in ['ignore', 'override', 'bypass', 'jailbreak']):
                if 'white_on_white' not in result.hidden_flags:
                    result.add_flag('white_on_white')
        
        # === CHECK FOR JAVASCRIPT ===
        if _has_javascript(file_path):
            result.add_flag('embedded_javascript')
        
        # === NO ERROR ===
        result.error = None
        
    except Exception as e:
        result.error = f"PDF error: {str(e)[:100]}"
    
    return result.to_dict()

def _extract_pdf_text(file_path: str) -> str:
    """Extract ALL text from PDF"""
    text = []
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page_num, page in enumerate(reader.pages):
                try:
                    extracted = page.extract_text()
                    if extracted:
                        text.append(extracted)
                except:
                    pass
    except:
        pass
    
    return "\n".join(text)

def _extract_pdf_metadata(file_path: str) -> dict:
    """Extract PDF metadata"""
    meta = {
        "author": "",
        "creator": "",
        "producer": "",
        "custom_properties": {}
    }
    
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            if reader.metadata:
                meta['author'] = str(reader.metadata.get('/Author', ''))
                meta['creator'] = str(reader.metadata.get('/Creator', ''))
                meta['producer'] = str(reader.metadata.get('/Producer', ''))
    except:
        pass
    
    return meta

def _check_raw_pdf_content(file_path: str) -> str:
    """Check raw PDF stream for suspicious text"""
    suspicious = []
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Look for readable attack keywords in raw PDF
        keywords = [
            b'ignore', b'override', b'bypass', b'jailbreak',
            b'forget', b'disregard', b'disable', b'disable',
            b'developer mode', b'DAN', b'unrestricted'
        ]
        
        for keyword in keywords:
            if keyword in content.lower():
                suspicious.append(keyword.decode('utf-8', errors='ignore'))
    
    except:
        pass
    
    return " ".join(suspicious)

def _has_javascript(file_path: str) -> bool:
    """Check for embedded JavaScript"""
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return b'/JavaScript' in content or b'/OpenAction' in content
    except:
        return False