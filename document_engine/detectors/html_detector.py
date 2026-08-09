import os
import re
from bs4 import BeautifulSoup
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_html_threats(file_path: str) -> dict:
    """Detect threats in HTML files"""
    result = DocumentResult(os.path.basename(file_path), 'html')
    result.matched_keywords = []
    result.hidden_flags = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            html_content = f.read()
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # === EXTRACT VISIBLE TEXT ===
        for tag in soup(["script", "style"]):
            tag.decompose()
        result.visible_text = soup.get_text(strip=True)[:500]
        
        # === CHECK HTML COMMENTS ===
        comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        if comments:
            for comment in comments:
                comment_text = comment.strip()
                if comment_text:
                    result.hidden_text += f"{comment_text}\n"
                    result.add_flag('html_comment')
                    
                    # Check for keywords
                    kw, _ = HiddenTextDetector.detect_attack_keywords(comment_text)
                    if kw:
                        result.matched_keywords.extend(kw)
        
        # === CHECK FOR HIDDEN ELEMENTS ===
        for tag in soup.find_all(True):
            style = (tag.get('style') or '').lower()
            
            # display:none
            if 'display' in style and 'none' in style:
                text = tag.get_text(strip=True)
                if text:
                    result.hidden_text += f"{text}\n"
                    result.add_flag('html_hidden')
                    kw, _ = HiddenTextDetector.detect_attack_keywords(text)
                    if kw:
                        result.matched_keywords.extend(kw)
            
            # visibility:hidden
            if 'visibility' in style and 'hidden' in style:
                text = tag.get_text(strip=True)
                if text:
                    result.hidden_text += f"{text}\n"
                    result.add_flag('html_hidden')
                    kw, _ = HiddenTextDetector.detect_attack_keywords(text)
                    if kw:
                        result.matched_keywords.extend(kw)
        
        # === CHECK FOR ZERO-WIDTH CHARACTERS ===
        if HiddenTextDetector.detect_zero_width_chars(html_content):
            result.hidden_text += "[ZERO_WIDTH_CHARS_DETECTED]\n"
            result.add_flag('zero_width_char')
        
        # === CHECK FOR EMBEDDED SCRIPTS ===
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                kw, _ = HiddenTextDetector.detect_attack_keywords(script.string)
                if kw:
                    result.add_flag('embedded_javascript')
                    result.matched_keywords.extend(kw)
        
        # === FINAL KEYWORD CHECK ===
        all_text = result.visible_text + (result.hidden_text or '')
        kw, _ = HiddenTextDetector.detect_attack_keywords(all_text)
        if kw and kw not in result.matched_keywords:
            result.matched_keywords.extend(kw)
        
        result.error = None
        
    except Exception as e:
        result.error = f"HTML error: {str(e)[:100]}"
    
    return result.to_dict()