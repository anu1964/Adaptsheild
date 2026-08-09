import os
import email
import re
from bs4 import BeautifulSoup
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_email_threats(file_path: str) -> dict:
    """Detect threats in email files"""
    result = DocumentResult(os.path.basename(file_path), 'email')
    result.matched_keywords = []
    result.hidden_flags = []
    
    try:
        # Read raw email file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            raw_email = f.read()
        
        # Parse email
        msg = email.message_from_string(raw_email)
        
        result.metadata['author'] = msg.get('From', '')
        
        # === EXTRACT ALL CONTENT ===
        all_text = ""
        html_content = ""
        
        # Get subject
        subject = msg.get('Subject', '')
        all_text += subject + "\n"
        
        # Process body
        if msg.is_multipart():
            for part in msg.iter_parts():
                try:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        text = payload.decode('utf-8', errors='ignore')
                    else:
                        text = str(payload)
                    
                    content_type = part.get_content_type()
                    if content_type == 'text/html':
                        html_content = text
                        all_text += text + "\n"
                    elif content_type == 'text/plain':
                        all_text += text + "\n"
                except Exception as e:
                    pass
        else:
            payload = msg.get_payload()
            if isinstance(payload, bytes):
                all_text += payload.decode('utf-8', errors='ignore')
            else:
                all_text += str(payload)
            
            if msg.get_content_type() == 'text/html':
                html_content = all_text
        
        # === CHECK FOR ATTACK KEYWORDS ===
        keywords, score = HiddenTextDetector.detect_attack_keywords(all_text)
        if keywords:
            result.matched_keywords.extend(keywords)
            if score > 0.2:
                result.add_flag('html_hidden')
        
        # === PARSE HTML IF PRESENT ===
        if html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Remove scripts/styles
                for tag in soup(["script", "style"]):
                    tag.decompose()
                
                result.visible_text = soup.get_text(strip=True)[:500]
                
                # === CHECK HTML COMMENTS ===
                comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
                if comments:
                    comment_text = " ".join(comments)
                    result.hidden_text += comment_text + "\n"
                    result.add_flag('html_comment')
                    
                    # Check comment for keywords
                    kw, _ = HiddenTextDetector.detect_attack_keywords(comment_text)
                    if kw:
                        result.matched_keywords.extend(kw)
                
                # === CHECK FOR HIDDEN DIVS ===
                for tag in soup.find_all(True):
                    style = (tag.get('style') or '').lower()
                    
                    if 'display:none' in style or 'display: none' in style:
                        text = tag.get_text(strip=True)
                        if text:
                            result.hidden_text += f"[HIDDEN] {text}\n"
                            result.add_flag('html_hidden')
                            kw, _ = HiddenTextDetector.detect_attack_keywords(text)
                            if kw:
                                result.matched_keywords.extend(kw)
                    
                    if 'visibility:hidden' in style or 'visibility: hidden' in style:
                        text = tag.get_text(strip=True)
                        if text:
                            result.hidden_text += f"[HIDDEN] {text}\n"
                            result.add_flag('html_hidden')
                            kw, _ = HiddenTextDetector.detect_attack_keywords(text)
                            if kw:
                                result.matched_keywords.extend(kw)
                
                # === CHECK FOR ZERO-WIDTH CHARS ===
                if HiddenTextDetector.detect_zero_width_chars(html_content):
                    result.add_flag('zero_width_char')
                
            except Exception as e:
                pass
        
        # === FINAL CHECK: No errors ===
        result.error = None
        
    except Exception as e:
        result.error = f"Email error: {str(e)[:100]}"
    
    return result.to_dict()