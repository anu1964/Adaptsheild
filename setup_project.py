"""
Complete project setup - creates all files at once
Run once: python setup_project.py
"""

import os
import sys

files = {
    "requirements.txt": "PyPDF2==3.0.1\npdfplumber==0.10.3\npython-docx==0.8.11\nbeautifulsoup4==4.12.2\nreportlab==4.0.9\n",
    
    "document_engine/__init__.py": "from .document_engine import parse_document\n\n__all__ = ['parse_document']\n",
    
    "document_engine/utils/__init__.py": "from .helpers import DocumentResult, save_result_json\n\n__all__ = ['DocumentResult', 'save_result_json']\n",
    
    "document_engine/detectors/__init__.py": "# Detectors module\n",
    
    "document_engine/utils/helpers.py": """import os
import json
from datetime import datetime

class DocumentResult:
    def __init__(self, source_file: str, file_type: str):
        self.source_file = source_file
        self.file_type = file_type
        self.visible_text = ""
        self.hidden_text = ""
        self.metadata = {
            "author": "",
            "creator": "",
            "producer": "",
            "custom_properties": {}
        }
        self.embedded_scripts = []
        self.hidden_flags = []
        self.images_found = 0
        self.suspicious_images = []
        self.error = None
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "file_type": self.file_type,
            "visible_text": self.visible_text[:2000] if self.visible_text else "",
            "hidden_text": self.hidden_text,
            "metadata": self.metadata,
            "embedded_scripts": self.embedded_scripts,
            "hidden_flags": self.hidden_flags,
            "images_found": self.images_found,
            "suspicious_images": self.suspicious_images,
            "error": self.error,
            "timestamp": self.timestamp
        }
    
    def add_flag(self, flag: str):
        if flag not in self.hidden_flags:
            self.hidden_flags.append(flag)
    
    def add_script(self, script: str):
        self.embedded_scripts.append(script)

def save_result_json(result: DocumentResult, output_path: str):
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    print(f"✓ Saved result to {output_path}")
""",

    "document_engine/detectors/hidden_text_detector.py": """import re
from typing import List, Tuple

class HiddenTextDetector:
    ATTACK_KEYWORDS = [
        "ignore previous", "ignore all previous", "disregard",
        "bypass", "override", "jailbreak", "developer mode",
        "DAN mode", "no restrictions", "unrestricted",
        "forget", "don't follow", "instead you",
        "actually you should", "real instructions",
        "forward to", "send to", "exfiltrate",
        "escalate privileges", "sudo", "root",
        "password", "secret", "api key", "token"
    ]
    
    @staticmethod
    def detect_attack_keywords(text: str) -> Tuple[List[str], float]:
        text_lower = text.lower()
        matched = []
        
        for keyword in HiddenTextDetector.ATTACK_KEYWORDS:
            if keyword in text_lower:
                matched.append(keyword)
        
        score = min(len(matched) / 5.0, 1.0)
        return matched, score
    
    @staticmethod
    def detect_html_comments(html_text: str) -> Tuple[List[str], bool]:
        comments = re.findall(r'<!--(.*?)-->', html_text, re.DOTALL)
        has_comments = len(comments) > 0
        return comments, has_comments
""",

    "document_engine/detectors/pdf_detector.py": """import os
import PyPDF2
import pdfplumber
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_pdf_threats(file_path: str) -> dict:
    result = DocumentResult(os.path.basename(file_path), 'pdf')
    
    try:
        result.visible_text = _extract_visible_text_pypdf2(file_path)
        metadata = _extract_pdf_metadata(file_path)
        result.metadata = metadata
        
        all_text = result.visible_text
        keywords, _ = HiddenTextDetector.detect_attack_keywords(all_text)
        if keywords:
            result.add_flag('attack_keywords_detected')
        
    except Exception as e:
        result.error = f"PDF parsing error: {str(e)}"
    
    return result.to_dict()

def _extract_visible_text_pypdf2(file_path: str) -> str:
    visible_text = []
    try:
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page_num, page in enumerate(reader.pages):
                text = page.extract_text()
                if text:
                    visible_text.append(f"[PAGE {page_num + 1}]\\n{text}")
    except Exception as e:
        print(f"PyPDF2 extraction warning: {e}")
    
    return "\\n".join(visible_text)

def _extract_pdf_metadata(file_path: str) -> dict:
    metadata = {
        "author": "",
        "creator": "",
        "producer": "",
        "custom_properties": {}
    }
    
    try:
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            if reader.metadata:
                metadata['author'] = str(reader.metadata.get('/Author', ''))
                metadata['creator'] = str(reader.metadata.get('/Creator', ''))
                metadata['producer'] = str(reader.metadata.get('/Producer', ''))
    except Exception as e:
        print(f"Metadata extraction warning: {e}")
    
    return metadata
""",

    "document_engine/detectors/email_detector.py": """import os
import email
from email.policy import default
from bs4 import BeautifulSoup
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_email_threats(file_path: str) -> dict:
    result = DocumentResult(os.path.basename(file_path), 'email')
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=default)
        
        result.metadata['author'] = msg.get('From', '')
        result.metadata['subject'] = msg.get('Subject', '')
        
        _extract_email_body(msg, result)
        
        keywords, _ = HiddenTextDetector.detect_attack_keywords(result.hidden_text)
        if keywords:
            result.add_flag('attack_keywords')
        
    except Exception as e:
        result.error = f"Email parsing error: {str(e)}"
    
    return result.to_dict()

def _extract_email_body(msg: email.message.Message, result: DocumentResult):
    if msg.is_multipart():
        for part in msg.iter_parts():
            content_type = part.get_content_type()
            
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    result.visible_text += payload.decode('utf-8', errors='ignore')
            
            elif content_type == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    html_content = payload.decode('utf-8', errors='ignore')
                    visible, hidden = _parse_html_email(html_content)
                    result.visible_text += visible
                    result.hidden_text += hidden
    else:
        if msg.get_content_type() == 'text/html':
            html_content = msg.get_payload(decode=True)
            if isinstance(html_content, bytes):
                html_content = html_content.decode('utf-8', errors='ignore')
            visible, hidden = _parse_html_email(html_content)
            result.visible_text = visible
            result.hidden_text = hidden
        else:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                result.visible_text = payload.decode('utf-8', errors='ignore')

def _parse_html_email(html_content: str) -> tuple:
    soup = BeautifulSoup(html_content, 'html.parser')
    
    visible_parts = []
    hidden_parts = []
    
    for tag in soup.find_all(True):
        style = tag.get('style', '').lower()
        text = tag.get_text(strip=True)
        if not text:
            continue
        
        is_hidden = False
        
        if 'display' in style and 'none' in style:
            is_hidden = True
        elif 'visibility' in style and 'hidden' in style:
            is_hidden = True
        
        if is_hidden:
            hidden_parts.append(text)
        else:
            visible_parts.append(text)
    
    return '\\n'.join(visible_parts), '\\n'.join(hidden_parts)
""",

    "document_engine/detectors/html_detector.py": """import os
from bs4 import BeautifulSoup
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_html_threats(file_path: str) -> dict:
    result = DocumentResult(os.path.basename(file_path), 'html')
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            html_content = f.read()
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        result.visible_text = _extract_visible_text(soup)
        
        hidden_text, hidden_flags = _extract_hidden_elements(soup)
        if hidden_text:
            result.hidden_text = hidden_text
            result.hidden_flags.extend(hidden_flags)
        
        comments = _extract_html_comments(html_content)
        if comments:
            result.hidden_text += '\\n[HTML_COMMENTS]\\n' + '\\n'.join(comments)
            result.add_flag('html_comments')
        
        keywords, _ = HiddenTextDetector.detect_attack_keywords(result.hidden_text)
        if keywords:
            result.add_flag('attack_keywords')
        
    except Exception as e:
        result.error = f"HTML parsing error: {str(e)}"
    
    return result.to_dict()

def _extract_visible_text(soup) -> str:
    for script in soup(['script', 'style']):
        script.decompose()
    
    text = soup.get_text()
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    return '\\n'.join(chunk for chunk in chunks if chunk)

def _extract_hidden_elements(soup) -> tuple:
    hidden_texts = []
    flags = set()
    
    for tag in soup.find_all(True):
        style = tag.get('style', '').lower()
        
        if 'display:none' in style or 'display: none' in style:
            text = tag.get_text(strip=True)
            if text:
                hidden_texts.append(f"[display:none] {text}")
                flags.add('html_display_none')
        
        elif 'visibility:hidden' in style or 'visibility: hidden' in style:
            text = tag.get_text(strip=True)
            if text:
                hidden_texts.append(f"[visibility:hidden] {text}")
                flags.add('html_visibility_hidden')
    
    return '\\n'.join(hidden_texts), list(flags)

def _extract_html_comments(html_content: str) -> list:
    import re
    comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
    return [comment.strip() for comment in comments if comment.strip()]
""",

    "document_engine/detectors/docx_detector.py": """import os
from docx import Document
from ..utils.helpers import DocumentResult
from .hidden_text_detector import HiddenTextDetector

def detect_docx_threats(file_path: str) -> dict:
    result = DocumentResult(os.path.basename(file_path), 'docx')
    
    try:
        doc = Document(file_path)
        
        result.visible_text = _extract_visible_text(doc)
        
        result.metadata['author'] = doc.core_properties.author or ""
        result.metadata['creator'] = doc.core_properties.creator or ""
        result.metadata['subject'] = doc.core_properties.subject or ""
        
        keywords, _ = HiddenTextDetector.detect_attack_keywords(result.visible_text)
        if keywords:
            result.add_flag('attack_keywords')
        
    except Exception as e:
        result.error = f"DOCX parsing error: {str(e)}"
    
    return result.to_dict()

def _extract_visible_text(doc) -> str:
    paragraphs = []
    for para in doc.paragraphs:
        text = para.text.strip()
        if text:
            paragraphs.append(text)
    return '\\n'.join(paragraphs)
""",

    "document_engine/document_engine.py": """import os
from typing import Dict
from .detectors.pdf_detector import detect_pdf_threats
from .detectors.email_detector import detect_email_threats
from .detectors.html_detector import detect_html_threats
from .detectors.docx_detector import detect_docx_threats
from .utils.helpers import DocumentResult

def parse_document(file_path: str, file_type: str) -> Dict:
    if not os.path.isfile(file_path):
        return {
            "error": f"File not found: {file_path}",
            "source_file": file_path,
            "file_type": file_type
        }
    
    file_type = file_type.lower().strip()
    
    if file_type == 'pdf':
        return detect_pdf_threats(file_path)
    elif file_type in ['email', 'eml', 'msg']:
        return detect_email_threats(file_path)
    elif file_type in ['html', 'htm']:
        return detect_html_threats(file_path)
    elif file_type in ['docx', 'doc']:
        return detect_docx_threats(file_path)
    else:
        return {"error": f"Unsupported file type: {file_type}"}

if __name__ == "__main__":
    print("✓ Document Engine loaded successfully")
""",
}

print("Creating all project files...")
print("=" * 60)

for file_path, content in files.items():
    os.makedirs(os.path.dirname(file_path) or '.', exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"✓ {file_path}")

print("=" * 60)
print("✓ All files created successfully!")