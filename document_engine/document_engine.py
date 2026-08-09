import os
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
