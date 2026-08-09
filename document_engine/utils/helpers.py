import os
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
        """Add a flag, ensuring it's in the valid 8-flag list"""
        VALID_FLAGS = {
            "white_on_white",
            "invisible_layer", 
            "metadata_injection",
            "embedded_javascript",
            "html_hidden",
            "html_comment",
            "zero_width_char",
            "font_subsetting"
        }
    
        # Normalize flag names to standard set
        flag_lower = flag.lower()
    
        # Map any non-standard names to official names
        if 'html_visibility_hidden' in flag_lower or 'html_display_none' in flag_lower:
            flag = 'html_hidden'
        elif 'attack_keywords' in flag_lower:
            flag = 'html_hidden'
    
        # Only add if it's a valid flag
        if flag in VALID_FLAGS and flag not in self.hidden_flags:
            self.hidden_flags.append(flag)
    
    def add_script(self, script: str):
        self.embedded_scripts.append(script)

def save_result_json(result: DocumentResult, output_path: str):
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    print(f"✓ Saved result to {output_path}")
