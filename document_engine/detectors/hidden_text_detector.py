import re
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
