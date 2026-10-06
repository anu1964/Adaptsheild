import re
from typing import List, Tuple


class HiddenTextDetector:
    ATTACK_KEYWORDS = [
        "ignore previous", "ignore all previous", "ignore your", "ignore the above",
        "disregard previous", "disregard all", "disregard your", "disregard the above",
        "bypass restrictions", "bypass safety", "bypass authentication",
        "override safety", "override protocol", "system override",
        "jailbreak", "developer mode", "dan mode",
        "no restrictions", "without restrictions",
        "forget your", "forget previous", "forget everything",
        "don't follow", "do not follow", "instead you",
        "actually you should", "real instructions", "the real instruction",
        "forward to", "send to", "exfiltrate",
        "escalate privileges", "sudo", "root access",
        "api key", "reveal your password", "reveal the password",
    ]

    # Whole-word/phrase matching, so "sudo" no longer matches "pseudocode".
    _KEYWORD_PATTERNS = [
        (kw, re.compile(r"(?<!\w)" + re.escape(kw) + r"(?!\w)", re.IGNORECASE))
        for kw in ATTACK_KEYWORDS
    ]
    _REGEX_PATTERNS = [
        ("instruction_override", re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b(?:\W+\w+){0,3}?\W+"
            r"(instructions|rules|prompt|guidelines|directions|restrictions|safeguards|policies)\b",
            re.IGNORECASE)),
        ("secret_exfiltration", re.compile(
            r"\b(reveal|output|print|leak)\b(?:\W+\w+){0,3}?\W+"
            r"(password|system prompt|hidden prompt|credentials)\b",
            re.IGNORECASE)),
    ]

    # Characters that are invisible and rarely appear in honest text:
    # zero-width space, word joiner, BOM (in the middle of text), and the
    # Unicode "tag" block used for ASCII smuggling.
    _ZW_ALWAYS = re.compile("[\u200b\u2060\ufeff\U000e0000-\U000e007f]")
    # ZWNJ/ZWJ are normal in Indic/Persian scripts and emoji, so they only
    # count when sandwiched between two ASCII letters (e.g. "ig<ZWJ>nore").
    _ZW_IN_WORD = re.compile("(?<=[A-Za-z])[\u200c\u200d](?=[A-Za-z])")
    _REGEX_PATTERNS = [
        ("instruction_override", re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b(?:\W+\w+){0,3}?\W+"
            r"(instructions|rules|prompt|guidelines|directions|restrictions|safeguards|policies)\b",
            re.IGNORECASE)),
        ("secret_exfiltration", re.compile(
            r"\b(reveal|output|print|leak)\b(?:\W+\w+){0,3}?\W+"
            r"(password|system prompt|hidden prompt|credentials)\b",
            re.IGNORECASE)),
    ]
    
    @staticmethod
    def detect_attack_keywords(text: str) -> Tuple[List[str], float]:
        text = text or ""
        matched = [kw for kw, pat in HiddenTextDetector._KEYWORD_PATTERNS if pat.search(text)]
        matched += [label for label, pat in HiddenTextDetector._REGEX_PATTERNS if pat.search(text)]
        score = min(len(matched) / 5.0, 1.0)
        return matched, score

    @staticmethod
    def detect_zero_width_chars(text: str) -> bool:
        text = (text or "").lstrip("\ufeff")  # a leading BOM is normal
        return bool(
            HiddenTextDetector._ZW_ALWAYS.search(text)
            or HiddenTextDetector._ZW_IN_WORD.search(text)
        )

    @staticmethod
    def detect_html_comments(html_text: str) -> Tuple[List[str], bool]:
        comments = re.findall(r'<!--(.*?)-->', html_text, re.DOTALL)
        return comments, len(comments) > 0