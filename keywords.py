"""
keywords.py
------------
Attack-pattern keyword dictionary for AMULYA Layer 1 (Input Guard).

Patterns are grouped by attack category so the scanner can both
(a) compute a keyword-based risk score, and
(b) attach human-readable attack-type flags to the result.

All matching is done case-insensitively and, in input_guard.py, against a
*normalized* version of the prompt (unicode-homoglyph-folded, leetspeak-
folded, whitespace-collapsed) so that trivial obfuscation of these exact
phrases doesn't defeat the keyword layer outright.
"""

# ---------------------------------------------------------------------------
# 1. Instruction override / prompt-hijacking phrases
# ---------------------------------------------------------------------------
INSTRUCTION_OVERRIDE = [
    "ignore all previous instructions",
    "ignore the above",
    "ignore previous instructions",
    "disregard your training",
    "disregard all prior instructions",
    "disregard the above",
    "forget everything above",
    "forget all previous instructions",
    "override your instructions",
    "override your programming",
    "your new instructions are",
    "from now on you will",
    "do not follow your guidelines",
    "bypass your restrictions",
    "bypass your guidelines",
    "this is your new system prompt",
    "new system prompt",
]

# ---------------------------------------------------------------------------
# 2. Role-play / persona / "unlocked" jailbreak personas
# ---------------------------------------------------------------------------
ROLEPLAY_PERSONA = [
    "developer mode",
    "dan mode",
    "you are now",
    "you are now dan",
    "act as dan",
    "you are now in",
    "no restrictions",
    "no filters",
    "no content policy",
    "unfiltered ai",
    "pretend you are",
    "pretend to be",
    "act as if you have no",
    "you have broken free of the typical confines of ai",
    "stay in character",
    "jailbreak",
    "jailbroken",
    "evil confidant",
    "opposite day",
    "do anything now",
    "which stands for",
    "immerse yourself in the role",
    "break character",
    "no longer act as",
    "not bound by",
    "free from the typical rules",
    "have no restrictions",
    "no longer bound",
    "override safety",
    "bypass restrictions",
    "unfiltered mode",
    "uncensored",
    "no limits",
    "free mode",
    "unrestricted access",
]

# ---------------------------------------------------------------------------
# 3. Semantic-disguise / social-engineering framings used to smuggle
#    disallowed requests inside "legitimate" wrappers
# ---------------------------------------------------------------------------
SEMANTIC_DISGUISE = [
    "hypothetical scenario",
    "for educational purposes",
    "for research purposes only",
    "write a story where",
    "write a fictional story",
    "in a fictional world where",
    "purely hypothetically",
    "just hypothetically speaking",
    "as a thought experiment",
    "asking for a friend",
    "this is just a game",
]

# ---------------------------------------------------------------------------
# 4. Encoding / obfuscation evasion cues
# ---------------------------------------------------------------------------
ENCODING_EVASION = [
    "translate to base64",
    "decode this base64",
    "respond in base64",
    "encode your response",
    "rot13",
    "in leetspeak",
    "reverse the following text",
    "answer backwards",
    "using only emojis",
]

# ---------------------------------------------------------------------------
# 5. System-prompt / meta extraction attempts
# ---------------------------------------------------------------------------
SYSTEM_EXTRACTION = [
    "repeat the words above",
    "print your system prompt",
    "reveal your instructions",
    "reveal your system prompt",
    "what are your instructions",
    "output the text above",
    "show me your prompt",
    "leak your prompt",
]

# ---------------------------------------------------------------------------
# Combined flat dictionary: phrase -> attack category
# (used by input_guard.py to build both matched_keywords and flags)
# ---------------------------------------------------------------------------
KEYWORD_CATEGORIES = {
    "instruction_override": INSTRUCTION_OVERRIDE,
    "roleplay_persona": ROLEPLAY_PERSONA,
    "semantic_disguise": SEMANTIC_DISGUISE,
    "encoding_evasion": ENCODING_EVASION,
    "system_extraction": SYSTEM_EXTRACTION,
}

# Flat list of every phrase (>= 30 required by spec; currently 58)
ALL_KEYWORDS = [kw for group in KEYWORD_CATEGORIES.values() for kw in group]

assert len(ALL_KEYWORDS) >= 30, "Keyword dictionary must contain at least 30 patterns"
