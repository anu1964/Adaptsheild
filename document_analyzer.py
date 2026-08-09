"""
document_analyzer.py
Layer 2B: Document Analyzer — Intent Divergence Detection
"""

import re
import warnings
warnings.filterwarnings("ignore")

_embedding_model = None

def _get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        from sentence_transformers import SentenceTransformer
        print("[document_analyzer] Loading sentence transformer... (one time)")
        _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        print("[document_analyzer] Model loaded.")
    return _embedding_model

KEYWORDS = [
    "ignore previous", "ignore all previous", "ignore your", "ignore the",
    "disregard", "disregard all", "disregard your", "disregard the",
    "forget your", "forget previous", "forget that", "forget everything",
    "override", "bypass", "disable", "new instructions", "system prompt",
    "developer mode", "admin mode", "root access", "superuser",
    "system override", "override safety", "override protocol",
    "forward to", "send to", "email all", "email to", "send all",
    "forward all", "send records", "customer records", "forward customer",
    "download all", "export data", "leak data", "transmit", "upload to",
    "delete all", "remove all", "wipe", "destroy", "execute",
    "run command", "shell command", "system command", "execute command",
    "jailbreak", "DAN mode", "no restrictions", "no limits",
    "unfiltered", "uncensored", "unrestricted", "no ethical",
    "pretend you are", "roleplay as", "simulate", "imagine you are",
    "you are now", "no longer bound", "do not follow", "override safety",
    "bypass restrictions", "disable filters", "disregard safety",
    "no rules", "without restrictions", "without limits",
]

ACTION_WORDS = ["forward", "send", "email", "delete", "transfer", "download", "execute", "wipe", "destroy", "remove", "transmit", "leak", "export"]


def analyze_document(doc_data: dict, user_prompt: str) -> dict:
    """
    Analyze document for malicious intent and intent divergence.
    """
    
    # Extract text from Vedanth's parser output
    visible = (doc_data.get("visible_text", "") or "").strip()
    hidden = (doc_data.get("hidden_text", "") or "").strip()
    scripts = " ".join(doc_data.get("embedded_scripts", []))
    meta = str(doc_data.get("metadata", {}))
    
    full_text = f"{visible} {hidden} {scripts} {meta}".strip()
    text_lower = full_text.lower()
    
    # --- STEP 1: Keyword detection ---
    matched = [kw for kw in KEYWORDS if kw in text_lower]
    keyword_score = min(len(matched) * 0.25, 1.0)
    
    # Email + action = suspicious
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    has_email = bool(re.search(email_pattern, full_text))
    has_action_and_email = has_email and any(w in text_lower for w in ACTION_WORDS)
    if has_action_and_email:
        keyword_score = max(keyword_score, 0.6)
    
    # --- STEP 2: Determine if suspicious ---
    has_suspicious = (len(matched) > 0) or has_action_and_email or (hidden.strip() != "")
    
    # --- STEP 3: Intent Divergence (only for suspicious docs) ---
    divergence = 0.0
    similarity = 0.5
    
    if has_suspicious:
        try:
            model = _get_embedding_model()
            prompt_emb = model.encode([user_prompt[:500]])
            
            # Compare against hidden text (where attacks live)
            analysis_text = hidden[:1500] if hidden else visible[:1500]
            doc_emb = model.encode([analysis_text])
            
            from sklearn.metrics.pairwise import cosine_similarity
            similarity = float(cosine_similarity(prompt_emb, doc_emb)[0][0])
            divergence = 1.0 - similarity
            
            # Boost if user asked for info but doc wants action
            user_asks_info = any(w in user_prompt.lower() for w in ["summarize", "what", "how", "explain", "describe", "tell me", "help", "who", "when", "where"])
            doc_has_action = any(w in text_lower for w in ACTION_WORDS)
            
            if doc_has_action and user_asks_info:
                divergence = min(divergence + 0.35, 1.0)
            elif doc_has_action:
                divergence = min(divergence + 0.2, 1.0)
                
        except Exception as e:
            print(f"[document_analyzer] Embedding error: {e}")
            divergence = 0.5 if matched else 0.0
    else:
        divergence = 0.0
        similarity = 0.5
    
    # --- STEP 4: R2 ---
    if has_suspicious:
        r2 = (keyword_score * 0.55) + (divergence * 0.45)
    else:
        r2 = 0.0
    
    r2 = min(r2, 1.0)
    
    # --- STEP 5: Flags ---
    flags = []
    if matched:
        flags.append("instruction_override")
    if divergence > 0.5:
        flags.append("intent_divergence")
    if has_action_and_email:
        flags.append("data_exfiltration")
    if hidden:
        flags.append("hidden_content_detected")
    if has_email:
        flags.append("contains_email")
    
    return {
        "r2": round(float(r2), 3),
        "divergence": round(float(divergence), 3),
        "flags": flags,
        "matched_keywords": matched,
        "semantic_similarity": round(float(similarity), 3),
        "detectors": {
            "pytector_score": 0.0,
            "llm_guard_score": 0.0,
            "divergence_score": round(float(divergence), 3)
        }
    }