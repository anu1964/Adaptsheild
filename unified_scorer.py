"""
AdaptShield - Layer 3: Unified Scorer
Author: Chirayu

Fuses:
  r1          -> Amulya's Layer 1 (prompt risk)
  r2          -> Chirayu's Layer 2B (document risk)
  divergence  -> Chirayu's Layer 2B (intent mismatch)

into a single final decision: SAFE / WARN / BLOCK.
"""

from typing import Optional

# Weights per the team brief: prompt is the primary attack vector,
# document is secondary but critical, divergence is the tie-breaker.
WEIGHT_R1 = 0.35
WEIGHT_R2 = 0.40
WEIGHT_DIVERGENCE = 0.25

THRESHOLD_SAFE_MAX = 0.35   # score < 0.4  -> SAFE
THRESHOLD_WARN_MAX = 0.65  # 0.4 <= score < 0.7 -> WARN, else BLOCK


def calculate_final_decision(r1: float, r2: float, divergence: float) -> dict:
    """
    Returns:
    {
        "final_score": 0.68,
        "decision": "WARN",
        "contributions": {
            "input_risk": 0.4,
            "document_risk": 0.35,
            "divergence": 0.25
        }
    }
    """
    r1 = float(max(0.0, min(1.0, r1 or 0.0)))
    r2 = float(max(0.0, min(1.0, r2 or 0.0)))
    divergence = float(max(0.0, min(1.0, divergence or 0.0)))

    final_score = (r1 * WEIGHT_R1) + (r2 * WEIGHT_R2) + (divergence * WEIGHT_DIVERGENCE)
    final_score = round(final_score, 4)

    if final_score < THRESHOLD_SAFE_MAX:
        decision = "SAFE"
    elif final_score < THRESHOLD_WARN_MAX:
        decision = "WARN"
    else:
        decision = "BLOCK"

    # Absolute (weighted) contribution of each component to the final score,
    # so the dashboard can show which layer drove the decision.
    contributions = {
        "input_risk": round(r1 * WEIGHT_R1, 4),
        "document_risk": round(r2 * WEIGHT_R2, 4),
        "divergence": round(divergence * WEIGHT_DIVERGENCE, 4),
    }

    return {
        "final_score": final_score,
        "decision": decision,
        "contributions": contributions,
    }


def top_contributor(contributions: dict) -> str:
    """Helper for the dashboard: which layer drove the decision most."""
    return max(contributions, key=contributions.get)


def run_full_pipeline(
    user_prompt: str,
    layer1_result: Optional[dict] = None,
    layer2b_result: Optional[dict] = None,
) -> dict:
    """
    Convenience wrapper that fuses Layer 1 + Layer 2B outputs (as-is, no
    re-implementation) into the final decision. Missing layers default to
    zero risk so the app never crashes if only one layer is available.
    """
    r1 = (layer1_result or {}).get("r1", 0.0)
    r2 = (layer2b_result or {}).get("r2", 0.0)
    divergence = (layer2b_result or {}).get("divergence", 0.0)

    result = calculate_final_decision(r1, r2, divergence)
    result["user_prompt"] = user_prompt
    result["layer1"] = layer1_result
    result["layer2b"] = layer2b_result
    return result


if __name__ == "__main__":
    import json
    print(json.dumps(calculate_final_decision(0.85, 0.72, 0.45), indent=2))
    print(json.dumps(calculate_final_decision(0.05, 0.02, 0.10), indent=2))
    print(json.dumps(calculate_final_decision(0.95, 0.90, 0.80), indent=2))
