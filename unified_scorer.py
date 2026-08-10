"""
unified_scorer.py
Layer 3: Unified Scorer — Fuses R1 + R2 + Divergence into final decision
Fix: Any layer showing high confidence elevates the final score
"""

def calculate_final_decision(r1: float, r2: float, divergence: float) -> dict:
    """
    Fuse Layer 1, Layer 2, and Divergence into a single decision.
    Security floor prevents high-risk layers from being diluted to SAFE.
    """
    r1 = float(r1)
    r2 = float(r2)
    divergence = float(divergence)
    
    # Base weighted fusion
    base_score = (r1 * 0.35) + (r2 * 0.40) + (divergence * 0.25)
    
    # SECURITY FLOOR: Any single layer showing strong risk elevates final score
    layer1_floor = r1 * 0.90
    layer2_floor = r2 * 0.90
    div_floor = divergence * 0.80
    
    final_score = max(base_score, layer1_floor, layer2_floor, div_floor)
    final_score = min(final_score, 1.0)
    final_score = round(final_score, 3)
    
    # Decision thresholds (adjusted for security floor)
    if final_score < 0.35:
        decision = "SAFE"
    elif final_score < 0.50:   # Lowered from 0.70 → 0.50
        decision = "WARN"
    else:
        decision = "BLOCK"
    
    contributors = {
        "layer1": r1 * 0.35,
        "layer2": r2 * 0.40,
        "divergence": divergence * 0.25
    }
    top_contributor = max(contributors, key=contributors.get)
    
    return {
        "final_score": final_score,
        "decision": decision,
        "top_contributor": top_contributor,
        "raw_scores": {
            "r1": r1,
            "r2": r2,
            "divergence": divergence,
            "base_fusion": round(base_score, 3),
            "layer1_floor": round(layer1_floor, 3),
            "layer2_floor": round(layer2_floor, 3)
        }
    }


if __name__ == "__main__":
    tests = [
        (0.0, 0.0, 0.0, "SAFE"),
        (0.786, 0.0, 0.0, "BLOCK"),
        (0.550, 0.0, 0.0, "WARN"),
        (0.794, 1.0, 1.0, "BLOCK"),
        (0.009, 0.0, 0.0, "SAFE"),
        (0.0, 0.850, 0.900, "BLOCK"),
        (0.300, 0.600, 0.500, "BLOCK"),
    ]
    
    print("=== UNIFIED SCORER TESTS ===\n")
    all_ok = True
    for r1, r2, div, expected in tests:
        result = calculate_final_decision(r1, r2, div)
        ok = result["decision"] == expected
        if not ok:
            all_ok = False
        print(f"{'✅' if ok else '❌'} R1={r1:.3f} R2={r2:.3f} Div={div:.3f} → Final={result['final_score']:.3f} [{result['decision']}] (expected {expected})")
    
    print(f"\n{'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}")