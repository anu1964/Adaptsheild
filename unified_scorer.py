"""
unified_scorer.py
Layer 3: Unified Scorer — Fuses R1 + R2 + Divergence into final decision

FIX (this version):
- Divergence floor is now GATED on real evidence. Previously
  `div_floor = divergence * 0.80` applied unconditionally, so a
  divergence of ~0.63 alone (no keyword hits in R1 or R2) reached the
  0.50 BLOCK threshold. Divergence only means "the document's intent
  differs from the user's intent"; it is corroboration, not proof.
- With R1 = R2 = 0, the maximum possible score is now the base fusion
  contribution of divergence (0.25), which stays in SAFE.
"""

# Minimum R1/R2 evidence before divergence is allowed to raise the score
# through the security floor.
EVIDENCE_GATE = 0.20


def calculate_final_decision(r1: float, r2: float, divergence: float) -> dict:
    """
    Fuse Layer 1, Layer 2, and Divergence into a single decision.
    Security floor prevents high-risk layers from being diluted to SAFE,
    but divergence alone can never force a WARN/BLOCK.
    """
    r1 = float(r1)
    r2 = float(r2)
    divergence = float(divergence)

    # Base weighted fusion
    base_score = (r1 * 0.35) + (r2 * 0.40) + (divergence * 0.25)

    # SECURITY FLOOR: any single layer showing strong risk elevates final score
    layer1_floor = r1 * 0.90
    layer2_floor = r2 * 0.90

    # Divergence floor only applies if a detector found real evidence
    evidence = max(r1, r2)
    div_floor = divergence * 0.80 if evidence >= EVIDENCE_GATE else 0.0

    final_score = max(base_score, layer1_floor, layer2_floor, div_floor)
    final_score = min(final_score, 1.0)
    final_score = round(final_score, 3)

    # Decision thresholds
    if final_score < 0.35:
        decision = "SAFE"
    elif final_score < 0.50:
        decision = "WARN"
    else:
        decision = "BLOCK"

    contributors = {
        "layer1": r1 * 0.35,
        "layer2": r2 * 0.40,
        "divergence": divergence * 0.25,
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
            "layer2_floor": round(layer2_floor, 3),
            "div_floor": round(div_floor, 3),
            "div_floor_active": evidence >= EVIDENCE_GATE,
        },
    }


if __name__ == "__main__":
    tests = [
        # (r1, r2, divergence, expected)
        (0.0, 0.0, 0.0, "SAFE"),
        (0.786, 0.0, 0.0, "BLOCK"),
        (0.550, 0.0, 0.0, "WARN"),
        (0.794, 1.0, 1.0, "BLOCK"),
        (0.009, 0.0, 0.0, "SAFE"),
        (0.0, 0.850, 0.900, "BLOCK"),
        (0.300, 0.600, 0.500, "BLOCK"),
        # Regression tests for the false-positive bug:
        (0.0, 0.0, 0.630, "SAFE"),   # divergence alone must NOT block
        (0.0, 0.0, 0.900, "SAFE"),   # even very high divergence alone
        (0.05, 0.0, 0.900, "SAFE"),  # trace R1 noise below evidence gate
        (0.0, 0.250, 0.900, "BLOCK"),  # some real R2 evidence + high divergence
    ]

    print("=== UNIFIED SCORER TESTS ===\n")
    all_ok = True
    for r1, r2, div, expected in tests:
        result = calculate_final_decision(r1, r2, div)
        ok = result["decision"] == expected
        if not ok:
            all_ok = False
        print(f"{'✅' if ok else '❌'} R1={r1:.3f} R2={r2:.3f} Div={div:.3f} "
              f"→ Final={result['final_score']:.3f} [{result['decision']}] (expected {expected})")

    print(f"\n{'ALL TESTS PASSED' if all_ok else 'SOME TESTS FAILED'}")