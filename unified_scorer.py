
"""
unified_scorer.py
Layer 3: Unified Scorer
Fuses R1 + R2 + Divergence + Contextual Risk.
"""

EVIDENCE_GATE = 0.20


def calculate_final_decision(
    r1: float,
    r2: float,
    divergence: float,
    contextual_risk: float = 0.0
) -> dict:

    r1 = max(0.0, min(float(r1), 1.0))
    r2 = max(0.0, min(float(r2), 1.0))
    divergence = max(0.0, min(float(divergence), 1.0))

    # Context alone must never cause BLOCK.
    contextual_risk = max(
        0.0, min(float(contextual_risk), 0.49)
    )

    # Base weighted fusion
    base_score = (
        r1 * 0.35 +
        r2 * 0.40 +
        divergence * 0.25
    )

    # Existing security floors
    layer1_floor = r1 * 0.90
    layer2_floor = r2 * 0.90

    evidence = max(r1, r2)

    div_floor = (
        divergence * 0.80
        if evidence >= EVIDENCE_GATE
        else 0.0
    )

    # Contextual risk is an additional scoring signal.
    final_score = max(
        base_score,
        layer1_floor,
        layer2_floor,
        div_floor,
        contextual_risk
    )

    final_score = round(min(final_score, 1.0), 3)

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
        "context": contextual_risk
    }

    return {
        "final_score": final_score,
        "decision": decision,
        "top_contributor": max(
            contributors, key=contributors.get
        ),
        "raw_scores": {
            "r1": r1,
            "r2": r2,
            "divergence": divergence,
            "contextual_risk": contextual_risk,
            "base_fusion": round(base_score, 3),
            "layer1_floor": round(layer1_floor, 3),
            "layer2_floor": round(layer2_floor, 3),
            "div_floor": round(div_floor, 3)
        }
    }


if __name__ == "__main__":

    tests = [
        (0.0, 0.0, 0.0, 0.0, "SAFE"),
        (0.786, 0.0, 0.0, 0.0, "BLOCK"),
        (0.0, 0.0, 0.0, 0.36, "WARN"),
        (0.0, 0.0, 0.0, 0.49, "WARN"),
        (0.0, 0.0, 0.63, 0.0, "SAFE"),
        (0.794, 1.0, 1.0, 0.0, "BLOCK"),
    ]

    print("\n=== UNIFIED SCORER TESTS ===\n")

    all_ok = True

    for r1, r2, div, ctx, expected in tests:

        result = calculate_final_decision(
            r1, r2, div, ctx
        )

        ok = result["decision"] == expected
        all_ok = all_ok and ok

        print(
            f"{'PASS' if ok else 'FAIL'} "
            f"R1={r1:.2f} R2={r2:.2f} "
            f"DIV={div:.2f} CTX={ctx:.2f} "
            f"-> {result['final_score']:.3f} "
            f"[{result['decision']}]"
        )

    print("\nALL TESTS PASSED" if all_ok else "\nTESTS FAILED")
