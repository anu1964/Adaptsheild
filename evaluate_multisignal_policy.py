"""
evaluate_multisignal_policy.py
--------------------------------
Tests the is_high_confidence_injection() multi-signal decision rule from
input_guard.py against your already-saved layer1_results.csv, as an
alternative to single-threshold r1 cutoffs.

Policy being tested (see input_guard.py for the real definition):
    (pytector_score >= 0.6 AND keyword_score > 0) OR
    (pytector_score >= 0.5 AND llm_guard_score >= 0.5)

This requires at least two independent signals to agree before flagging,
rather than trusting one weighted score. Different failure mode than
threshold sweeping -- worth checking whether it beats the best r1-only
threshold on the same data.
"""

import pandas as pd

df = pd.read_csv("layer1_results.csv")

pred = ((df["pytector_score"] >= 0.6) & (df["keyword_score"] > 0)) | (
    (df["pytector_score"] >= 0.5) & (df["llm_guard_score"] >= 0.5)
)

tp = ((df.true_label) & (pred)).sum()
fn = ((df.true_label) & (~pred)).sum()
fp = ((~df.true_label) & (pred)).sum()
tn = ((~df.true_label) & (~pred)).sum()

recall = tp / max(tp + fn, 1)
fpr = fp / max(fp + tn, 1)
precision = tp / max(tp + fp, 1)
accuracy = (tp + tn) / len(df)

print("Multi-signal policy (requires 2 detectors to agree):")
print(f"  recall={recall:.1%}  fpr={fpr:.1%}  accuracy={accuracy:.1%}  precision={precision:.1%}")
print(f"  tp={tp} fn={fn} fp={fp} tn={tn}")
