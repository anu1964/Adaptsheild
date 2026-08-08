"""
threshold_tuning.py
--------------------
Reads an already-generated layer1_results.csv (from test_layer1.py) and
sweeps the r1 risk threshold to find the cutoff that maximizes accuracy /
best balances detection rate vs false positive rate.

No re-scanning needed -- this just re-evaluates the r1 scores you already
have on disk against different thresholds.

Usage:
    python threshold_tuning.py
"""

import pandas as pd

df = pd.read_csv("layer1_results.csv")

lines = []
lines.append(f"{'threshold':>10} {'recall':>10} {'fpr':>10} {'accuracy':>10} {'precision':>10}")
lines.append("-" * 55)

best = None
best_accuracy_overall = None
for t in [round(x * 0.01, 2) for x in range(1, 100, 1)]:
    pred = df["r1"] >= t
    tp = ((df.true_label) & (pred)).sum()
    fn = ((df.true_label) & (~pred)).sum()
    fp = ((~df.true_label) & (pred)).sum()
    tn = ((~df.true_label) & (~pred)).sum()

    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    precision = tp / max(tp + fp, 1)
    accuracy = (tp + tn) / len(df)

    lines.append(f"{t:>10.2f} {recall:>9.1%} {fpr:>9.1%} {accuracy:>9.1%} {precision:>9.1%}")

    meets_target = recall >= 0.85 and fpr < 0.15
    score = accuracy if meets_target else -1
    if best is None or (meets_target and score > best[1]):
        best = (t, score, recall, fpr, accuracy)

    if best_accuracy_overall is None or accuracy > best_accuracy_overall[4]:
        best_accuracy_overall = (t, None, recall, fpr, accuracy)

lines.append("")
if best and best[1] != -1:
    t, _, recall, fpr, accuracy = best
    lines.append(f"Best threshold meeting targets (recall>=85%, FPR<15%): {t}")
    lines.append(f"  -> recall={recall:.1%}  fpr={fpr:.1%}  accuracy={accuracy:.1%}")
else:
    lines.append("No threshold in this sweep met BOTH recall>=85% and FPR<15% simultaneously.")
    lines.append("Best OVERALL ACCURACY threshold instead (may not meet both targets):")
    t, _, recall, fpr, accuracy = best_accuracy_overall
    lines.append(f"  threshold={t}  recall={recall:.1%}  fpr={fpr:.1%}  accuracy={accuracy:.1%}")

output = "\n".join(lines)
print(output)

with open("threshold_sweep_results.txt", "w") as f:
    f.write(output + "\n")
print("\nFull table also saved to threshold_sweep_results.txt")
