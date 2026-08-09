# AdaptShield — Chirayu's Modules (Layer 3 only)

Files in this folder:

| File | Layer | Purpose |
|---|---|---|
| `unified_scorer.py` | 3 | Fuses `r1` (Amulya, Layer 1) + `r2`/`divergence` (teammate, Layer 2B) into final SAFE/WARN/BLOCK decision |
| `app.py` | 3 | Streamlit dashboard — 3 screens (Input Testing, Document Testing, Full Pipeline) |
| `requirements.txt` | — | Dependencies for the full project (all layers, so the team can share one file) |

## Setup

```bash
pip install -r requirements.txt
```

## Run tests

```bash
python3 unified_scorer.py   # smoke test fusion logic
```

## Run the dashboard

```bash
streamlit run app.py
```

The app auto-detects whether `input_guard.py` (Amulya, Layer 1),
`document_engine.py` (Vedanth, Layer 2A), and `document_analyzer.py`
(teammate, Layer 2B) exist in the same folder. Drop those files in
alongside these and all three tabs light up — the app runs fine even if
a module is still missing, it just shows a warning for that section
instead of crashing.

## Fusion logic (Layer 3)

```
final_score = (r1 * 0.40) + (r2 * 0.35) + (divergence * 0.25)

score < 0.4        -> SAFE
0.4 <= score < 0.7  -> WARN
score >= 0.7        -> BLOCK
```

## Integration contract (unchanged from the team brief)

```
Chirayu (Layer 3) receives:
  r1 from Amulya:          {"r1": 0.85, "flags": [...], "detectors": {...}, "matched_keywords": [...]}
  r2/divergence from Layer 2B: {"r2": 0.72, "divergence": 0.45, "flags": [...], "matched_keywords": [...], "semantic_similarity": 0.35}

Chirayu (Layer 3) outputs -> The World sees:
{"final_score": 0.68, "decision": "WARN", "contributions": {...}}
```
