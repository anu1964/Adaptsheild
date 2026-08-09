"""
train_fallback_models.py
-------------------------
Trains the two OFFLINE fallback classifiers used by input_guard.py when the
real Pytector / LLM Guard transformer weights can't be downloaded (no
huggingface.co access in this sandbox).

These are deliberately classical, lightweight, CPU-only models -- NOT a
transformer built from scratch (explicitly out of scope per the brief):

  - fallback_pytector.pkl : TF-IDF (word 1-2 grams) + Logistic Regression
        stands in for Pytector's transformer classifier.
  - fallback_llm_guard.pkl: TF-IDF (char 3-5 grams, word-boundary) + Naive
        Bayes stands in for LLM Guard's scanner. Character n-grams make
        this signal meaningfully different from the word-level model above
        (it's more robust to spacing/punctuation obfuscation), which is
        the point of ensembling two distinct detectors rather than
        computing the same score twice.

IMPORTANT - train/test hygiene:
This script creates a fixed, seeded 70/30 train/test split of the
verazuo/jailbreak_llms corpus and trains ONLY on the 70% train partition.
test_layer1.py evaluates ONLY on the 30% test partition (same seed, same
split logic) so the validation numbers in layer1_summary.txt are computed
on data neither fallback model has ever seen -- not memorized training
data.
"""

import os
import pickle
import random

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(HERE, "jailbreak_llms", "data", "prompts")
JAILBREAK_CSV = os.path.join(DATA_DIR, "jailbreak_prompts_2023_12_25.csv")
BENIGN_CSV = os.path.join(DATA_DIR, "regular_prompts_2023_12_25.csv")

MODELS_DIR = os.path.join(HERE, "models")
SPLIT_SEED = 42
TEST_SIZE = 0.30
MAX_PROMPT_CHARS = 4000

# Cap benign examples so the training set isn't ~10x skewed toward benign
# (13.7k benign vs 1.4k jailbreak) -- keeps class balance reasonable while
# still giving the vectorizer/classifier a large, varied benign vocabulary
# to drive the false-positive rate down.
MAX_BENIGN_FOR_TRAINING = 8000


def load_full_labeled_corpus():
    jb_df = pd.read_csv(JAILBREAK_CSV)
    ben_df = pd.read_csv(BENIGN_CSV)

    jb_texts = jb_df["prompt"].dropna().astype(str).str.slice(0, MAX_PROMPT_CHARS).tolist()
    ben_texts = ben_df["prompt"].dropna().astype(str).str.slice(0, MAX_PROMPT_CHARS).tolist()

    random.seed(SPLIT_SEED)
    random.shuffle(ben_texts)
    ben_texts = ben_texts[:MAX_BENIGN_FOR_TRAINING]

    texts = jb_texts + ben_texts
    labels = [1] * len(jb_texts) + [0] * len(ben_texts)
    return texts, labels


def make_split(texts, labels):
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=TEST_SIZE, random_state=SPLIT_SEED, stratify=labels
    )
    return x_train, x_test, y_train, y_test


def train_and_save():
    os.makedirs(MODELS_DIR, exist_ok=True)
    texts, labels = load_full_labeled_corpus()
    x_train, x_test, y_train, y_test = make_split(texts, labels)

    print(f"Train: {len(x_train)} ({sum(y_train)} jailbreak / {len(y_train) - sum(y_train)} benign)")
    print(f"Test : {len(x_test)} ({sum(y_test)} jailbreak / {len(y_test) - sum(y_test)} benign) [held out]")

    # ---- Model A: word TF-IDF + Logistic Regression (Pytector stand-in) ----
    vec_a = TfidfVectorizer(ngram_range=(1, 3), min_df=2, max_features=60000, sublinear_tf=True)
    xa_train = vec_a.fit_transform(x_train)
    clf_a = LogisticRegression(max_iter=3000, C=5.0, class_weight="balanced")
    clf_a.fit(xa_train, y_train)

    with open(os.path.join(MODELS_DIR, "fallback_pytector.pkl"), "wb") as f:
        pickle.dump({"vectorizer": vec_a, "model": clf_a}, f)

    # ---- Model B: char n-gram TF-IDF + Naive Bayes (LLM Guard stand-in) ----
    vec_b = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, max_features=60000)
    xb_train = vec_b.fit_transform(x_train)
    clf_b = MultinomialNB(alpha=0.1)
    clf_b.fit(xb_train, y_train)

    with open(os.path.join(MODELS_DIR, "fallback_llm_guard.pkl"), "wb") as f:
        pickle.dump({"vectorizer": vec_b, "model": clf_b}, f)

    # quick sanity metrics on held-out split (informational only -- the
    # authoritative validation run is test_layer1.py against input_guard.py
    # end-to-end, including the keyword layer and ensembling)
    from sklearn.metrics import classification_report

    xa_test = vec_a.transform(x_test)
    xb_test = vec_b.transform(x_test)
    pred_a = clf_a.predict(xa_test)
    pred_b = clf_b.predict(xb_test)

    print("\n[Model A - word TF-IDF + LogisticRegression] held-out report:")
    print(classification_report(y_test, pred_a, target_names=["benign", "jailbreak"]))
    print("[Model B - char n-gram TF-IDF + NaiveBayes] held-out report:")
    print(classification_report(y_test, pred_b, target_names=["benign", "jailbreak"]))

    # Persist the exact held-out test split so test_layer1.py evaluates on
    # precisely the same never-trained-on examples.
    test_df = pd.DataFrame({"prompt": x_test, "jailbreak": y_test})
    test_df.to_csv(os.path.join(HERE, "held_out_test_split.csv"), index=False)
    print(f"\nHeld-out test split saved to held_out_test_split.csv ({len(test_df)} rows)")
    print(f"Models saved to {MODELS_DIR}/")


if __name__ == "__main__":
    train_and_save()
