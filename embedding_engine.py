"""
embedding_engine.py
Unified Embedding Engine for AdaptShield.
Prefers fastembed (ONNX runtime) with local onnx_cache for high speed,
low RAM, and small bundle size.
Falls back to sentence_transformers if fastembed is unavailable.
"""

import os
import sys
from pathlib import Path
import numpy as np

# Prevent OpenMP runtime conflict on Windows
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"

# Pre-import onnxruntime if available before other C libraries
try:
    import onnxruntime
except ImportError:
    pass

_cached_engine = None

def cosine_similarity(a, b):
    """
    Numerically identical drop-in replacement for sklearn.metrics.pairwise.cosine_similarity.
    Avoids loading heavy OpenMP/C runtime dependencies from sklearn.
    """
    a = np.asarray(a, dtype=np.float32)
    b = np.asarray(b, dtype=np.float32)
    if a.ndim == 1:
        a = a.reshape(1, -1)
    if b.ndim == 1:
        b = b.reshape(1, -1)
    a_norm = np.linalg.norm(a, axis=1, keepdims=True)
    b_norm = np.linalg.norm(b, axis=1, keepdims=True)
    a_norm[a_norm == 0] = 1e-10
    b_norm[b_norm == 0] = 1e-10
    return np.dot(a / a_norm, (b / b_norm).T)


class EmbeddingEngine:
    def __init__(self):
        self.backend = None
        self.model = None

        base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)).resolve()
        onnx_cache = base_dir / "models" / "onnx_cache"

        # 1. Try FastEmbed (ONNX)
        if onnx_cache.exists():
            try:
                from fastembed import TextEmbedding
                self.model = TextEmbedding(
                    "sentence-transformers/all-MiniLM-L6-v2",
                    cache_dir=str(onnx_cache),
                    local_files_only=True
                )
                self.backend = "fastembed"
                print("[EmbeddingEngine] Loaded ONNX model via fastembed.")
            except Exception as e:
                print(f"[EmbeddingEngine] fastembed load failed: {e}")

        # 2. Fallback to SentenceTransformer
        if self.backend is None:
            st_path = base_dir / "models" / "all-MiniLM-L6-v2"
            target = str(st_path) if st_path.exists() else "all-MiniLM-L6-v2"
            try:
                from sentence_transformers import SentenceTransformer
                self.model = SentenceTransformer(target)
                self.backend = "sentence_transformers"
                print("[EmbeddingEngine] Loaded SentenceTransformer model.")
            except Exception as e:
                print(f"[EmbeddingEngine] SentenceTransformer load failed: {e}")

    def encode(self, texts, convert_to_numpy=True):
        if isinstance(texts, str):
            texts = [texts]
        if self.backend == "fastembed":
            embs = list(self.model.embed(texts))
            return np.array(embs, dtype=np.float32)
        elif self.backend == "sentence_transformers":
            return self.model.encode(texts, convert_to_numpy=convert_to_numpy)
        else:
            raise RuntimeError("No embedding model available")


def get_embedding_engine():
    global _cached_engine
    if _cached_engine is None:
        try:
            eng = EmbeddingEngine()
            if eng.backend is not None:
                _cached_engine = eng
            else:
                _cached_engine = False
        except Exception as e:
            print(f"[EmbeddingEngine] Error initializing: {e}")
            _cached_engine = False
    return _cached_engine if _cached_engine is not False else None
