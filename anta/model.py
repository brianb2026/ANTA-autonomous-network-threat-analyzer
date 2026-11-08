"""ONNX Runtime wrapper around a session model: the bundled Isolation Forest, or an ONNX
model the user added (see modelstore.py). Scores are kept so that lower is more anomalous
whatever the model's own convention, and every model's alert threshold is calibrated on
benign sessions the same way."""
from __future__ import annotations

import json
import math
import os

import numpy as np

from .features import FEATURE_NAMES


def model_output(out, column) -> np.ndarray:
    """One score per session from an ONNX output: a score tensor, a column of a
    probability tensor, or scikit-learn's per-class maps (ZipMap)."""
    if isinstance(out, list):  # [{class: probability}, ...]
        return np.array([float(d.get(column, d.get(str(column), 0.0))) for d in out], dtype=float)
    arr = np.asarray(out, dtype=float)
    if arr.ndim == 2 and arr.shape[1] > 1:
        return arr[:, int(column or 0)]
    return arr.reshape(-1)


class AnomalyModel:
    def __init__(self, model_dir: str):
        import onnxruntime as ort

        with open(os.path.join(model_dir, "meta.json")) as fh:
            self.meta = json.load(fh)
        if self.meta["features"] != FEATURE_NAMES:
            raise ValueError("model was trained with a different feature layout; retrain with `make train`")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1  # tiny model: threading overhead dominates
        self.session = ort.InferenceSession(os.path.join(model_dir, "model.onnx"), opts,
                                            providers=["CPUExecutionProvider"])
        self.input_name = self.session.get_inputs()[0].name
        outputs = [o.name for o in self.session.get_outputs()]
        self.score_output = self.meta.get("output") or ("scores" if "scores" in outputs else outputs[-1])
        self.output_column = self.meta.get("output_column")
        # A model that scores anomalies high is negated, so lower is always more anomalous.
        self.sign = -1.0 if self.meta.get("direction") == "higher" else 1.0
        self.name = self.meta.get("name") or "Built-in Isolation Forest"
        self.threshold = self.meta["threshold"]
        self.score_std = self.meta["score_std"] or 0.05
        self.mean = np.array(self.meta["feature_mean"], dtype=np.float32)
        self.std = np.array(self.meta["feature_std"], dtype=np.float32)
        self.std[self.std == 0] = 1.0

    @staticmethod
    def available(model_dir: str) -> bool:
        return os.path.exists(os.path.join(model_dir, "model.onnx"))

    def scores(self, x: np.ndarray) -> np.ndarray:
        """Session scores, lower more anomalous (an Isolation Forest's decision scores as they are)."""
        x = np.atleast_2d(x).astype(np.float32)
        out = self.session.run([self.score_output], {self.input_name: x})[0]
        return self.sign * model_output(out, self.output_column)

    def native(self, score: float) -> float:
        """A score in the model's own units (what its author would recognise)."""
        return self.sign * score

    def is_anomaly(self, score: float) -> bool:
        return score < self.threshold

    def confidence(self, score: float) -> float:
        """Map a raw score to 0..1, 0.5 at the threshold."""
        z = (self.threshold - score) / self.score_std
        return 1.0 / (1.0 + math.exp(-2.5 * z))

    def top_deviations(self, x: np.ndarray, k: int = 3) -> list[dict]:
        """Features furthest from the benign training distribution (by z-score)."""
        z = (np.asarray(x, dtype=np.float32) - self.mean) / self.std
        order = np.argsort(-np.abs(z))[:k]
        return [{"feature": FEATURE_NAMES[i], "z": float(z[i]), "value": float(x[i]),
                 "baseline": float(self.mean[i])} for i in order]
