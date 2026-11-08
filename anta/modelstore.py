"""The detection models ANTA can use, and which one is in use.

  * the bundled Isolation Forest ("builtin");
  * ONNX models the user adds: each is checked (one float input of ANTA's 10 session
    features, a score per session out), then calibrated on held-out benign sessions so
    its alert threshold is set the way the bundled model's is, and measured on labelled
    attack sessions so the user sees what it catches before switching to it;
  * a detection agent instead of a model ("agent", see agent.py).

Added models live owner-only in the data folder; the choice survives restarts.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import tempfile

import numpy as np

from . import paths
from .features import FEATURE_NAMES
from .model import AnomalyModel, model_output

MAX_MODEL_BYTES = 64 << 20
CALIBRATION_FILE = "calibration.npz"
BUILTIN, AGENT = "builtin", "agent"
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,40}-[0-9a-f]{8}")


class ModelError(ValueError):
    pass


def _private_write(path: str, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def calibration_set(model_dir: str | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Held-out benign sessions and labelled attack sessions, as feature rows."""
    path = os.path.join(model_dir or os.path.join(paths.bundle_dir(), "models"), CALIBRATION_FILE)
    with np.load(path, allow_pickle=False) as data:
        if [str(f) for f in data["features"]] != FEATURE_NAMES:
            raise ModelError("the calibration set doesn't match ANTA's session features")
        return data["benign"].astype(np.float32), data["attack"].astype(np.float32)


class ModelStore:
    def __init__(self, root: str | None = None, builtin_dir: str | None = None, builtin_model=None):
        self.root = root or os.path.join(paths.app_data_dir(), "models", "custom")
        self.builtin_model = builtin_model  # the built-in model if it's already loaded (it takes seconds)
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        self.builtin_dir = builtin_dir or paths.models_dir()
        self.state_path = os.path.join(self.root, "active.json")
        self._builtin_catch: tuple | None = None  # (the built-in model's file stamp, its catch rate)

    # ------------------------------------------------------------ the list

    def _custom_ids(self) -> list[str]:
        return sorted(d for d in os.listdir(self.root) if _ID.fullmatch(d) and
                      os.path.exists(os.path.join(self.root, d, "meta.json")))

    def _meta(self, model_id: str) -> dict:
        with open(os.path.join(self.root, model_id, "meta.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def _builtin_catch_rate(self) -> float | None:
        """The built-in model measured on the labelled attack sessions, as an added one is."""
        try:
            stamp = os.stat(os.path.join(self.builtin_dir, "model.onnx")).st_mtime_ns
            if self._builtin_catch is None or self._builtin_catch[0] != stamp:
                model = self.builtin_model or AnomalyModel(self.builtin_dir)
                attack = calibration_set()[1]
                rate = float(np.mean(model.scores(attack) < model.threshold)) if len(attack) else None
                self._builtin_catch = (stamp, rate)
            return self._builtin_catch[1]
        except Exception:  # noqa: BLE001 - no calibration set or a model that won't load: just not shown
            return None

    def calibration_sizes(self) -> dict | None:
        """How many benign and attack sessions the rates in the list are measured on."""
        try:
            benign, attack = calibration_set()
        except (OSError, ValueError, KeyError):
            return None
        return {"benign": int(len(benign)), "attack": int(len(attack))}

    def active(self) -> str:
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                chosen = json.load(fh).get("active", BUILTIN)
        except (OSError, ValueError):
            return BUILTIN
        return chosen if chosen in (BUILTIN, AGENT) or chosen in self._custom_ids() else BUILTIN

    def set_active(self, model_id: str) -> None:
        if model_id not in (BUILTIN, AGENT) and model_id not in self._custom_ids():
            raise ModelError("unknown model")
        _private_write(self.state_path, json.dumps({"active": model_id}).encode())

    def list(self) -> list[dict]:
        active = self.active()
        out = []
        try:
            with open(os.path.join(self.builtin_dir, "meta.json"), encoding="utf-8") as fh:
                bm = json.load(fh)
            out.append({"id": BUILTIN, "kind": "builtin", "name": "Built-in Isolation Forest",
                        "created": bm.get("created"), "benign_alert_rate": (bm.get("calibration") or {}).get("fp_rate"),
                        "attack_catch_rate": self._builtin_catch_rate(), "about": f"{bm.get('trees')} trees, trained on "
                        f"{bm.get('train_sessions') or 0:,} benign sessions"})
        except (OSError, ValueError):
            out.append({"id": BUILTIN, "kind": "builtin", "name": "Built-in Isolation Forest", "missing": True})
        for mid in self._custom_ids():
            try:
                m = self._meta(mid)
            except (OSError, ValueError):
                continue
            out.append({"id": mid, "kind": "onnx", "name": m.get("name"), "created": m.get("created"),
                        "benign_alert_rate": m["calibration"]["fp_rate"],
                        "attack_catch_rate": m["calibration"].get("attack_catch_rate"),
                        "direction": m.get("direction"), "output": m.get("output"),
                        "file": m.get("file"), "size": m.get("size"), "sha256": m.get("sha256")})
        out.append({"id": AGENT, "kind": "agent", "name": "Detection agent"})
        for entry in out:
            entry["active"] = entry["id"] == active
        return out

    def load(self, model_id: str | None = None) -> AnomalyModel | None:
        """The session model to score with; None for the agent (or a model that won't load)."""
        model_id = model_id or self.active()
        if model_id == AGENT:
            return None
        directory = self.builtin_dir if model_id == BUILTIN else os.path.join(self.root, model_id)
        if not AnomalyModel.available(directory):
            return None
        return AnomalyModel(directory)

    def remove(self, model_id: str) -> None:
        if model_id not in self._custom_ids():
            raise ModelError("unknown model")
        if self.active() == model_id:
            self.set_active(BUILTIN)
        shutil.rmtree(os.path.join(self.root, model_id))

    # ------------------------------------------------------------ adding one

    def add_onnx(self, name: str, data: bytes, direction: str = "auto", fp_rate: float = 0.005,
                 filename: str = "") -> dict:
        """Check, calibrate and store an ONNX model. Raises ModelError saying what's wrong."""
        import onnxruntime as ort

        name = re.sub(r"\s+", " ", str(name or "")).strip()[:80] or "Imported model"
        if not data or len(data) > MAX_MODEL_BYTES:
            raise ModelError(f"the model must be an ONNX file of at most {MAX_MODEL_BYTES >> 20} MB")
        if direction not in ("auto", "lower", "higher"):
            raise ModelError("direction must be auto, lower or higher")
        if not 0.0001 <= fp_rate <= 0.2:
            raise ModelError("the benign alert rate must be between 0.01% and 20%")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        try:  # (only the CPU provider: no custom-op libraries are ever loaded)
            sess = ort.InferenceSession(data, opts, providers=["CPUExecutionProvider"])
        except Exception as exc:  # noqa: BLE001 - onnxruntime raises several unrelated types
            raise ModelError(f"not a model ONNX Runtime can load: {str(exc).splitlines()[0][:200]}") from None
        inputs = sess.get_inputs()
        if len(inputs) != 1 or inputs[0].type != "tensor(float)":
            raise ModelError("the model must take one float tensor: a row of ANTA's session features")
        shape = inputs[0].shape
        if len(shape) != 2 or shape[1] not in (len(FEATURE_NAMES), None) and not isinstance(shape[1], str):
            raise ModelError(f"the model's input must be [N, {len(FEATURE_NAMES)}] (ANTA's session features), "
                             f"not {shape}")
        output, column = self._pick_output(sess)
        benign, attack = calibration_set()

        def run(x: np.ndarray) -> np.ndarray:
            try:
                out = sess.run([output], {inputs[0].name: x})[0]
                s = model_output(out, column)
            except Exception as exc:  # noqa: BLE001
                raise ModelError(f"the model failed on ANTA's session features: {str(exc).splitlines()[0][:200]}") \
                    from None
            if s.shape != (len(x),) or not np.all(np.isfinite(s)):
                raise ModelError("the model must give one finite score per session")
            return s

        benign_scores, attack_scores = run(benign), run(attack) if len(attack) else np.empty(0)
        if direction == "auto":  # whichever way round puts the attacks on the anomalous side
            direction = "higher" if len(attack_scores) and attack_scores.mean() > benign_scores.mean() else "lower"
        sign = -1.0 if direction == "higher" else 1.0
        b, a = sign * benign_scores, sign * attack_scores
        threshold = float(np.quantile(b, fp_rate))
        std = float(np.std(b)) or 0.05
        z_mean, z_std = benign.mean(axis=0), benign.std(axis=0)
        digest = hashlib.sha256(data).hexdigest()
        model_id = f"{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')[:40] or 'model'}-{digest[:8]}"
        meta = {
            "name": name, "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "file": os.path.basename(filename)[:120], "size": len(data), "sha256": digest,
            "features": FEATURE_NAMES, "output": output, "output_column": column, "direction": direction,
            "threshold": threshold, "score_std": std,
            "feature_mean": [float(v) for v in z_mean], "feature_std": [float(v) for v in z_std],
            "calibration": {"source": "ANTA's held-out benign sessions", "sessions": int(len(b)),
                            "fp_rate": float(np.mean(b < threshold)), "target_fp_rate": fp_rate,
                            "attack_sessions": int(len(a)),
                            "attack_catch_rate": float(np.mean(a < threshold)) if len(a) else None},
        }
        directory = os.path.join(self.root, model_id)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        _private_write(os.path.join(directory, "model.onnx"), data)
        _private_write(os.path.join(directory, "meta.json"), json.dumps(meta, indent=1).encode())
        AnomalyModel(directory)  # it loads the way the analyzer will load it
        return next(e for e in self.list() if e["id"] == model_id)

    @staticmethod
    def _pick_output(sess) -> tuple[str, object]:
        """Which output is the score: a "scores" tensor (Isolation Forest), a probability
        tensor or per-class maps (a classifier: the malicious class), else the first float
        tensor."""
        outs = sess.get_outputs()
        by_name = {o.name: o for o in outs}
        if "scores" in by_name and by_name["scores"].type == "tensor(float)":
            return "scores", None
        for o in outs:
            if o.type.startswith("seq(map("):  # scikit-learn ZipMap: [{class: p}]
                return o.name, 1
        for o in outs:
            if o.type == "tensor(float)" and len(o.shape) == 2 and o.shape[1] == 2:
                return o.name, 1  # [P(benign), P(malicious)]
        for o in outs:
            if o.type in ("tensor(float)", "tensor(double)"):
                return o.name, None
        raise ModelError("the model has no float output to read a score from")
