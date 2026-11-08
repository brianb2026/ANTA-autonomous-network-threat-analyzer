"""Train the Isolation Forest on benign sessions and export it to ONNX.

  python -m anta.train --benign data/benign_train.pcap --out models \
      [--benign more.pcap ...] [--validate val.pcap ...] [--test holdout.pcap ...] \
      [--eval data/mixed_demo.pcap --eval-malicious 10.0.0.23,10.0.0.44] [--compare models]

Sessions are produced by running the C++ engine over each capture, so training
sees exactly the same features as live inference. Pre-extracted JSONL from the
engine also works (pass a .jsonl path instead of a .pcap).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys

import numpy as np

from .features import FEATURE_NAMES, feature_vector, session_features
from .security import InvalidRecord, validate_session


def iter_sessions(path: str, engine: str):
    """Yield final session records from a pcap (via the engine) or a JSONL file."""
    if path.endswith(".jsonl") or path.endswith(".json"):
        with open(path) as fh:
            for line in fh:
                rec = json.loads(line)
                if rec.get("type") == "session" and rec.get("final"):
                    yield rec
        return
    proc = subprocess.Popen([engine, "-r", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        rec = json.loads(line)
        if rec.get("type") == "session" and rec.get("final"):
            yield rec
    if proc.wait() != 0:
        raise RuntimeError(f"engine failed on {path}")


def model_eligible(rec: dict) -> bool:
    """The session model covers TCP conversations that carried data."""
    return rec["proto"] == "tcp" and bool(rec.get("events"))


def load_matrix(paths, engine):
    rows, recs = [], []
    for p in paths:
        for rec in iter_sessions(p, engine):
            try:
                rec = validate_session(rec)
            except (InvalidRecord, TypeError, ValueError):
                continue
            if model_eligible(rec):
                rows.append(feature_vector(session_features(rec)))
                recs.append(rec)
    return np.vstack(rows) if rows else np.empty((0, len(FEATURE_NAMES)), np.float32), recs


CALIBRATION_FILE = "calibration.npz"


def onnx_scores(model, x: np.ndarray) -> np.ndarray:
    """Scores from an ONNX model (a path, or the model's bytes)."""
    import onnxruntime as ort
    sess = ort.InferenceSession(model, providers=["CPUExecutionProvider"])
    return sess.run(["scores"], {"input": x.astype(np.float32)})[0].reshape(-1) if len(x) else np.empty(0)


def measure(model, threshold: float, test_x: np.ndarray, eval_x: np.ndarray | None,
            eval_recs: list | None, malicious: set[str]) -> dict:
    """How a model does on held-out benign sessions (its false-alarm rate) and on a labelled
    capture (its false alarms there, and each attacker's sessions it flags)."""
    out: dict = {}
    if len(test_x):
        s = onnx_scores(model, test_x)
        out["test"] = {"sessions": int(len(test_x)), "fp_rate": float(np.mean(s < threshold)),
                       "p01_margin": float(np.quantile(s, 0.001) - threshold)}
    if eval_x is not None and len(eval_x):
        s = onnx_scores(model, eval_x)
        flagged = s < threshold
        is_bad = np.array([r["src_ip"] in malicious or r["dst_ip"] in malicious for r in eval_recs])
        n_benign = int((~is_bad).sum())
        per = {}
        for ip in sorted(malicious):
            mask = np.array([ip in (r["src_ip"], r["dst_ip"]) for r in eval_recs])
            if mask.any():
                per[ip] = {"sessions": int(mask.sum()), "flagged": int((mask & flagged).sum()),
                           "min_score": float(s[mask].min()), "margin": float(s[mask].min() - threshold)}
        out["eval"] = {"benign_sessions": n_benign, "benign_fp_rate": float(np.sum(flagged & ~is_bad)) / max(1, n_benign),
                       "attackers": per}
    return out


def describe(label: str, m: dict) -> None:
    if "test" in m:
        print(f"  {label}: held-out benign FP rate {m['test']['fp_rate']:.2%} on {m['test']['sessions']} sessions")
    if "eval" in m:
        e = m["eval"]
        caught = ", ".join(f"{ip} {a['flagged']}/{a['sessions']}" for ip, a in e["attackers"].items())
        print(f"  {label}: eval benign FP rate {e['benign_fp_rate']:.2%}; attacker sessions flagged: {caught}")


def eval_split(path: str, engine: str, malicious: set[str]):
    """A labelled capture's sessions as (benign rows, attack rows)."""
    xe, recs = load_matrix([path], engine)
    bad = np.array([r["src_ip"] in malicious or r["dst_ip"] in malicious for r in recs], dtype=bool)
    return xe[~bad], xe[bad]


def write_calibration(out_dir: str, validate: list[str], eval_path: str | None, malicious: set[str],
                      engine: str) -> str:
    """The feature rows a model the user adds is calibrated and checked on: held-out benign
    sessions (its alert threshold) and, if given, a labelled capture's attack sessions (what
    it catches). Stored next to the model so the desktop app carries it."""
    benign, _ = load_matrix(validate, engine)
    attack = np.empty((0, len(FEATURE_NAMES)), np.float32)
    if eval_path:
        _, attack = eval_split(eval_path, engine, malicious)
    path = os.path.join(out_dir, CALIBRATION_FILE)
    np.savez_compressed(path, benign=benign.astype(np.float32), attack=attack.astype(np.float32),
                        features=np.array(FEATURE_NAMES))
    print(f"calibration set: {len(benign)} benign and {len(attack)} attack sessions -> {path}")
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign", action="append", default=[], help="benign pcap/jsonl for training (repeatable)")
    ap.add_argument("--calibration-only", action="store_true",
                    help="only (re)write the calibration set added models are checked on (needs --validate)")
    ap.add_argument("--validate", action="append", default=[],
                    help="held-out benign pcap/jsonl used to calibrate the threshold (repeatable; strongly "
                         "recommended: thresholds set on training data are optimistic)")
    ap.add_argument("--engine", default="build/anta-engine")
    ap.add_argument("--out", default="models")
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--max-samples", type=int, default=2048,
                    help="sessions each tree sees (2048 of the ~20k in the built-in training set; held-out tests "
                         "showed attack sessions stand out more than at 256-1024, at the same false-alarm rate)")
    ap.add_argument("--fp-rate", type=float, default=0.005,
                    help="target fraction of benign sessions above the alert threshold")
    ap.add_argument("--test", action="append", default=[],
                    help="held-out benign pcap/jsonl never trained or calibrated on: how often the model alerts on "
                         "benign traffic it hasn't seen (repeatable)")
    ap.add_argument("--compare", metavar="DIR",
                    help="a model directory (model.onnx + meta.json) to measure on the same test and eval sets")
    ap.add_argument("--eval", help="labelled capture to evaluate against")
    ap.add_argument("--eval-malicious", default="",
                    help="comma-separated attacker IPs in --eval (a session is malicious if either endpoint matches)")
    args = ap.parse_args(argv)
    malicious = {ip for ip in args.eval_malicious.split(",") if ip}
    if args.calibration_only:
        if not args.validate:
            sys.exit("--calibration-only needs --validate")
        write_calibration(args.out, args.validate, args.eval, malicious, args.engine)
        return
    if not args.benign:
        sys.exit("--benign is required")

    previous = None  # (the model compared with, read before this one may replace it)
    if args.compare:
        try:
            with open(os.path.join(args.compare, "meta.json")) as fh, \
                    open(os.path.join(args.compare, "model.onnx"), "rb") as mh:
                previous = (json.load(fh), mh.read())
        except (OSError, ValueError) as exc:
            print(f"warning: nothing to compare with in {args.compare}: {exc}")

    from sklearn.ensemble import IsolationForest
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    x, _ = load_matrix(args.benign, args.engine)
    if len(x) < 200:
        sys.exit(f"only {len(x)} usable sessions; need more benign traffic")
    print(f"training on {len(x)} benign TCP sessions, {len(FEATURE_NAMES)} features")

    forest = IsolationForest(n_estimators=args.trees, max_samples=min(args.max_samples, len(x)),
                             contamination="auto", random_state=42)
    forest.fit(x)
    train_scores = forest.decision_function(x)

    if args.validate:
        xv, _ = load_matrix(args.validate, args.engine)
        val_scores = forest.decision_function(xv)
        threshold = float(np.quantile(val_scores, args.fp_rate))
        calib = {"source": "validation", "sessions": int(len(xv)), "fp_rate": float(np.mean(val_scores < threshold))}
        print(f"calibrated on {len(xv)} held-out benign sessions")
    else:
        print("warning: no --validate set; calibrating on training data (FP rate will be underestimated)")
        threshold = float(np.quantile(train_scores, args.fp_rate))
        calib = {"source": "training", "sessions": int(len(x)), "fp_rate": float(np.mean(train_scores < threshold))}
    train_fp = float(np.mean(train_scores < threshold))

    onx = convert_sklearn(forest, initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
                          target_opset={"": 17, "ai.onnx.ml": 3})
    os.makedirs(args.out, exist_ok=True)
    model_path = os.path.join(args.out, "model.onnx")
    tmp_path = model_path + ".tmp"
    with open(tmp_path, "wb") as fh:
        fh.write(onx.SerializeToString())

    # Verify the exported graph agrees with scikit-learn before shipping it.
    import onnxruntime as ort
    sess = ort.InferenceSession(tmp_path, providers=["CPUExecutionProvider"])
    sample = x[np.random.default_rng(0).choice(len(x), size=min(5000, len(x)), replace=False)]
    onnx_scores = sess.run(["scores"], {"input": sample})[0].reshape(-1)
    max_err = float(np.max(np.abs(onnx_scores - forest.decision_function(sample))))
    print(f"ONNX parity check on {len(sample)} sessions: max |sklearn - onnx| = {max_err:.2e}")
    if max_err > 1e-3:
        os.unlink(tmp_path)
        sys.exit("ONNX export diverges from scikit-learn")
    os.replace(tmp_path, model_path)
    if args.validate:
        write_calibration(args.out, args.validate, args.eval, malicious, args.engine)

    meta = {
        "features": FEATURE_NAMES,
        "threshold": threshold,
        "score_std": float(np.std(train_scores)),
        "score_quantiles": {str(q): float(np.quantile(train_scores, q)) for q in (0.001, 0.005, 0.01, 0.05, 0.5)},
        "feature_mean": x.mean(axis=0).tolist(),
        "feature_std": x.std(axis=0).tolist(),
        "train_sessions": int(len(x)),
        "train_sources": [os.path.basename(p) for p in args.benign],
        "train_fp_rate": train_fp,
        "calibration": calib,
        "trees": args.trees,
        "max_samples": args.max_samples,
        "onnx_max_error": max_err,
        "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    print(f"threshold {threshold:.4f}: benign FP rate {calib['fp_rate']:.2%} on {calib['source']} data, "
          f"{train_fp:.2%} on training data")

    test_x = load_matrix(args.test, args.engine)[0] if args.test else np.empty((0, len(FEATURE_NAMES)), np.float32)
    eval_x, eval_recs = load_matrix([args.eval], args.engine) if args.eval else (None, None)
    if args.test or args.eval:
        print("held-out measurements:")
        mine = measure(model_path, threshold, test_x, eval_x, eval_recs, malicious)
        describe("this model", mine)
        if "test" in mine:
            meta["test"] = {"sources": [os.path.basename(p) for p in args.test], **mine["test"]}
        if previous:
            other, blob = previous
            theirs = measure(blob, float(other["threshold"]), test_x, eval_x, eval_recs, malicious)
            describe(f"the model it's compared with ({other.get('train_sessions')} training sessions)", theirs)
            meta["compared_with"] = {"train_sessions": other.get("train_sessions"), "created": other.get("created"),
                                     **theirs}

    if args.eval:
        bad = {ip for ip in args.eval_malicious.split(",") if ip}
        xe, recs = eval_x, eval_recs
        s = sess.run(["scores"], {"input": xe})[0].reshape(-1)
        flagged = s < threshold
        is_bad = np.array([r["src_ip"] in bad or r["dst_ip"] in bad for r in recs])
        n_benign = int((~is_bad).sum())
        fp = int(np.sum(flagged & ~is_bad))
        print(f"eval ({os.path.basename(args.eval)}): {n_benign} benign sessions, {fp} flagged "
              f"({fp / max(1, n_benign):.2%} FP rate); per attacker:")
        per = {}
        for ip in sorted(bad):
            mask = np.array([ip in (r["src_ip"], r["dst_ip"]) for r in recs])
            if not mask.any():
                continue
            per[ip] = {"sessions": int(mask.sum()), "flagged": int((mask & flagged).sum()),
                       "min_score": float(s[mask].min())}
            print(f"  {ip}: {per[ip]['flagged']}/{per[ip]['sessions']} sessions flagged, "
                  f"min score {per[ip]['min_score']:.3f}")
        print("  (beacon check-ins look like ordinary small sessions one at a time; the timing detector, not "
              "this model, is what catches them)")
        meta["eval"] = {"source": os.path.basename(args.eval), "benign_sessions": n_benign,
                        "benign_fp_rate": fp / max(1, n_benign), "attackers": per}

    with open(os.path.join(args.out, "meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    print(f"wrote {model_path} and meta.json")


if __name__ == "__main__":
    main()
