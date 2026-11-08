"""User settings kept in the data folder (owner-only JSON): flow logging and the
rolling capture buffer. Every value is validated and clamped on load and save."""
from __future__ import annotations

import contextlib
import json
import os
import tempfile

from . import paths

DEFAULTS = {
    "flowlog_live": True,       # write a flow log line for every session of a live capture
    "flowlog_files": False,     # ...and of capture files that are opened
    "flowlog_days": 30,         # keep this many days of flow logs
    "flowlog_max_mb": 1024,     # and at most this much in total
    "ring_segment_mb": 256,     # a live recording rotates to a new segment at this size
    "ring_segments": 8,         # older segments kept (the rolling buffer is segment_mb x segments)
}
LIMITS = {"flowlog_days": (1, 3650), "flowlog_max_mb": (10, 1_000_000), "ring_segment_mb": (16, 65536),
          "ring_segments": (1, 1000)}


def path() -> str:
    return os.path.join(paths.app_data_dir(), "settings.json")


def validate(values: dict) -> dict:
    out = dict(DEFAULTS)
    for k, default in DEFAULTS.items():
        if k not in values:
            continue
        v = values[k]
        if isinstance(default, bool):
            out[k] = bool(v)
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            lo, hi = LIMITS[k]
            out[k] = int(min(max(v, lo), hi))
    return out


def load() -> dict:
    try:
        with open(path(), encoding="utf-8") as fh:
            return validate(json.load(fh))
    except (OSError, ValueError, TypeError):
        return dict(DEFAULTS)


def save(values: dict) -> dict:
    clean = validate(values)
    directory = os.path.dirname(path())
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".settings-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=1)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return clean
