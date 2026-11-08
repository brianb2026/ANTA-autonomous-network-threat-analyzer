"""Where things live, in a source checkout and inside a packaged (PyInstaller) app."""
from __future__ import annotations

import os
import sys

APP_NAME = "ANTA"
IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def bundle_dir() -> str:
    """Read-only resources: the PyInstaller bundle, or the repository root."""
    if frozen():
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def web_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def engine_path() -> str:
    name = "anta-engine.exe" if IS_WINDOWS else "anta-engine"
    if frozen():
        return os.path.join(bundle_dir(), name)
    for candidate in (os.path.join(bundle_dir(), "build", name),
                      os.path.join(bundle_dir(), "build", "cmake", name),
                      os.path.join(bundle_dir(), "build", "cmake", "Release", name)):
        if os.path.exists(candidate):
            return candidate
    return os.path.join(bundle_dir(), "build", name)


def _private_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    if not IS_WINDOWS:  # Windows profile directories already carry owner-only ACLs
        os.chmod(path, 0o700)
    return path


def app_data_dir() -> str:
    """Per-user writable data: recordings, demo capture, user model, config, logs."""
    override = os.environ.get("ANTA_DATA_DIR")  # tests (and portable installs) keep their data elsewhere
    if override:
        return _private_dir(override)
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        path = os.path.join(base, APP_NAME)
    elif IS_MAC:
        path = os.path.join(os.path.expanduser("~"), "Library", "Application Support", APP_NAME)
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
        path = os.path.join(base, "anta")
    return _private_dir(path)


def captures_dir() -> str:
    return _private_dir(os.path.join(app_data_dir(), "captures"))


def samples_dir() -> str:
    return _private_dir(os.path.join(app_data_dir(), "samples"))


def logs_dir() -> str:
    return _private_dir(os.path.join(app_data_dir(), "logs"))


def models_dir() -> str:
    """A model the user trained (in app data) wins over the bundled one."""
    user = os.path.join(app_data_dir(), "models")
    if os.path.exists(os.path.join(user, "model.onnx")):
        return user
    return os.path.join(bundle_dir(), "models")


def config_path() -> str | None:
    path = os.path.join(app_data_dir(), "anta.toml")
    return path if os.path.exists(path) else None
