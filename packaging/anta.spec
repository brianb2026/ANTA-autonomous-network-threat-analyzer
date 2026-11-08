# PyInstaller spec for the ANTA desktop application (macOS .app, Windows/Linux folder).
#   python packaging/build.py    (builds the engine first, then runs this)
import os
import sys

from PyInstaller.utils.hooks import collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
IS_WIN, IS_MAC = sys.platform == "win32", sys.platform == "darwin"
ENGINE = os.environ.get("ANTA_ENGINE") or os.path.join(ROOT, "build", "anta-engine.exe" if IS_WIN else "anta-engine")
ICONS = os.path.join(ROOT, "packaging", "icons")
VERSION = os.environ.get("ANTA_VERSION", "0.2.0")

if not os.path.exists(ENGINE):
    raise SystemExit(f"engine binary not found at {ENGINE}; build it first (python packaging/build.py)")
if not os.path.exists(os.path.join(ROOT, "models", "model.onnx")):
    raise SystemExit("models/model.onnx missing; run `make train` (or keep the committed model)")

a = Analysis(
    [os.path.join(ROOT, "packaging", "launch.py")],
    pathex=[ROOT],
    binaries=[(ENGINE, ".")],
    datas=[
        (os.path.join(ROOT, "anta", "web"), "anta/web"),
        (os.path.join(ROOT, "anta", "geo"), "anta/geo"),  # the offline GeoIP table
        (os.path.join(ROOT, "models", "model.onnx"), "models"),
        (os.path.join(ROOT, "models", "meta.json"), "models"),
        (os.path.join(ROOT, "models", "calibration.npz"), "models"),  # what an added model is checked on
        (os.path.join(ROOT, "config.example.toml"), "."),
    ],
    # Imported lazily (demo generator, CLI pass-through, IPC) so the analysis can't see them.
    hiddenimports=["anthropic", "anta.agent_providers", "truststore", "anta.tools.gen_traffic", "anta.tools.pcapgen", "anta.__main__", "anta.train",
                   "zmq.asyncio", *collect_submodules("webview.platforms")],
    # Training-only and test dependencies stay out of the app (they're large).
    excludes=["sklearn", "scipy", "skl2onnx", "onnx", "pytest", "tkinter", "matplotlib", "PyInstaller",
              "IPython", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="ANTA",
    console=False,                 # windowed app: no console window on Windows
    icon=os.path.join(ICONS, "anta.ico" if IS_WIN else "anta.icns" if IS_MAC else "anta.png"),
    disable_windowed_traceback=False,
    argv_emulation=False,
    codesign_identity=os.environ.get("ANTA_CODESIGN_IDENTITY"),
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="ANTA")

if IS_MAC:
    app = BUNDLE(
        coll,
        name="ANTA.app",
        icon=os.path.join(ICONS, "anta.icns"),
        bundle_identifier="io.github.anta.analyzer",
        version=VERSION,
        info_plist={
            "CFBundleName": "ANTA",
            "CFBundleDisplayName": "ANTA",
            "CFBundleShortVersionString": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            "NSHumanReadableCopyright": "ANTA — Autonomous Network Threat Analyzer",
            "LSApplicationCategoryType": "public.app-category.developer-tools",
        },
    )
