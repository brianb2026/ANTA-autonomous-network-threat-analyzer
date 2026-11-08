"""Build the ANTA desktop application for the current OS.

  python packaging/build.py [--npcap-sdk DIR] [--skip-engine] [--version 0.2.0]

Steps: engine (CMake) -> icons -> PyInstaller bundle -> OS package
  macOS    dist/ANTA.app, ANTA-<v>-macos-<arch>.dmg and .zip
  Windows  dist/ANTA/ANTA.exe, ANTA-<v>-windows-x64-setup.exe (Inno Setup, if installed) and .zip
  Linux    dist/ANTA/ANTA, ANTA-<v>-linux-<arch>.tar.gz (with install.sh and a .desktop entry)

Each OS must be built on that OS (PyInstaller does not cross-compile); the
GitHub Actions workflow in .github/workflows/build.yml does all three.
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
IS_WIN, IS_MAC = sys.platform == "win32", sys.platform == "darwin"


def run(cmd: list[str], **kw) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, **kw)


def tool(name: str) -> str:
    """Prefer tools installed in this Python environment (e.g. pip's cmake)."""
    local = os.path.join(os.path.dirname(sys.executable), name + (".exe" if IS_WIN else ""))
    return local if os.path.exists(local) else (shutil.which(name) or name)


def build_engine(npcap_sdk: str | None) -> str:
    build_dir = os.path.join(ROOT, "build", "cmake")
    cfg = [tool("cmake"), "-S", ROOT, "-B", build_dir, "-DCMAKE_BUILD_TYPE=Release"]
    if IS_WIN:
        sdk = npcap_sdk or os.environ.get("NPCAP_SDK")
        if not sdk:
            sys.exit("Windows builds need the Npcap SDK: --npcap-sdk DIR (https://npcap.com/#download)")
        cfg.append(f"-DNPCAP_SDK={sdk}")
    if IS_MAC:
        cfg.append("-DCMAKE_OSX_DEPLOYMENT_TARGET=11.0")
    run(cfg)
    run([tool("cmake"), "--build", build_dir, "--config", "Release", "--parallel"])
    name = "anta-engine.exe" if IS_WIN else "anta-engine"
    for candidate in (os.path.join(build_dir, "Release", name), os.path.join(build_dir, name)):
        if os.path.exists(candidate):
            out = os.path.join(ROOT, "build", name)
            # A new file, not an overwrite: macOS kills a signed binary rewritten in
            # place once it has run (its signature is cached per file).
            if os.path.exists(out):
                os.remove(out)
            shutil.copy2(candidate, out)
            run([out, "--version"])
            return out
    sys.exit("engine build produced no binary")


def arch() -> str:
    m = platform.machine().lower()
    return {"amd64": "x64", "x86_64": "x64" if IS_WIN else "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m)


def package_mac(version: str) -> list[str]:
    app = os.path.join(DIST, "ANTA.app")
    base = os.path.join(DIST, f"ANTA-{version}-macos-{arch()}")
    run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", app, base + ".zip"])
    staging = os.path.join(ROOT, "build", "dmg")
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)
    run(["ditto", app, os.path.join(staging, "ANTA.app")])
    os.symlink("/Applications", os.path.join(staging, "Applications"))
    if os.path.exists(base + ".dmg"):
        os.unlink(base + ".dmg")
    run(["hdiutil", "create", "-volname", "ANTA", "-srcfolder", staging, "-ov", "-format", "UDZO", base + ".dmg"])
    return [base + ".dmg", base + ".zip"]


def package_windows(version: str) -> list[str]:
    folder = os.path.join(DIST, "ANTA")
    base = os.path.join(DIST, f"ANTA-{version}-windows-{arch()}")
    with zipfile.ZipFile(base + ".zip", "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, _, files in os.walk(folder):
            for f in files:
                full = os.path.join(dirpath, f)
                zf.write(full, os.path.relpath(full, DIST))
    out = [base + ".zip"]
    iscc = shutil.which("iscc") or r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    if os.path.exists(iscc):
        run([iscc, f"/DSourceDir={folder}", f"/DAppVersion={version}", f"/DOutputDir={DIST}",
             f"/DOutputName=ANTA-{version}-windows-{arch()}-setup",
             os.path.join(ROOT, "packaging", "windows", "anta.iss")])
        out.insert(0, base + "-setup.exe")
    else:
        print("Inno Setup not found: skipping the installer (zip only)")
    return out


def package_linux(version: str) -> list[str]:
    folder = os.path.join(DIST, "ANTA")
    for name in ("install.sh", "anta.desktop"):
        shutil.copy2(os.path.join(ROOT, "packaging", "linux", name), os.path.join(folder, name))
    os.chmod(os.path.join(folder, "install.sh"), 0o755)
    shutil.copy2(os.path.join(ROOT, "packaging", "icons", "anta.png"), os.path.join(folder, "anta.png"))
    out = os.path.join(DIST, f"ANTA-{version}-linux-{arch()}.tar.gz")
    with tarfile.open(out, "w:gz") as tf:
        tf.add(folder, arcname="ANTA")
    return [out]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--npcap-sdk", help="Windows: extracted Npcap SDK directory")
    ap.add_argument("--skip-engine", action="store_true", help="reuse build/anta-engine")
    ap.add_argument("--version", default=os.environ.get("ANTA_VERSION", "0.2.0"))
    args = ap.parse_args()

    engine = os.path.join(ROOT, "build", "anta-engine.exe" if IS_WIN else "anta-engine")
    if not args.skip_engine:
        engine = build_engine(args.npcap_sdk)
    run([sys.executable, os.path.join(ROOT, "packaging", "make_icons.py")])
    env = dict(os.environ, ANTA_ENGINE=engine, ANTA_VERSION=args.version)
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", DIST,
         "--workpath", os.path.join(ROOT, "build", "pyinstaller"), os.path.join(ROOT, "packaging", "anta.spec")],
        env=env)
    artifacts = package_mac(args.version) if IS_MAC else package_windows(args.version) if IS_WIN \
        else package_linux(args.version)
    print("\nBuilt:")
    for a in artifacts:
        print(f"  {a}  ({os.path.getsize(a) / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
