import json
import os
import subprocess
import sys
import tempfile

import pytest

# Keep test sockets and export temp files out of the user's real ~/.anta/run.
# (/tmp keeps Unix socket paths short; Windows has no /tmp.)
os.environ["ANTA_RUNTIME_DIR"] = tempfile.mkdtemp(prefix="anta-test-", dir="/tmp" if os.path.isdir("/tmp") else None)
# ...and their settings, feeds and flow logs out of the user's real data folder.
os.environ["ANTA_DATA_DIR"] = tempfile.mkdtemp(prefix="anta-data-")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.environ.get("ANTA_ENGINE") or os.path.join(ROOT, "build",
                                                        "anta-engine.exe" if sys.platform == "win32" else "anta-engine")
DATA = os.path.join(ROOT, "data")
MODELS = os.path.join(ROOT, "models")

# Attack infrastructure planted in mixed_demo.pcap
C2_FIXED, C2_JITTER, C2_KEEPALIVE, EXFIL_DST = "192.168.1.105", "45.77.12.34", "198.51.100.7", "203.0.113.50"
ATTACKER_HOSTS = {"10.0.0.23", "10.0.0.31", "10.0.0.44", "10.0.0.52", "10.0.0.61"}


@pytest.fixture(scope="session")
def engine():
    if not os.environ.get("ANTA_ENGINE"):
        subprocess.run(["make", "-C", ROOT, "-s"], check=True)
    return ENGINE


@pytest.fixture(scope="session")
def data_dir():
    needed = {"demo": "mixed_demo.pcap", "val": "benign_val.pcap", "tests": "edge_cases.pcap"}
    for only, name in needed.items():
        if not os.path.exists(os.path.join(DATA, name)):
            subprocess.run([sys.executable, "-m", "anta.tools.gen_traffic", "--out", DATA, "--only", only],
                           check=True, cwd=ROOT)
    return DATA


def run_engine(engine, *args):
    out = subprocess.run([engine, *args], check=True, capture_output=True, text=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def sessions(records):
    return [r for r in records if r["type"] == "session" and r["final"]]


@pytest.fixture(scope="session")
def demo_records(engine, data_dir):
    return run_engine(engine, "-r", os.path.join(data_dir, "mixed_demo.pcap"))
