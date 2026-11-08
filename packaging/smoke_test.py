"""Launch a built ANTA app headless and check it end to end.

  python packaging/smoke_test.py [path/to/app/executable] [--capture data/edge_cases.pcap]

Starts the packaged app with --headless --url-file, then over the authenticated
API: checks the summary and model, lists interfaces, analyses a capture file and
verifies the alerts/sessions, and confirms unauthenticated access is refused.
Used by CI on macOS, Linux and Windows.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_exe() -> str:
    if sys.platform == "darwin":
        return os.path.join(ROOT, "dist", "ANTA.app", "Contents", "MacOS", "ANTA")
    return os.path.join(ROOT, "dist", "ANTA", "ANTA.exe" if sys.platform == "win32" else "ANTA")


def call(base, token, path, method="GET", body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body else None)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - loopback only
        return json.loads(resp.read())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", nargs="?", default=default_exe())
    ap.add_argument("--capture", default=os.path.join(ROOT, "data", "edge_cases.pcap"))
    ap.add_argument("--expect-sessions", type=int, default=6)
    ap.add_argument("--skip-engine", action="store_true", help="don't analyse a file (e.g. Windows without Npcap)")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        url_file = os.path.join(tmp, "url")
        env = dict(os.environ, ANTA_RUNTIME_DIR=os.path.join(tmp, "run"))
        proc = subprocess.Popen([args.exe, "--headless", "--url-file", url_file], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.time() + 120
            while not (os.path.exists(url_file) and os.path.getsize(url_file)):
                if proc.poll() is not None:
                    print(f"FAIL: app exited with {proc.returncode} before serving")
                    return 1
                if time.time() > deadline:
                    print("FAIL: app did not start within 120 s")
                    return 1
                time.sleep(0.5)
            url = open(url_file).read().strip()
            base, token = url.split("/?token=")
            print(f"app serving at {base}")

            try:
                call(base, None, "/api/summary")
                print("FAIL: unauthenticated request was accepted")
                return 1
            except urllib.error.HTTPError as exc:
                assert exc.code == 401, exc.code
            summary = call(base, token, "/api/summary")
            print(f"summary ok; ONNX model loaded: {summary['model']}")
            assert summary["model"], "bundled ONNX model failed to load"
            for _ in range(60):  # the GeoIP table loads in the background (about a second)
                geo = call(base, token, "/api/intel")["geo"]
                if geo["loaded"] or geo["error"]:
                    break
                time.sleep(0.5)
            print(f"GeoIP: {geo['rows']} ranges from the {'bundled' if geo['bundled'] else 'downloaded'} table")
            assert geo["loaded"] and geo["rows"] > 100_000, geo

            try:
                devices = call(base, token, "/api/interfaces")
                print(f"interfaces: {[d['name'] for d in devices][:5]}")
            except urllib.error.HTTPError as exc:
                print(f"interfaces unavailable ({exc.code}): {exc.read().decode()[:200]}")

            if not args.skip_engine:
                state = call(base, token, "/api/session", "POST", {"mode": "file", "path": args.capture})
                while state["state"] in ("starting", "running"):
                    time.sleep(0.5)
                    state = call(base, token, "/api/session")
                summary = call(base, token, "/api/summary")
                print(f"analysed {os.path.basename(args.capture)}: state={state['state']} "
                      f"sessions={summary['sessions']} alerts={summary['alerts']}")
                assert state["state"] == "finished", state
                assert summary["sessions"] == args.expect_sessions, summary["sessions"]
                page = call(base, token, "/api/packets?from=1&limit=10&count=1")
                detail = call(base, token, f"/api/packets/{page['packets'][0]['n']}")
                print(f"packet viewer: {page['matched_total']} frames; frame 1 = {page['packets'][0]['proto']} "
                      f"'{page['packets'][0]['info']}', {len(detail['layers'])} layers")
                assert page["packets"] and detail["layers"] and detail["hex"]
            print("PASS")
            return 0
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
