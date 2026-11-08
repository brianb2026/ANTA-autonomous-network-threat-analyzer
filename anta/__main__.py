"""ANTA command line.

  anta serve   run the analyzer + web dashboard
  anta analyze terminal-only analysis (no UI), e.g. piping engine output via stdin
  anta train   train/export the ONNX model (alias for python -m anta.train)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .analyzer import Analyzer, Config
from .ingest import read_stdin

SEV_COLOR = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[36m"}
RESET = "\033[0m"


def load_model(model_dir: str, quiet: bool = False):
    from .model import AnomalyModel

    if not AnomalyModel.available(model_dir):
        if not quiet:
            print(f"anta: no model in {model_dir}/ (run `make train`); ML scoring disabled, "
                  f"rule-based detectors still active", file=sys.stderr)
        return None
    return AnomalyModel(model_dir)


def print_alert(alert: dict, color: bool, prefix: str = "") -> None:
    c = SEV_COLOR.get(alert["severity"], "") if color else ""
    r = RESET if color else ""
    print(f"{prefix}{c}[{alert['severity'].upper():8}] {alert['id']} {alert['title']}{r}")
    print(f"    {alert['headline']}")
    for d in alert["details"]:
        print(f"      - {d}")
    sys.stdout.flush()


def cmd_analyze(args) -> int:
    analyzer = Analyzer(load_model(args.model), Config.load(args.config))
    seen: set[str] = set()
    color = sys.stdout.isatty() and not args.json

    def sink(rec):
        for alert in analyzer.ingest(rec):
            if alert.get("retracted"):
                seen.discard(alert["id"])
                continue
            if args.json:
                print(json.dumps({k: v for k, v in alert.items() if k not in ("timeline", "chart")}, default=float))
                sys.stdout.flush()
            elif alert["id"] not in seen:
                print_alert(alert, color, prefix="NEW ")
            seen.add(alert["id"])

    if args.pcap:
        # Convenience: run the engine ourselves and feed its stdout through the same path.
        import subprocess
        proc = subprocess.Popen([args.engine, "-r", args.pcap], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                text=True)
        sys.stdin = proc.stdout  # read_stdin() still pulls one line at a time
        n = read_stdin(sink)
        proc.wait()
    else:
        n = read_stdin(sink)

    if not args.json:
        s = analyzer.summary()
        print(f"\n=== {n} records, {s['sessions']} sessions, {s['alerts']} alerts "
              f"{s['by_severity']} ===")
        for alert in sorted(analyzer.alerts.values(), key=lambda a: -a["confidence"]):
            print_alert(alert, color)
    return 0


def cmd_serve(args) -> int:
    from . import server

    if args.stdin and (args.pcap or args.interface):
        sys.exit("--stdin cannot be combined with --pcap/--interface")
    analyzer = Analyzer(load_model(args.model), Config.load(args.config))
    try:
        asyncio.run(server.run(args, analyzer))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_app(args) -> int:
    from . import app
    return app.run(headless=args.headless, browser=args.browser, port=args.port, engine=args.engine,
                   model=args.model, config=args.config, url_file=args.url_file)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="anta", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", default="models", help="directory with model.onnx + meta.json")
    ap.add_argument("--engine", default="build/anta-engine", help="path to the C++ engine binary")
    ap.add_argument("--config", help="TOML file overriding detector thresholds and allowlists")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="analyzer + web dashboard")
    src = s.add_mutually_exclusive_group()
    src.add_argument("--stdin", action="store_true", help="read engine JSON lines from stdin")
    src.add_argument("--pcap", help="spawn the engine on a capture file")
    src.add_argument("--interface", help="spawn the engine on a live interface (needs root)")
    s.add_argument("--transport", choices=["zmq", "unix"], default="zmq",
                   help="IPC with the engine: ZeroMQ PULL (default) or newline JSON over a Unix socket")
    s.add_argument("--endpoint", help="listen endpoint (default: ipc://~/.anta/run/engine.ipc for zmq, "
                                      "~/.anta/run/engine.sock for unix)")
    s.add_argument("--token", help="dashboard session token (default: random per run, or $ANTA_TOKEN)")
    s.add_argument("--allow-host", action="append", help="extra Host header to accept (e.g. a tunnel name)")
    s.add_argument("--filter", help="BPF filter for --interface (recordings go to the app data captures folder)")
    s.add_argument("--no-listen", action="store_true", help="don't open an endpoint for an external engine")
    s.add_argument("--replay-speed", type=float, default=0.0,
                   help="pace offline input at N x real time (0 = as fast as possible)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)

    a = sub.add_parser("analyze", help="terminal analysis; reads engine JSON lines from stdin")
    a.add_argument("--pcap", help="run the engine on this file instead of reading stdin")
    a.add_argument("--json", action="store_true", help="emit alerts as JSON lines")
    a.set_defaults(func=cmd_analyze)

    g = sub.add_parser("app", help="desktop application (native window; falls back to the browser)")
    g.add_argument("--headless", action="store_true", help="no window: print the dashboard URL and keep serving")
    g.add_argument("--browser", action="store_true", help="open in the default browser instead of a native window")
    g.add_argument("--port", type=int, default=0)
    g.add_argument("--url-file", help="write the dashboard URL (with token) to this file")
    g.set_defaults(func=cmd_app)

    t = sub.add_parser("train", help="train the anomaly model", add_help=False)
    t.set_defaults(func=None)

    args, rest = ap.parse_known_args(argv)
    if args.cmd == "train":
        from . import train
        train.main(rest)
        return 0
    if rest:
        ap.error(f"unrecognized arguments: {' '.join(rest)}")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
