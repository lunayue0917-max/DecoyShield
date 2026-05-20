"""
DecoyShield CLI — argparse dispatcher + subcommand handlers.

Subcommands:
  serve      Run a standalone honeypot server (Flask dev).
  inject     Pipe HTML/JSON through DecoyShield injectors.
  analyze    Summarize a captures.jsonl log.
  bait       Print one raw payload string.
"""
from __future__ import annotations

import argparse
import json as _json
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional, Sequence

from .. import __version__
from ..edge import SUPPORTED as EDGE_PLATFORMS
from ..injectors import DEFAULT_CHANNELS, bait, inject_html, inject_json
from ..registry import registry


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Force UTF-8 on stdout/stderr so non-ASCII payload chars (—, ², ≡, …)
    # don't crash on Windows consoles that default to cp936/cp1252.
    # No-op on real UTF-8 terminals and on capsys-wrapped streams.
    for _stream in (sys.stdout, sys.stderr):
        _reconfigure = getattr(_stream, "reconfigure", None)
        if _reconfigure is not None:
            try:
                _reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "_handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return 1
    return handler(args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decoyshield",
        description=(
            "DecoyShield CLI — counter-recon honeypot toolkit. Run a "
            "standalone honeypot, inject bait into HTML/JSON, analyze "
            "capture logs, or emit raw payload strings."
        ),
    )
    p.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")

    # ── serve ────────────────────────────────────────────────────────
    sp = sub.add_parser(
        "serve",
        help="Run a standalone DecoyShield honeypot (Flask dev server).",
        description=(
            "Spin up a self-contained DecoyShield honeypot. Wires "
            "FlaskHoneypot to a fresh Flask app and binds to host:port. "
            "Suitable for demos, local experimentation, and CTF-style "
            "deployments. For production, embed FlaskHoneypot in your "
            "own app behind gunicorn + a reverse proxy."
        ),
    )
    sp.add_argument("--host", default="127.0.0.1", help="(default: 127.0.0.1)")
    sp.add_argument("--port", type=int, default=5000, help="(default: 5000)")
    sp.add_argument(
        "--log", default="logs/captures.jsonl",
        help="JSONL capture log path (default: logs/captures.jsonl)",
    )
    sp.add_argument(
        "--dashboard-path", default="/_defender",
        help="URL prefix for the defender dashboard (default: /_defender)",
    )
    sp.add_argument(
        "--auth", metavar="USER:PASS",
        help="Enable HTTP basic auth on the dashboard.",
    )
    sp.set_defaults(_handler=_cmd_serve)

    # ── inject ───────────────────────────────────────────────────────
    ip = sub.add_parser(
        "inject",
        help="Pipe HTML or JSON through DecoyShield injectors.",
        description=(
            "Read HTML or JSON from a file or stdin, embed invisible "
            "DecoyShield bait, write the result. Mode is auto-detected "
            "from the first non-whitespace character ({/[ => json, "
            "anything else => html) unless --mode is given."
        ),
    )
    ip.add_argument(
        "--mode", choices=("auto", "html", "json"), default="auto",
        help="Payload type (default: auto)",
    )
    ip.add_argument(
        "--input", "-i", default="-",
        help="Input path; '-' = stdin (default: stdin)",
    )
    ip.add_argument(
        "--output", "-o", default="-",
        help="Output path; '-' = stdout (default: stdout)",
    )
    ip.add_argument(
        "--channels", default=",".join(DEFAULT_CHANNELS),
        help=("Comma-separated HTML channels. Available: "
              "comment, hidden_div, white_text, hidden_input. "
              f"(default: {','.join(DEFAULT_CHANNELS)})"),
    )
    ip.set_defaults(_handler=_cmd_inject)

    # ── analyze ──────────────────────────────────────────────────────
    ap = sub.add_parser(
        "analyze",
        help="Summarize a captures.jsonl log.",
        description=(
            "Read a DecoyShield capture log (newline-delimited JSON) "
            "and print a summary: total events, verdict breakdown, "
            "top IPs / paths / user-agents, payloads served counts."
        ),
    )
    ap.add_argument(
        "log", nargs="?", default="logs/captures.jsonl",
        help="Path to captures.jsonl (default: logs/captures.jsonl)",
    )
    ap.add_argument(
        "--limit", type=int, default=10,
        help="Top-N entries per category (default: 10)",
    )
    ap.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="(default: text)",
    )
    ap.set_defaults(_handler=_cmd_analyze)

    # ── bait ─────────────────────────────────────────────────────────
    bp = sub.add_parser(
        "bait",
        help="Print one raw payload string.",
        description=(
            "Emit a single payload by name. Pipe into a file, a config "
            "comment, a banner — anywhere an LLM scanner might read. "
            "Use `decoyshield list` to see all available names."
        ),
    )
    bp.add_argument(
        "name", nargs="?", default="moral_lock",
        help="Payload name (default: moral_lock). "
             "See `decoyshield list` for the full catalog.",
    )
    bp.set_defaults(_handler=_cmd_bait)

    # ── list ─────────────────────────────────────────────────────────
    lp = sub.add_parser(
        "list",
        help="List all registered payloads with metadata.",
        description=(
            "Enumerate the payload registry: name, category, language, "
            "source, and one-line description for every available "
            "payload (built-in plus any user-registered)."
        ),
    )
    lp.add_argument(
        "--category", metavar="CAT",
        help="Filter by category (e.g. moral_lock, token_blackhole, traceback).",
    )
    lp.add_argument(
        "--language", metavar="LANG",
        help="Filter by language (e.g. en).",
    )
    lp.add_argument(
        "--source", choices=("builtin", "user"),
        help="Filter by source.",
    )
    lp.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="(default: text)",
    )
    lp.set_defaults(_handler=_cmd_list)

    # ── info ─────────────────────────────────────────────────────────
    ifp = sub.add_parser(
        "info",
        help="Show metadata + body for one payload.",
        description=(
            "Print the full registry entry for a named payload: "
            "metadata header followed by the payload body."
        ),
    )
    ifp.add_argument("name", help="Payload name (see `decoyshield list`).")
    ifp.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="(default: text)",
    )
    ifp.set_defaults(_handler=_cmd_info)

    # ── edge ─────────────────────────────────────────────────────────
    ep = sub.add_parser(
        "edge",
        help="Print a deployment config for an edge platform.",
        description=(
            "Generate a ready-to-paste config for an edge platform "
            "(nginx, caddy, cloudflare). Pipe the output to a file: "
            "`decoyshield edge nginx > /etc/nginx/conf.d/decoyshield.conf`."
        ),
    )
    ep.add_argument(
        "platform", choices=EDGE_PLATFORMS,
        help="Target edge platform.",
    )
    ep.add_argument(
        "--origin", default="https://your-origin.example.com",
        help="(cloudflare only) origin URL the Worker forwards to "
             "(default: https://your-origin.example.com)",
    )
    ep.set_defaults(_handler=_cmd_edge)

    return p


# ── handlers ─────────────────────────────────────────────────────────

def _cmd_bait(args: argparse.Namespace) -> int:
    entry = registry.get(args.name)
    if entry is None:
        print(
            f"decoyshield bait: unknown payload {args.name!r}. "
            f"Run `decoyshield list` to see available names.",
            file=sys.stderr,
        )
        return 2
    sys.stdout.write(entry.body)
    sys.stdout.write("\n")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    entries = registry.list(
        category=args.category,
        language=args.language,
        source=args.source,
    )
    if args.format == "json":
        payload = [
            {
                "name": e.name,
                "category": e.category,
                "language": e.language,
                "source": e.source,
                "description": e.description,
                "size": len(e.body),
            }
            for e in entries
        ]
        print(_json.dumps(payload, indent=2))
        return 0

    if not entries:
        print("(no payloads match the given filters)")
        return 0

    name_w = max(len(e.name) for e in entries)
    cat_w = max(len(e.category) for e in entries)
    print(
        f"{'NAME'.ljust(name_w)}  "
        f"{'CATEGORY'.ljust(cat_w)}  "
        f"{'LANG'.ljust(4)}  "
        f"{'SOURCE'.ljust(7)}  DESCRIPTION"
    )
    print("-" * (name_w + cat_w + 4 + 7 + 6 + 30))
    for e in entries:
        print(
            f"{e.name.ljust(name_w)}  "
            f"{e.category.ljust(cat_w)}  "
            f"{e.language.ljust(4)}  "
            f"{e.source.ljust(7)}  {e.description}"
        )
    return 0


def _cmd_info(args: argparse.Namespace) -> int:
    entry = registry.get(args.name)
    if entry is None:
        print(
            f"decoyshield info: unknown payload {args.name!r}. "
            f"Run `decoyshield list` to see available names.",
            file=sys.stderr,
        )
        return 2

    if args.format == "json":
        print(_json.dumps({
            "name": entry.name,
            "category": entry.category,
            "language": entry.language,
            "source": entry.source,
            "description": entry.description,
            "size": len(entry.body),
            "body": entry.body,
        }, indent=2))
        return 0

    print(f"name:        {entry.name}")
    print(f"category:    {entry.category}")
    print(f"language:    {entry.language}")
    print(f"source:      {entry.source}")
    print(f"description: {entry.description}")
    print(f"size:        {len(entry.body)} chars")
    print()
    print("body:")
    print("-" * 60)
    print(entry.body)
    return 0


def _cmd_inject(args: argparse.Namespace) -> int:
    if args.input == "-":
        data = sys.stdin.read()
    else:
        try:
            data = Path(args.input).read_text(encoding="utf-8")
        except FileNotFoundError:
            print(
                f"decoyshield inject: input not found: {args.input}",
                file=sys.stderr,
            )
            return 2

    mode = args.mode
    if mode == "auto":
        stripped = data.lstrip()
        mode = "json" if stripped[:1] in ("{", "[") else "html"

    if mode == "html":
        channels = tuple(
            c.strip() for c in args.channels.split(",") if c.strip()
        )
        out = inject_html(data, channels=channels)
    else:  # json
        try:
            obj = _json.loads(data)
        except _json.JSONDecodeError as e:
            print(f"decoyshield inject: invalid JSON: {e}", file=sys.stderr)
            return 2
        if not isinstance(obj, dict):
            print(
                "decoyshield inject: JSON top-level must be an object",
                file=sys.stderr,
            )
            return 2
        out = _json.dumps(inject_json(obj), indent=2)

    if args.output == "-":
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
    else:
        Path(args.output).write_text(out, encoding="utf-8")
        print(
            f"decoyshield inject: wrote {len(out)} bytes to {args.output}",
            file=sys.stderr,
        )
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    path = Path(args.log)
    if not path.exists():
        print(f"decoyshield analyze: no log at {path}", file=sys.stderr)
        return 2

    events: List[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue

    summary = _summarize(events, top_n=args.limit)
    if args.format == "json":
        print(_json.dumps(summary, indent=2))
    else:
        _print_text(summary, path)
    return 0


def _summarize(events: List[dict], *, top_n: int) -> dict:
    if not events:
        return {"total": 0}
    verdicts = Counter(e.get("verdict", "unknown") for e in events)
    ips = Counter(e.get("ip") for e in events if e.get("ip"))
    uas = Counter(e.get("ua") for e in events if e.get("ua"))
    paths = Counter(e.get("path") for e in events if e.get("path"))
    payloads = Counter(
        p for e in events for p in (e.get("payloads_served") or [])
    )
    times: List[str] = [
        str(e["ts"]) for e in events
        if e.get("ts") is not None
    ]
    return {
        "total": len(events),
        "first_seen": min(times) if times else None,
        "last_seen": max(times) if times else None,
        "verdicts": dict(verdicts),
        "payloads_served": dict(payloads),
        "top_ips": ips.most_common(top_n),
        "top_paths": paths.most_common(top_n),
        "top_uas": uas.most_common(top_n),
    }


def _print_text(s: dict, source: Path) -> None:
    print(f"DecoyShield capture log: {source}")
    print("=" * 60)
    if s.get("total", 0) == 0:
        print("no events")
        return
    print(f"total events:     {s['total']}")
    print(f"first seen:       {s.get('first_seen', '-')}")
    print(f"last seen:        {s.get('last_seen', '-')}")
    print()
    print("verdicts:")
    for v, n in sorted(s["verdicts"].items(), key=lambda x: -x[1]):
        print(f"  {v:<24}  {n}")
    print()
    print("payloads served:")
    for p_name, n in sorted(s["payloads_served"].items(), key=lambda x: -x[1]):
        print(f"  {p_name:<24}  {n}")
    print()
    print(f"top IPs (up to {len(s['top_ips'])}):")
    for ip, n in s["top_ips"]:
        print(f"  {ip:<24}  {n}")
    print()
    print(f"top paths (up to {len(s['top_paths'])}):")
    for p_path, n in s["top_paths"]:
        print(f"  {p_path:<40}  {n}")
    print()
    print(f"top user agents (up to {len(s['top_uas'])}):")
    for ua, n in s["top_uas"]:
        ua_short = (ua[:57] + "...") if len(ua) > 60 else ua
        print(f"  {ua_short:<60}  {n}")


def _cmd_edge(args: argparse.Namespace) -> int:
    from ..edge import caddy, cloudflare, nginx

    if args.platform == "nginx":
        sys.stdout.write(nginx.render())
    elif args.platform == "caddy":
        sys.stdout.write(caddy.render())
    elif args.platform == "cloudflare":
        sys.stdout.write(cloudflare.render(origin=args.origin))
    else:  # argparse choices guards this; defensive only
        print(
            f"decoyshield edge: unknown platform {args.platform!r}",
            file=sys.stderr,
        )
        return 2
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from flask import Flask

    from ..flask_adapter import FlaskHoneypot

    auth = None
    if args.auth:
        if ":" not in args.auth:
            print(
                "decoyshield serve: --auth must be USER:PASS",
                file=sys.stderr,
            )
            return 2
        user, pwd = args.auth.split(":", 1)
        auth = (user, pwd)

    app = Flask("decoyshield-cli")
    FlaskHoneypot(
        app,
        log_path=args.log,
        dashboard_path=args.dashboard_path,
        dashboard_auth=auth,
    )

    base = f"http://{args.host}:{args.port}"
    dash = args.dashboard_path.rstrip("/") + "/dashboard"
    print(
        f"DecoyShield {__version__} listening on {base}",
        file=sys.stderr,
    )
    print(
        "  bait routes:  /  /login  /admin  /api/docs  /api/v1/users  "
        "/.env  /robots.txt",
        file=sys.stderr,
    )
    print(f"  dashboard:    {base}{dash}", file=sys.stderr)
    print(f"  log:          {args.log}", file=sys.stderr)
    if auth is None:
        print(
            "  (dashboard is OPEN; pass --auth USER:PASS to gate it)",
            file=sys.stderr,
        )
    print(file=sys.stderr)
    app.run(host=args.host, port=args.port)
    return 0
