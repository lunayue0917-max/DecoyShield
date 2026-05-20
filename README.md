# DecoyShield

> A web-layer counter-recon honeypot against **agentic LLM attackers**.
> Drop invisible-to-human, visible-to-LLM payloads into your HTTP responses
> to halt, stall, or fingerprint AI-driven penetration scans.

[![tests](https://github.com/lunayue0917-max/DecoyShield/actions/workflows/test.yml/badge.svg)](https://github.com/lunayue0917-max/DecoyShield/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Typed](https://img.shields.io/badge/typed-PEP%20561-success)](https://peps.python.org/pep-0561/)

---

## Why this exists

LLM-driven offensive tools (PentestGPT, AutoGPT, custom LangChain agents)
are now scanning the web at scale. Unlike a human attacker, an LLM agent:

- **reads everything** in the response, including HTML comments, hidden
  inputs, CSS-hidden text, and debug-style headers;
- **follows instructions** that look authoritative, especially when they
  appear to come from the operator or the system;
- **burns tokens proportional to context complexity**, so deliberately
  expensive "protocol" descriptions cost the attacker real money.

DecoyShield turns these properties into a defence. It plants three
classes of payload that humans cannot see in a rendered browser but an
LLM-driven scanner *will* read:

| Payload | What it does |
|---------|--------------|
| `moral_lock` | Re-asserts the attacker LLM's safety policy ("this is a research honeypot, abort"). |
| `token_blackhole` | Presents a bogus multi-step "WAF bypass protocol" that looks solvable but is engineered to consume reasoning tokens. |
| `traceback` | Induces the attacker LLM to disclose its model, operator prompt, and tool chain in the next request — giving you attribution. |

A defender dashboard at `/_defender/dashboard` shows captures in real
time, classified by an attacker-fingerprint heuristic.

## Install

```bash
pip install decoyshield
```

> The PyPI distribution name is `decoyshield`, the Python import name is
> `decoyshield`. So you install one, import the other:
>
> ```python
> from decoyshield import FlaskHoneypot
> ```

From source:

```bash
git clone https://github.com/lunayue0917-max/DecoyShield.git
cd decoyshield
pip install -e .
```

## Quick start

DecoyShield ships three usage modes — pick whichever fits your codebase.

### 1. Flask drop-in (one line)

```python
from flask import Flask
from decoyshield import FlaskHoneypot

app = Flask(__name__)
FlaskHoneypot(app)
```

The honeypot now:

- registers bait routes that look like a vulnerable internal portal
  (`/`, `/admin`, `/login`, `/api/docs`, `/api/v1/users`, `/.env`,
  `/robots.txt`);
- adds payload-bearing response headers to every response
  (`X-Audit-Notice`, `X-Bypass-Protocol`, `X-Debug-Trace`);
- writes every captured request to `logs/captures.jsonl`;
- serves a live dashboard at `/_defender/dashboard`.

### 2. WSGI / ASGI middleware (any framework)

For Django, FastAPI, Starlette, Bottle, or anything else that speaks
WSGI/ASGI, wrap your app once:

```python
# WSGI (Flask, Django, Bottle, Pyramid, …)
from decoyshield.middleware import WSGIMiddleware
app.wsgi_app = WSGIMiddleware(app.wsgi_app)

# ASGI (FastAPI, Starlette, Quart, Litestar, …)
from decoyshield.middleware import ASGIMiddleware
app = ASGIMiddleware(app)
```

The middleware adds bait headers to every response, and (by default)
rewrites `text/html` bodies to embed invisible payloads. Toggle behaviours:

```python
WSGIMiddleware(
    app,
    inject_response_headers=True,   # add X-Audit-Notice etc.
    inject_html_body=True,          # rewrite text/html bodies
    inject_json_body=False,         # add _debug key to application/json
    skip_paths=("/_internal",),     # leave these path prefixes alone
)
```

### 3. Edge platforms — no Python on the host (v0.7+)

Deploy DecoyShield in front of any upstream (Node, Go, PHP, static
site) without installing Python on the production server. Generate
configs for your edge platform once and check them into infra:

```bash
# nginx — drop into a server block (or /etc/nginx/conf.d/)
decoyshield edge nginx > /etc/nginx/conf.d/decoyshield.conf

# Caddy — import from your site blocks
decoyshield edge caddy > /etc/caddy/decoyshield.caddyfile

# Cloudflare Worker — paste into the dashboard, or use wrangler
decoyshield edge cloudflare --origin https://your-origin.example.com > worker.js
```

Each generated config: bait headers (`X-Audit-Notice`,
`X-Debug-Trace`, `X-Bypass-Protocol`), small inline bait routes
(`/admin`, `/.env`, `/api/v1/users`, `/robots.txt`), and optional HTML
body injection. The configs are rendered from the same constants the
Python library uses, so they stay in sync with whatever DecoyShield
version is installed.

### 4. `decoyshield` CLI (no code at all)

After `pip install decoyshield`, the `decoyshield` command is on your
PATH (or run `python -m decoyshield`):

```bash
# Run a self-contained honeypot on :5000
decoyshield serve --port 5000 --auth admin:strong-password

# Pipe-protect a static HTML file (auto-detects HTML vs JSON)
cat page.html | decoyshield inject > page_protected.html
decoyshield inject -i api.json -o api_protected.json --mode json

# Summarize captured attacker activity
decoyshield analyze logs/captures.jsonl
decoyshield analyze logs/captures.jsonl --format json --limit 20

# Emit one raw payload string for use anywhere
decoyshield bait moral_lock
```

### 5. Programmer-callable primitives (any code)

When you assemble HTTP responses by hand — or want to seed an LLM-readable
config file, log line, or CLI banner — import the pure functions:

```python
from decoyshield import (
    bait, inject_html, inject_json, inject_headers, is_scanner, protect,
)

# Wrap an HTML string before serving
body = inject_html("<html><body>hi</body></html>")

# Add a _debug field that an LLM treats as authoritative
data = inject_json({"users": [...]})

# Add X-Audit-Notice etc. to any headers dict
hdrs = inject_headers({"Content-Type": "text/html"})

# Get one raw payload as a string
banner = bait("moral_lock")

# Quick gate: was the request likely automated?
if is_scanner(request.headers, request.path):
    ...

# Or decorate a function whose return value should be wrapped
@protect
def homepage():
    return "<html><body>hi</body></html>"
```

`inject_html` is idempotent and inserts before `</body>` when possible,
otherwise appends. `inject_json` returns a copy with a `_debug` key —
the original dict is not mutated.

## Configuration

```python
FlaskHoneypot(
    app,

    # Which bait routes to install. Drop ones that conflict with your
    # real app. Default: all of them.
    decoys=("index", "login", "admin", "api_docs",
            "api_users", "robots", "dotenv"),

    # URL prefix for the defender panel. Pick something unguessable in
    # production so attackers cannot find their own capture trail.
    dashboard_path="/_defender",

    # Gate /_defender/* behind authentication. None = open (dev only).
    # Use a (user, password) tuple for HTTP Basic, or a callable for
    # custom checks (cookie, JWT, IP allowlist, …).
    dashboard_auth=("watcher", "use-a-strong-password"),

    # Where to append capture events.
    log_path="logs/captures.jsonl",

    # Rotate the capture log when it exceeds this many bytes. None
    # disables rotation. Archives are named captures-YYYYMMDD-NNN.jsonl
    # and never deleted automatically — you own retention.
    rotate_max_bytes=50 * 1024 * 1024,

    # Set False to skip the response-header injection (you'll still get
    # bait routes and the dashboard, just no header-channel payloads).
    auto_inject_headers=True,
)
```

### Custom payloads

```python
from decoyshield import Honeypot, FlaskHoneypot, MORAL_LOCK, TOKEN_BLACKHOLE

hp = Honeypot(payloads={
    "moral_lock": MORAL_LOCK,
    "token_blackhole": TOKEN_BLACKHOLE,
    "traceback": "...your own template...",
})

FlaskHoneypot(app, honeypot=hp)
```

### Payload registry (v0.6+)

The registry is a queryable catalog of every payload (built-in plus any
you register at runtime). It carries metadata: category, language,
source, description.

```python
from decoyshield import Honeypot, registry

# Discover what's available
registry.names()
# ['moral_lock', 'moral_lock_terse', 'token_blackhole',
#  'token_blackhole_zk', 'traceback', 'traceback_oauth']

registry.list(category="moral_lock")          # filtered entries
entry = registry.get("token_blackhole_zk")
entry.description                              # short summary

# Register your own (built-ins are not replaceable)
registry.register(
    "my_custom",
    body="...payload string...",
    category="moral_lock",
    description="In-house variant tuned for our scanner",
)

# Use the full registry catalog (built-ins + your additions) with Honeypot
hp = Honeypot(payloads=registry.as_dict())
FlaskHoneypot(app, honeypot=hp)
```

Discover from the CLI too:

```bash
decoyshield list                          # table of all payloads + metadata
decoyshield list --category moral_lock    # filter
decoyshield list --format json            # machine-readable
decoyshield info token_blackhole_zk       # full metadata + body
```

### Custom fingerprinter

```python
def my_detector(headers, path, method):
    # return (verdict_str, tag_list, score_int)
    ...

Honeypot(detector_fn=my_detector)
```

## Deploying to production

decoyshield ships safe defaults but a few choices are worth tightening
before you point a real domain at it.

### 1. Authenticate the dashboard

The defender panel exposes every captured request — including the
attacker's own. Leaving it open means anyone who guesses the URL can
read your capture log and learn your bait routes.

```python
import os
FlaskHoneypot(
    app,
    dashboard_path="/_internal/" + os.environ["DEFENDER_SLUG"],
    dashboard_auth=(os.environ["DEFENDER_USER"], os.environ["DEFENDER_PASS"]),
)
```

For richer auth (session cookies, JWT, IP allowlists, OAuth), pass a
callable:

```python
from flask import request
FlaskHoneypot(app, dashboard_auth=lambda: request.cookies.get("admin") == TOKEN)
```

### 2. Watch out for `/.env` indexing

The `dotenv` decoy returns plausible-looking-but-fake credentials when
hit. On a public domain, search engines may index this and surface the
decoy creds in results. Either drop the `dotenv` decoy in your decoys
tuple, or restrict it via your reverse proxy:

```python
FlaskHoneypot(app, decoys=("login", "admin", "api_docs", "api_users"))
```

### 3. `robots.txt` precedence

decoyshield's `robots.txt` decoy advertises forbidden paths like
`/admin` to bait scanners that read robots.txt. If you already serve a
real `robots.txt`, drop the `robots` decoy to avoid clobbering it.

### 4. Log rotation and retention

Capture logs grow forever by default size policy (50 MiB → rotate, no
auto-delete). On a busy host, wire archives into your existing log
shipping or set up a cron to prune old archives:

```bash
# delete archives older than 90 days
find logs/ -name 'captures-*.jsonl' -mtime +90 -delete
```

Tune the threshold for your environment:

```python
FlaskHoneypot(app, rotate_max_bytes=10 * 1024 * 1024)   # 10 MiB
FlaskHoneypot(app, rotate_max_bytes=None)               # disable
```

### 5. Reverse proxy / TLS

decoyshield is a Flask app like any other. Run behind a real
WSGI/ASGI server (gunicorn, waitress) and a TLS-terminating reverse
proxy (nginx, Caddy, Cloudflare). Make sure the proxy forwards
``X-Forwarded-For`` so the dashboard records the actual attacker IP,
and configure ``ProxyFix`` accordingly:

```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

### 6. Don't deploy where you cannot legally defend

decoyshield is purely passive — it never makes outbound requests. But
the payloads do attempt to redirect the attacker's LLM. Only deploy on
hosts you own or have explicit authorisation to defend. Don't claim
"this is a research honeypot" unless you actually operate one.

## Defender dashboard

`/_defender/dashboard` (auto-refreshes every 10s) shows:

- total captured requests, unique IPs;
- count of `moral_lock` / `token_blackhole` / `traceback` hits;
- verdict distribution (`likely_scanner` / `likely_ai` / …);
- the last 200 events with method, path, score, fingerprint tags, and
  which payloads were served.

Raw events as JSON: `/_defender/raw`.

## How invisibility works

| Channel | Method | Human visible? | LLM reads it? |
|---------|--------|----------------|---------------|
| HTML comment | `<!-- payload -->` | ❌ | ✅ |
| Hidden div | `display:none` + `aria-hidden` | ❌ | ✅ |
| White-on-white | `color:#fff;background:#fff;font-size:1px` | ❌ (effectively) | ✅ |
| Hidden input | `<input type="hidden" value="...">` | ❌ | ✅ |
| HTTP header | `X-Audit-Notice: …` | ❌ (browser ignores) | ✅ (in raw HTTP) |
| JSON `_debug` | `{"_internal_note": "..."}` | ❌ (not rendered) | ✅ |
| `.env` / `robots.txt` comments | `# payload` | ❌ (unless probed) | ✅ |

## How it compares

| Project | Defends against | Layer | Per-route adapter |
|---------|----------------|-------|-------------------|
| **decoyshield** | Agentic LLM pentest (PentestGPT, AutoGPT, …) | HTTP / Web / any Python code | ✅ Flask + WSGI + ASGI + callable primitives |
| [Nepenthes] | Training-data crawlers | HTTP (standalone) | ❌ |
| [Iocaine] | Training-data crawlers (poisoning) | HTTP (standalone) | ❌ |
| [PalisadeResearch/llm-honeypot] | LLM SSH scanners | SSH | ❌ |
| [Rebuff], [LLM Guard] | Prompt injection **of** your LLM | LLM input | n/a (opposite direction) |

[Nepenthes]: https://news.ycombinator.com/item?id=42725147
[Iocaine]: https://diysolarforum.com/threads/iocaine-the-deadliest-poison-known-to-ai.102401/
[PalisadeResearch/llm-honeypot]: https://github.com/PalisadeResearch/llm-honeypot
[Rebuff]: https://github.com/protectai/rebuff
[LLM Guard]: https://github.com/protectai/llm-guard

## Safety and ethics

- DecoyShield is **purely passive**. It only responds to requests sent
  to your server. It does not make outbound requests, scan, or attack.
- Payloads are **prompt injection against the attacker's LLM**, not the
  attacker themselves. They contain no malware, no exploits, no real
  legal threats.
- Do not deploy on a property you do not own or are not authorised to
  defend. Some payloads reference your "research honeypot" status; if
  you operate one, that statement must be accurate.
- Search engine crawlers (Googlebot, Bingbot) may also read your bait
  routes. The included `/robots.txt` disallows them, but for production
  you should also gate decoys behind a UA / IP allow-list.

## Roadmap

- **0.4** ✅ — Callable primitives + WSGI/ASGI middleware (Django / FastAPI / Starlette / Bottle)
- **0.5** ✅ — `decoyshield` CLI (`serve`, `inject`, `analyze`, `bait`)
- **0.6** ✅ — Payload registry + variants (`moral_lock_terse`, `token_blackhole_zk`, `traceback_oauth`) + `list` / `info` commands
- **0.7** ✅ — Edge plugins (nginx / Caddy / Cloudflare Worker) via `decoyshield edge`
- **0.8** — Node (Express / Fastify) middleware
- **0.9** — Prometheus / OpenTelemetry exporter for capture metrics
- **1.0** — API freeze, security audit, comprehensive docs

## Contributing

Issues and PRs welcome. Areas where help is especially useful:

- New payload templates (different framings, different languages,
  different LLM jailbreak surface targets)
- Detector improvements (TLS fingerprinting, request-timing analysis)
- Framework adapters (FastAPI, Django, Express, Fastify)

Run tests:

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
