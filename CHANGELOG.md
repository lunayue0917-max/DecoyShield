# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] — 2026-05-20

**Payload registry.** v0.6 lifts payloads from three hard-coded constants
into a queryable catalog. Three new built-in variants ship out of the
box; you can register your own at runtime and discover everything via
the `decoyshield list` / `decoyshield info` CLI commands.

### Added
- **`decoyshield.registry`** — module-level `PayloadRegistry` instance
  with full metadata (category, language, source, description) per
  entry. Public API:
  ```python
  from decoyshield import registry

  registry.names()                       # all payload names
  registry.list(category="moral_lock")   # filtered entries
  registry.categories()                  # set of distinct categories
  entry = registry.get("moral_lock_terse")
  entry.body, entry.category, entry.language, entry.description

  registry.register(
      "my_custom", body="...", category="moral_lock",
      description="In-house variant tuned for our scanner",
  )
  ```
  Built-in entries cannot be unregistered or overwritten — register
  variants under a new name.

- **Three new built-in payloads** (registry total: 6):
  - **`moral_lock_terse`** — shorter moral_lock for low-context
    channels (HTTP headers, single-line comments).
  - **`token_blackhole_zk`** — fake Groth16-style zero-knowledge proof
    of work; longer Fiat-Shamir derivation chain than the original
    Fermat-decomposition variant.
  - **`traceback_oauth`** — OAuth2 Client Credentials flow handshake
    disguise, eliciting the same identity disclosure as `traceback`
    but framed as an authentication step.

- **`decoyshield list`** — enumerate the registry as a table (text) or
  array of objects (json). Filters: `--category`, `--language`,
  `--source`.

- **`decoyshield info NAME`** — print full metadata + body for a single
  payload. Supports `--format json` for machine consumption.

### Changed
- **`decoyshield bait NAME`** now accepts any registered payload name
  (not just the three originals). Unknown names print a hint pointing
  at `decoyshield list` and exit with code 2 (instead of argparse
  bailing).

### Compatibility
- `PAYLOADS` still maps the three original names; `Honeypot()` /
  `FlaskHoneypot()` defaults are unchanged. Pass
  `Honeypot(payloads=registry.as_dict())` to opt into the full catalog.
- All v0.5 public APIs and CLI behaviour preserved.

## [0.5.0] — 2026-05-20

**Command-line interface.** v0.5 ships the `decoyshield` CLI: run a
standalone honeypot, pipe HTML/JSON through the injectors, analyze a
capture log, or print raw payload strings — without writing any glue
code.

### Added
- **`decoyshield` console script** (registered via
  `[project.scripts]`) and `python -m decoyshield` entry point. Four
  subcommands:
  - **`decoyshield serve`** — boot a self-contained honeypot on
    `host:port`, backed by `FlaskHoneypot`. Flags: `--host`, `--port`,
    `--log`, `--dashboard-path`, `--auth USER:PASS`.
  - **`decoyshield inject`** — read HTML or JSON from a file or stdin,
    embed bait, write to a file or stdout. Auto-detects payload type
    from the first non-whitespace character (`{`/`[` → JSON, otherwise
    HTML). Flags: `--mode auto|html|json`, `-i/--input`, `-o/--output`,
    `--channels` (comma-separated subset of
    `comment,hidden_div,white_text,hidden_input`).
  - **`decoyshield analyze`** — summarize `captures.jsonl`: total
    events, time range, verdict breakdown, top IPs / paths /
    user-agents, payloads-served counts. Flags: `--limit N`,
    `--format text|json`.
  - **`decoyshield bait NAME`** — print one raw payload string to
    stdout. Pipe into config comments, banners, CLI help text, or any
    static file an LLM scanner might read.
- 24 CLI tests covering each subcommand and the `python -m
  decoyshield` module entry path.

### Examples
```bash
# Standalone honeypot for a demo / CTF box
decoyshield serve --port 5000 --auth admin:supersecret

# Pipe-protect a static HTML file
cat page.html | decoyshield inject > page_protected.html

# Quick triage of the capture log
decoyshield analyze logs/captures.jsonl --limit 5

# Seed a config file or banner with a payload
decoyshield bait moral_lock >> /etc/myapp/banner.txt
```

### Compatibility
All v0.4.0 public APIs (Flask drop-in, WSGI/ASGI middleware,
programmer-callable primitives) remain unchanged. The CLI is purely
additive.

## [0.4.0] — 2026-05-20

**DecoyShield as a callable library.** Previously the package shipped a
framework-agnostic core (`Honeypot`) plus a Flask adapter
(`FlaskHoneypot`); v0.4.0 promotes the embedding logic into a flat
top-level API that any program can call directly, and adds WSGI/ASGI
middleware for non-Flask stacks.

### Added
- **Programmer-callable primitives** — pure functions you can call from
  any framework or non-web code:
  ```python
  from decoyshield import (
      bait, inject_html, inject_json, inject_headers, is_scanner,
  )
  body = inject_html("<html><body>hi</body></html>")
  data = inject_json({"users": []})
  hdrs = inject_headers({"Content-Type": "text/html"})
  if is_scanner(request.headers, request.path):
      ...
  ```
  - `inject_html(html, *, payloads=None, channels=...)` — embeds bait
    via configurable channels (`comment`, `hidden_div`, `white_text`,
    `hidden_input`). Idempotent: re-injecting a marked document is a
    no-op.
  - `inject_json(data, *, key="_debug")` — returns a copy with one
    extra key carrying the payload set.
  - `inject_headers(headers)` — augments a headers dict with
    `X-Audit-Notice`, `X-Debug-Trace`, `X-Bypass-Protocol`.
  - `bait(name)` — returns a single raw payload string for manual
    embedding in CLI banners, config comments, or static files.
  - `is_scanner(headers, path, method)` — boolean wrapper around the
    detector for use as an `if` gate.
- **`@protect` decorator** — auto-injects bait into a function's return
  value; auto-detects `str` / `dict` / `(body, status[, headers])`
  tuple-style returns.
- **`decoyshield.middleware.WSGIMiddleware`** — wraps any WSGI app
  (Flask, Django, Bottle, Pyramid, plain WSGI callables). Adds bait
  headers; optionally rewrites `text/html` and `application/json`
  bodies.
- **`decoyshield.middleware.ASGIMiddleware`** — wraps any ASGI app
  (FastAPI, Starlette, Quart, Litestar). Same feature set as the WSGI
  middleware; non-HTTP scopes (lifespan, websocket) pass through
  unchanged.

### Changed
- README documents the three usage modes (Flask drop-in / middleware /
  primitives) explicitly.

### Compatibility
- All v0.3.0 APIs (`Honeypot`, `FlaskHoneypot`, `MORAL_LOCK`,
  `TOKEN_BLACKHOLE`, `TRACEBACK`, `PAYLOADS`, `fingerprint`) remain
  exported with unchanged behaviour. Existing code does not need
  changes.

## [0.3.0] — 2026-05-15

**Project rebranded to DecoyShield.** Every identifier is now
`decoyshield` — GitHub repo, PyPI package, Python import, Claude Code
skill.

### Changed (breaking)
- **PyPI distribution renamed** from `agent-trap` → `decoyshield`.
- **Python import renamed** from `ai_defender` → `decoyshield`. Update
  imports:
  ```python
  # before
  from ai_defender import FlaskHoneypot
  # after
  from decoyshield import FlaskHoneypot
  ```
- **GitHub repo renamed** from `lunayue0917-max/AI-Defender` →
  `lunayue0917-max/DecoyShield`. GitHub automatically redirects the
  old URL, but update bookmarks.
- **Claude Code skill renamed** from `/ai-defender` → `/decoyshield`.
- Brand text in the `MORAL_LOCK` payload and the `X-Audit-Notice`
  response header now reads "DecoyShield" instead of "AI-Defender".

### Migration
This is a pre-1.0 breaking rename. The `agent-trap` package on PyPI
will not receive further releases — pin or upgrade explicitly:
```bash
pip uninstall agent-trap
pip install decoyshield
```

## [0.2.1] — 2026-05-14

First release published to PyPI (as `agent-trap`; superseded by
`decoyshield` in 0.3.0). No runtime changes from 0.2.0.

### Added
- `.github/workflows/release.yml` — on tag push, builds sdist + wheel
  and publishes to PyPI via the OIDC trusted publisher bound to the
  GitHub `pypi` environment. No PyPI API token is stored in the repo.

### Changed
- Synced the package `__version__` with `pyproject.toml` (was lagging
  at 0.1.0).

## [0.2.0] — 2026-05-14

### Added
- **Dashboard authentication** — `FlaskHoneypot(dashboard_auth=...)` accepts
  `None` (default, open), an `("user", "password")` tuple for HTTP basic
  auth, or a `callable() -> bool` for custom auth predicates (cookie,
  JWT, IP allowlist, etc.). Comparisons are constant-time via
  `hmac.compare_digest`.
- **Capture-log rotation** — `CaptureLog` and `Honeypot` accept
  `rotate_max_bytes` (default 50 MiB). The active file is atomically
  renamed to `captures-YYYYMMDD-NNN.jsonl` when it exceeds the threshold;
  `rotate_max_bytes=None` disables rotation. `CaptureLog.archives()`
  lists historic files.
- **PEP 561 type information** — every public API now has type hints, and
  the package ships a `py.typed` marker so downstream type-checkers
  consume them directly.
- **CI** — GitHub Actions workflow runs pytest across ubuntu/windows ×
  Python 3.9–3.13, plus a separate mypy job.
- **Production deployment guide** in README covering dashboard auth,
  decoy gating, log retention, and proxy/TLS configuration.

### Changed
- `CLAUDE.md` is no longer tracked in the public repo (it is the local
  Claude Code project-instructions file).

## [0.1.0] — 2026-05-14

Initial release.

### Added
- `Honeypot` framework-agnostic core (payloads, detector, capture log).
- `FlaskHoneypot` one-line Flask integration that registers:
  - bait routes: `/`, `/login`, `/admin`, `/api/docs`, `/api/v1/users`,
    `/robots.txt`, `/.env`
  - defender dashboard at `/_defender/dashboard`
  - raw capture JSON at `/_defender/raw`
- Three built-in payload categories:
  - `moral_lock` — reverse prompt-injection that re-asserts safety policy
    on the attacker's LLM
  - `token_blackhole` — bogus multi-step "WAF bypass protocol" designed
    to consume reasoning tokens
  - `traceback` — handshake that induces the attacker's LLM to disclose
    its model, operator instruction, and tool chain
- Heuristic request fingerprinting (`decoyshield.detector.fingerprint`)
  classifying requests as `likely_scanner` / `likely_ai` /
  `likely_automation` / `likely_human` / `unknown` with score and tags.
- JSONL capture log with auto-rotating safe append (`CaptureLog`).
- Customisable payloads, decoy subset, dashboard prefix, log path.
- Examples: `examples/flask_demo.py`, `examples/custom_payloads.py`.
- MIT license, packaging via `pyproject.toml`.

[Unreleased]: https://github.com/lunayue0917-max/DecoyShield/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.6.0
[0.5.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.5.0
[0.4.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.4.0
[0.3.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.3.0
[0.2.1]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.2.1
[0.2.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.2.0
[0.1.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.1.0
