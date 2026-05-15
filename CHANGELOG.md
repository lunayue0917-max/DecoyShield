# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/lunayue0917-max/DecoyShield/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.3.0
[0.2.1]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.2.1
[0.2.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.2.0
[0.1.0]: https://github.com/lunayue0917-max/DecoyShield/releases/tag/v0.1.0
