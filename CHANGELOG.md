# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Heuristic request fingerprinting (`ai_defender.detector.fingerprint`)
  classifying requests as `likely_scanner` / `likely_ai` /
  `likely_automation` / `likely_human` / `unknown` with score and tags.
- JSONL capture log with auto-rotating safe append (`CaptureLog`).
- Customisable payloads, decoy subset, dashboard prefix, log path.
- Examples: `examples/flask_demo.py`, `examples/custom_payloads.py`.
- MIT license, packaging via `pyproject.toml`.

[Unreleased]: https://github.com/lunayue0917-max/AI-Defender/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/lunayue0917-max/AI-Defender/releases/tag/v0.2.0
[0.1.0]: https://github.com/lunayue0917-max/AI-Defender/releases/tag/v0.1.0
