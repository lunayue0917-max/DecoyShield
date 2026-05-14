# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/lunayue0917-max/AI-Defender/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lunayue0917-max/AI-Defender/releases/tag/v0.1.0
