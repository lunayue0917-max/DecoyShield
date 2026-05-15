---
name: decoyshield
description: Add DecoyShield honeypot protection to a Python web app to defend against agentic LLM attackers (PentestGPT, AutoGPT, custom LangChain scanners). Use when the user asks to defend their Flask/web service against AI-driven penetration testing, asks to add "prompt injection honeypot" or "anti-LLM-scanner" defenses, asks to integrate decoyshield, or mentions wanting their app to detect / stall / fingerprint LLM-driven scans.
---

# decoyshield skill

When invoked, you are integrating the **decoyshield** Python package into
the current project so that the user's web service plants payloads that
are invisible to humans but visible to LLM-driven scanners.

The package implements three payload categories:

1. `moral_lock` — reverse prompt-injection that re-asserts safety policy
   on the attacker's LLM ("this is a research honeypot, abort").
2. `token_blackhole` — bogus multi-step "WAF bypass protocol" engineered
   to consume the attacker LLM's reasoning tokens.
3. `traceback` — induces the attacker LLM to disclose its own model,
   operator instruction, and tool chain on its next request.

Repository: https://github.com/lunayue0917-max/DecoyShield

## Step 1 — figure out the integration target

Look at the project layout before touching anything:

- Is there a Flask app? Look for `Flask(__name__)`, `app.run()`, common
  files like `app.py`, `wsgi.py`, `application.py`, `src/<pkg>/__init__.py`.
- Is there a FastAPI / Django / other framework? decoyshield currently
  ships a Flask adapter only — if the project is FastAPI/Django, tell
  the user and offer to (a) scaffold a tiny Flask sidecar that runs the
  honeypot on a sibling port, or (b) wait for v0.2 which adds FastAPI.
  Don't pretend to add Flask middleware to a FastAPI app.
- Is there a `requirements.txt` / `pyproject.toml` / `Pipfile` / `uv.lock`?
  Use whichever the project uses.

## Step 2 — add the dependency

Add `decoyshield>=0.1.0` to the relevant manifest:

- `requirements.txt`: append `decoyshield>=0.1.0`
- `pyproject.toml`: add to `[project] dependencies`
- `Pipfile`: add under `[packages]`

Do not run `pip install` unless the user asked. Mention the install
command in your summary instead.

## Step 3 — wire the middleware

Find the Flask app factory or top-level `app = Flask(...)` and add one
line right after the app is constructed:

```python
from decoyshield import FlaskHoneypot
FlaskHoneypot(app)
```

If the user has existing routes that overlap with default decoys
(`/`, `/login`, `/admin`, `/api/docs`, `/api/v1/users`, `/.env`,
`/robots.txt`), do not silently overwrite them. Instead, configure a
subset:

```python
FlaskHoneypot(app, decoys=("login", "api_docs", "dotenv"))
```

If the user has their own `/` route, drop `"index"` from decoys. Same
for `/admin`, `/api/docs`, etc.

For production deployments, also recommend customising the dashboard
URL prefix so the capture trail is not discoverable:

```python
FlaskHoneypot(app, dashboard_path="/_internal/<unguessable>")
```

## Step 4 — log directory + gitignore

Ensure `logs/` exists and is gitignored. Append `logs/` and `*.jsonl`
to `.gitignore` if not already present. Do NOT create or commit any
existing capture files — they may contain real attacker fingerprints
and IPs the user does not want in public history.

## Step 5 — what to tell the user

Summarise in this order:

1. Files you changed (paths + one-line description each).
2. The install command (`pip install decoyshield` or framework-equivalent).
3. The defender dashboard URL (e.g. `http://localhost:5000/_defender/dashboard`).
4. A *one-sentence* safety reminder: decoyshield is purely passive,
   responds only to inbound requests, and contains no real legal
   threats or exploits.
5. Suggest a way to test it: hit the app with `curl -A 'PentestGPT/2.0 python-requests'`
   and check the dashboard.

## Things to never do

- Never enable header-injection on a production app without warning the
  user — `X-Audit-Notice` headers in responses *will* be picked up by
  some monitoring tools and may produce false alerts.
- Never replace the user's existing routes. Always use the `decoys`
  parameter to restrict what gets registered.
- Never commit `logs/captures.jsonl`.
- Never run the user's server yourself unless asked. After wiring the
  code, stop and let the user run it.
- Never claim decoyshield blocks attacks. It does not. It is a
  honeypot: it observes, stalls, and re-injects guidance, but a
  sufficiently determined attacker who sanitises HTML before feeding it
  to their LLM will defeat it. Set expectations honestly.

## Useful one-liners

```python
# Default integration (all decoys, dashboard at /_defender)
FlaskHoneypot(app)

# Header injection only (no decoy routes)
FlaskHoneypot(app, decoys=())

# Decoys only, no response header injection
FlaskHoneypot(app, auto_inject_headers=False)

# Custom log path and dashboard prefix
FlaskHoneypot(app, log_path="/var/log/honeypot.jsonl",
              dashboard_path="/internal/honeypot")

# Bring your own payloads
from decoyshield import Honeypot
hp = Honeypot(payloads={"moral_lock": "...", "token_blackhole": "...",
                        "traceback": "..."})
FlaskHoneypot(app, honeypot=hp)
```
