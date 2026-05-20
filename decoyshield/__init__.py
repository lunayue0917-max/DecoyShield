"""
decoyshield — Counter-recon honeypot toolkit against agentic LLM attackers.

Three usage modes, pick whichever fits your codebase:

1. **Drop-in Flask app** — one line:

       from flask import Flask
       from decoyshield import FlaskHoneypot

       app = Flask(__name__)
       FlaskHoneypot(app)

2. **Framework-agnostic middleware** — Django / FastAPI / Starlette /
   Bottle / plain WSGI / ASGI:

       from decoyshield.middleware import WSGIMiddleware, ASGIMiddleware

       app.wsgi_app = WSGIMiddleware(app.wsgi_app)       # WSGI
       app = ASGIMiddleware(app)                          # ASGI

3. **Programmer-callable primitives** — embed in any code that emits
   HTTP responses, files, or LLM-readable text:

       from decoyshield import inject_html, inject_json, inject_headers
       from decoyshield import bait, is_scanner, protect

       body = inject_html("<html><body>hi</body></html>")
       data = inject_json({"users": []})
       hdrs = inject_headers({"Content-Type": "text/html"})

       @protect
       def render():
           return "<html><body>...</body></html>"
"""
from .core import Honeypot
from .decorators import protect
from .detector import fingerprint
from .flask_adapter import FlaskHoneypot
from .injectors import (
    bait,
    inject_headers,
    inject_html,
    inject_json,
    is_scanner,
)
from .payloads import MORAL_LOCK, PAYLOADS, TOKEN_BLACKHOLE, TRACEBACK

__version__ = "0.4.0"
__all__ = [
    # framework adapters
    "Honeypot",
    "FlaskHoneypot",
    # programmer-callable primitives (v0.4)
    "bait",
    "inject_html",
    "inject_json",
    "inject_headers",
    "is_scanner",
    "protect",
    # raw payloads / lower-level fingerprinter
    "MORAL_LOCK",
    "TOKEN_BLACKHOLE",
    "TRACEBACK",
    "PAYLOADS",
    "fingerprint",
]
