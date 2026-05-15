"""
ai-defender — Web-layer counter-recon honeypot against agentic LLM attackers.

Quick start:

    from flask import Flask
    from ai_defender import FlaskHoneypot

    app = Flask(__name__)
    FlaskHoneypot(app)
    app.run()

That's it — your app now has bait routes (/admin, /api/docs, /login,
/.env, /robots.txt), automatic payload injection into all responses,
and a defender dashboard at /_defender/dashboard.
"""
from .core import Honeypot
from .flask_adapter import FlaskHoneypot
from .payloads import MORAL_LOCK, TOKEN_BLACKHOLE, TRACEBACK, PAYLOADS
from .detector import fingerprint

__version__ = "0.2.1"
__all__ = [
    "Honeypot",
    "FlaskHoneypot",
    "MORAL_LOCK",
    "TOKEN_BLACKHOLE",
    "TRACEBACK",
    "PAYLOADS",
    "fingerprint",
]
