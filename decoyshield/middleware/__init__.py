"""
Framework-agnostic middleware for DecoyShield.

* :class:`WSGIMiddleware` — wraps any WSGI app (Flask, Django, Bottle,
  Pyramid, plain WSGI callables).
* :class:`ASGIMiddleware` — wraps any ASGI app (FastAPI, Starlette,
  Quart, Litestar).

Both inject bait headers and (optionally) inject HTML / JSON bait into
the response body. Pick one matching your stack; do not stack them.
"""
from .asgi import ASGIMiddleware
from .wsgi import WSGIMiddleware

__all__ = ["WSGIMiddleware", "ASGIMiddleware"]
