"""
Decorator API — protect any function that returns a response without
threading injectors through your call sites by hand.

    from decoyshield import protect

    @protect
    def homepage():
        return "<html><body>hi</body></html>"

    @protect(kind="json")
    def users_api():
        return {"users": [...]}

``@protect`` auto-detects return types: ``str`` is treated as HTML,
``dict`` as JSON, and ``(body, status)`` / ``(body, status, headers)``
tuples (Flask-style) are unpacked and re-packed.
"""
from __future__ import annotations

import functools
from typing import Any, Callable

from .injectors import inject_html, inject_json


def protect(
    fn: Any = None,
    *,
    kind: str = "auto",
) -> Callable:
    """Decorate a function so its return value gets bait injected.

    Args:
        kind: ``"auto"`` (default) — detect from return type. ``"html"``
            forces HTML injection (treats the result as a string).
            ``"json"`` forces JSON injection (treats the result as a
            dict).
    """
    if kind not in ("auto", "html", "json"):
        raise ValueError(
            f"protect kind must be auto/html/json, got {kind!r}"
        )

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return _apply(f(*args, **kwargs), kind)
        return wrapper

    if fn is not None and callable(fn):
        return decorator(fn)
    return decorator


def _apply(result, kind: str):
    if kind == "html":
        return inject_html(result)
    if kind == "json":
        return inject_json(result)

    # auto
    if isinstance(result, str):
        return inject_html(result)
    if isinstance(result, dict):
        return inject_json(result)
    if isinstance(result, tuple) and result:
        head, *rest = result
        if isinstance(head, str):
            return (inject_html(head), *rest)
        if isinstance(head, dict):
            return (inject_json(head), *rest)
    return result
