"""
WSGI middleware — wrap any WSGI app to inject DecoyShield bait.

    from flask import Flask
    from decoyshield.middleware import WSGIMiddleware

    app = Flask(__name__)
    app.wsgi_app = WSGIMiddleware(app.wsgi_app)

Django (``wsgi.py``)::

    from django.core.wsgi import get_wsgi_application
    from decoyshield.middleware import WSGIMiddleware

    application = WSGIMiddleware(get_wsgi_application())

The middleware buffers the response body so it can rewrite HTML before
``</body>`` / extend JSON with a ``_debug`` field. Large streaming
responses are buffered in full — keep that in mind for endpoints that
return multi-megabyte payloads (set ``inject_html_body=False`` /
``inject_json_body=False`` to opt out per-feature).
"""
from __future__ import annotations

import json as _json
from typing import Callable, Iterable, List, Tuple

from ..core import DEFAULT_RESPONSE_HEADERS
from ..injectors import inject_html, inject_json

WSGIApp = Callable
StartResponse = Callable


class WSGIMiddleware:
    """Wrap a WSGI app, inject DecoyShield payloads into responses.

    Args:
        app: The underlying WSGI callable to wrap.
        inject_response_headers: Add ``X-Audit-Notice`` etc. to every
            response.
        inject_html_body: When ``Content-Type`` is ``text/html``, rewrite
            the body to embed invisible bait.
        inject_json_body: When ``Content-Type`` is ``application/json``,
            add a ``_debug`` key to top-level dicts. Disabled by default
            because it alters the response shape.
        skip_paths: Iterable of path prefixes to leave untouched (e.g.
            your real API endpoints, or internal dashboards).
    """

    def __init__(
        self,
        app: WSGIApp,
        *,
        inject_response_headers: bool = True,
        inject_html_body: bool = True,
        inject_json_body: bool = False,
        skip_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.inject_response_headers = inject_response_headers
        self.inject_html_body = inject_html_body
        self.inject_json_body = inject_json_body
        self.skip_paths = tuple(skip_paths)

    def __call__(
        self,
        environ: dict,
        start_response: StartResponse,
    ) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        if self.skip_paths and any(path.startswith(p) for p in self.skip_paths):
            return self.app(environ, start_response)

        captured: dict = {"status": None, "headers": None, "exc_info": None}

        def _capture(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = list(headers)
            captured["exc_info"] = exc_info

            def _write(_chunk: bytes) -> None:  # legacy write callable
                return None

            return _write

        body_iter = self.app(environ, _capture)
        try:
            chunks: List[bytes] = list(body_iter)
        finally:
            close = getattr(body_iter, "close", None)
            if close is not None:
                close()
        raw = b"".join(chunks)

        headers: List[Tuple[str, str]] = captured["headers"] or []

        if self.inject_response_headers:
            existing = {k.lower() for k, _v in headers}
            for k, v in DEFAULT_RESPONSE_HEADERS.items():
                if k.lower() not in existing:
                    headers.append((k, v))

        ctype = ""
        for k, v in headers:
            if k.lower() == "content-type":
                ctype = v.lower()
                break

        if self.inject_html_body and "text/html" in ctype:
            try:
                raw = inject_html(raw.decode("utf-8")).encode("utf-8")
            except UnicodeDecodeError:
                pass
        elif self.inject_json_body and "application/json" in ctype:
            try:
                data = _json.loads(raw.decode("utf-8"))
                if isinstance(data, dict):
                    raw = _json.dumps(inject_json(data)).encode("utf-8")
            except (UnicodeDecodeError, ValueError):
                pass

        new_headers: List[Tuple[str, str]] = []
        found_cl = False
        for k, v in headers:
            if k.lower() == "content-length":
                new_headers.append((k, str(len(raw))))
                found_cl = True
            else:
                new_headers.append((k, v))
        if not found_cl:
            new_headers.append(("Content-Length", str(len(raw))))

        start_response(captured["status"], new_headers, captured["exc_info"])
        return [raw]
