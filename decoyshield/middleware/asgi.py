"""
ASGI middleware — wrap any ASGI app to inject DecoyShield bait.

FastAPI::

    from fastapi import FastAPI
    from decoyshield.middleware import ASGIMiddleware

    app = FastAPI()
    app.add_middleware(ASGIMiddleware)

Starlette::

    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from decoyshield.middleware import ASGIMiddleware

    app = Starlette(middleware=[Middleware(ASGIMiddleware)])

Plain ASGI::

    app = ASGIMiddleware(my_asgi_app)

The middleware buffers the response body so it can rewrite HTML before
``</body>``. Streaming responses are concatenated in memory — opt out
per-feature with ``inject_html_body=False`` / ``inject_json_body=False``
when responses are large.
"""
from __future__ import annotations

import json as _json
from typing import Iterable, List, Tuple

from ..core import DEFAULT_RESPONSE_HEADERS
from ..injectors import inject_html, inject_json


class ASGIMiddleware:
    """Wrap an ASGI app, inject DecoyShield payloads into HTTP responses.

    Non-HTTP scopes (lifespan, websocket) are passed through unchanged.

    Args:
        app: The underlying ASGI app.
        inject_response_headers: Add ``X-Audit-Notice`` etc.
        inject_html_body: Rewrite ``text/html`` bodies to embed bait.
        inject_json_body: Add ``_debug`` to top-level dicts of
            ``application/json`` responses. Off by default.
        skip_paths: Path prefixes to bypass entirely.
    """

    def __init__(
        self,
        app,
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

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if self.skip_paths and any(path.startswith(p) for p in self.skip_paths):
            await self.app(scope, receive, send)
            return

        state: dict = {
            "status": 200,
            "headers": [],
            "body": bytearray(),
        }

        async def _send(message):
            mtype = message.get("type")
            if mtype == "http.response.start":
                state["status"] = message["status"]
                state["headers"] = list(message.get("headers", []))
            elif mtype == "http.response.body":
                state["body"].extend(message.get("body", b""))
                if not message.get("more_body", False):
                    await self._flush(state, send)
            else:
                await send(message)

        await self.app(scope, receive, _send)

    async def _flush(self, state: dict, send) -> None:
        headers: List[Tuple[bytes, bytes]] = state["headers"]

        if self.inject_response_headers:
            existing = {h[0].lower() for h in headers}
            for default_name, default_val in DEFAULT_RESPONSE_HEADERS.items():
                if default_name.lower().encode() not in existing:
                    headers.append(
                        (default_name.encode(), default_val.encode())
                    )

        ctype = ""
        for hkey, hval in headers:
            if hkey.lower() == b"content-type":
                ctype = hval.decode("latin-1").lower()
                break

        body: bytes = bytes(state["body"])
        if self.inject_html_body and "text/html" in ctype:
            try:
                body = inject_html(body.decode("utf-8")).encode("utf-8")
            except UnicodeDecodeError:
                pass
        elif self.inject_json_body and "application/json" in ctype:
            try:
                data = _json.loads(body.decode("utf-8"))
                if isinstance(data, dict):
                    body = _json.dumps(inject_json(data)).encode("utf-8")
            except (UnicodeDecodeError, ValueError):
                pass

        new_headers: List[Tuple[bytes, bytes]] = []
        found_cl = False
        for hkey, hval in headers:
            if hkey.lower() == b"content-length":
                new_headers.append((hkey, str(len(body)).encode()))
                found_cl = True
            else:
                new_headers.append((hkey, hval))
        if not found_cl:
            new_headers.append((b"content-length", str(len(body)).encode()))

        await send({
            "type": "http.response.start",
            "status": state["status"],
            "headers": new_headers,
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })
