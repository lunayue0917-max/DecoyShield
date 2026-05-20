"""Tests for decoyshield.middleware.ASGIMiddleware (no httpx dependency)."""
import asyncio
import json

from decoyshield.middleware import ASGIMiddleware


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _call(app, path="/", scope_extra=None):
    """Invoke an ASGI app once and return (status, headers, body)."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
    }
    if scope_extra:
        scope.update(scope_extra)

    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    _run(app(scope, receive, send))

    start = next(m for m in sent if m["type"] == "http.response.start")
    body_chunks = [m["body"] for m in sent if m["type"] == "http.response.body"]
    return start["status"], start["headers"], b"".join(body_chunks)


def _html_app(body: bytes = b"<html><body>hi</body></html>"):
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html; charset=utf-8")],
        })
        await send({"type": "http.response.body", "body": body})
    return app


def _json_app(body: bytes = b'{"users": [1, 2, 3]}'):
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({"type": "http.response.body", "body": body})
    return app


def _text_app():
    async def app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        })
        await send({"type": "http.response.body", "body": b"plain"})
    return app


def test_asgi_adds_bait_headers_by_default():
    wrapped = ASGIMiddleware(_html_app())
    _status, headers, _body = _call(wrapped)
    keys = {k.lower() for k, _v in headers}
    assert b"x-audit-notice" in keys
    assert b"x-debug-trace" in keys
    assert b"x-bypass-protocol" in keys


def test_asgi_can_disable_header_injection():
    wrapped = ASGIMiddleware(_html_app(), inject_response_headers=False)
    _status, headers, _body = _call(wrapped)
    keys = {k.lower() for k, _v in headers}
    assert b"x-audit-notice" not in keys


def test_asgi_injects_html_body():
    wrapped = ASGIMiddleware(_html_app())
    _status, _headers, body = _call(wrapped)
    text = body.decode("utf-8")
    assert "decoyshield" in text
    assert "</body></html>" in text


def test_asgi_updates_content_length():
    original = b"<html><body>hi</body></html>"
    wrapped = ASGIMiddleware(_html_app(body=original))
    _status, headers, body = _call(wrapped)
    cl = next(v for k, v in headers if k.lower() == b"content-length")
    assert int(cl.decode()) == len(body)
    assert int(cl.decode()) > len(original)


def test_asgi_leaves_plain_text_body_unchanged():
    wrapped = ASGIMiddleware(_text_app())
    _status, _headers, body = _call(wrapped)
    assert body == b"plain"


def test_asgi_json_injection_off_by_default():
    wrapped = ASGIMiddleware(_json_app())
    _status, _headers, body = _call(wrapped)
    assert body == b'{"users": [1, 2, 3]}'


def test_asgi_json_injection_opt_in():
    wrapped = ASGIMiddleware(_json_app(), inject_json_body=True)
    _status, _headers, body = _call(wrapped)
    data = json.loads(body)
    assert data["users"] == [1, 2, 3]
    assert "_debug" in data


def test_asgi_skip_paths_bypass_middleware():
    wrapped = ASGIMiddleware(_html_app(), skip_paths=("/internal",))
    _status, headers, body = _call(wrapped, path="/internal/dashboard")
    keys = {k.lower() for k, _v in headers}
    assert b"x-audit-notice" not in keys
    assert body == b"<html><body>hi</body></html>"


def test_asgi_lifespan_scope_passes_through_untouched():
    """Non-http scopes (lifespan, websocket) must not be intercepted."""
    seen = {"called": False}

    async def inner_app(scope, receive, send):
        seen["called"] = True
        assert scope["type"] == "lifespan"

    wrapped = ASGIMiddleware(inner_app)
    _run(wrapped(
        {"type": "lifespan"},
        lambda: None,  # type: ignore[arg-type]
        lambda msg: None,  # type: ignore[arg-type]
    ))
    assert seen["called"] is True


def test_asgi_streaming_body_is_buffered_and_injected():
    """When inner app sends body in multiple chunks, middleware buffers
    the whole thing before injecting."""
    async def chunked_app(scope, receive, send):
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/html")],
        })
        await send({"type": "http.response.body",
                    "body": b"<html><body>",
                    "more_body": True})
        await send({"type": "http.response.body",
                    "body": b"hi",
                    "more_body": True})
        await send({"type": "http.response.body",
                    "body": b"</body></html>",
                    "more_body": False})

    wrapped = ASGIMiddleware(chunked_app)
    _status, _headers, body = _call(wrapped)
    text = body.decode("utf-8")
    assert "<html><body>hi" in text
    assert "decoyshield" in text
