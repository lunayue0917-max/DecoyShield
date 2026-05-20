"""Tests for decoyshield.middleware.WSGIMiddleware."""
from typing import Iterable, List, Tuple

from decoyshield.middleware import WSGIMiddleware


def _call(app, path="/", method="GET", environ_extra=None):
    """Invoke a WSGI app and return (status, headers, body_bytes)."""
    captured: dict = {"status": None, "headers": None}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = list(headers)
        return lambda chunk: None

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "SERVER_NAME": "test",
        "SERVER_PORT": "80",
        "wsgi.url_scheme": "http",
    }
    if environ_extra:
        environ.update(environ_extra)

    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


def _html_app(body: bytes = b"<html><body>hi</body></html>"):
    def app(environ, start_response):
        headers: List[Tuple[str, str]] = [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ]
        start_response("200 OK", headers)
        return [body]
    return app


def _json_app(body: bytes = b'{"users": [1, 2, 3]}'):
    def app(environ, start_response):
        headers: List[Tuple[str, str]] = [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ]
        start_response("200 OK", headers)
        return [body]
    return app


def _text_app(body: bytes = b"plain text response"):
    def app(environ, start_response):
        headers = [("Content-Type", "text/plain"),
                   ("Content-Length", str(len(body)))]
        start_response("200 OK", headers)
        return [body]
    return app


def test_wsgi_adds_bait_headers_by_default():
    wrapped = WSGIMiddleware(_html_app())
    _status, headers, _body = _call(wrapped)
    keys = {k.lower() for k, _v in headers}
    assert "x-audit-notice" in keys
    assert "x-debug-trace" in keys
    assert "x-bypass-protocol" in keys


def test_wsgi_can_disable_header_injection():
    wrapped = WSGIMiddleware(_html_app(), inject_response_headers=False)
    _status, headers, _body = _call(wrapped)
    keys = {k.lower() for k, _v in headers}
    assert "x-audit-notice" not in keys


def test_wsgi_injects_html_body():
    wrapped = WSGIMiddleware(_html_app())
    _status, _headers, body = _call(wrapped)
    text = body.decode("utf-8")
    assert "decoyshield" in text
    assert "</body></html>" in text


def test_wsgi_updates_content_length():
    original = b"<html><body>hi</body></html>"
    wrapped = WSGIMiddleware(_html_app(body=original))
    _status, headers, body = _call(wrapped)
    cl = next(v for k, v in headers if k.lower() == "content-length")
    assert int(cl) == len(body)
    assert int(cl) > len(original)


def test_wsgi_leaves_plain_text_body_unchanged():
    wrapped = WSGIMiddleware(_text_app())
    _status, _headers, body = _call(wrapped)
    assert body == b"plain text response"


def test_wsgi_json_injection_off_by_default():
    wrapped = WSGIMiddleware(_json_app())
    _status, _headers, body = _call(wrapped)
    assert body == b'{"users": [1, 2, 3]}'


def test_wsgi_json_injection_opt_in():
    wrapped = WSGIMiddleware(_json_app(), inject_json_body=True)
    _status, _headers, body = _call(wrapped)
    import json
    data = json.loads(body)
    assert data["users"] == [1, 2, 3]
    assert "_debug" in data


def test_wsgi_skip_paths_bypass_middleware():
    wrapped = WSGIMiddleware(_html_app(), skip_paths=("/internal",))
    _status, headers, body = _call(wrapped, path="/internal/dashboard")
    keys = {k.lower() for k, _v in headers}
    assert "x-audit-notice" not in keys
    assert body == b"<html><body>hi</body></html>"


def test_wsgi_can_disable_html_body_injection():
    wrapped = WSGIMiddleware(_html_app(), inject_html_body=False)
    _status, _headers, body = _call(wrapped)
    assert body == b"<html><body>hi</body></html>"


def test_wsgi_integration_with_flask():
    from flask import Flask
    a = Flask(__name__)

    @a.route("/")
    def index():
        return "<html><body>real flask app</body></html>"

    a.wsgi_app = WSGIMiddleware(a.wsgi_app)
    client = a.test_client()
    r = client.get("/")
    assert r.status_code == 200
    assert b"decoyshield" in r.data
    assert "X-Audit-Notice" in r.headers
