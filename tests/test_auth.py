"""Tests for the optional dashboard authentication."""
import base64

import pytest
from flask import Flask, request

from decoyshield import FlaskHoneypot


def _basic_header(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def authed_client(tmp_path):
    a = Flask(__name__)
    FlaskHoneypot(
        a,
        log_path=str(tmp_path / "c.jsonl"),
        dashboard_auth=("watcher", "s3cret"),
    )
    return a.test_client()


def test_dashboard_blocks_unauthenticated(authed_client):
    r = authed_client.get("/_defender/dashboard")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Basic ")


def test_raw_log_blocks_unauthenticated(authed_client):
    r = authed_client.get("/_defender/raw")
    assert r.status_code == 401


def test_dashboard_accepts_correct_credentials(authed_client):
    r = authed_client.get(
        "/_defender/dashboard",
        headers=_basic_header("watcher", "s3cret"),
    )
    assert r.status_code == 200
    assert b"Capture Dashboard" in r.data


def test_dashboard_rejects_wrong_password(authed_client):
    r = authed_client.get(
        "/_defender/dashboard",
        headers=_basic_header("watcher", "WRONG"),
    )
    assert r.status_code == 401


def test_dashboard_rejects_wrong_user(authed_client):
    r = authed_client.get(
        "/_defender/dashboard",
        headers=_basic_header("intruder", "s3cret"),
    )
    assert r.status_code == 401


def test_unauthed_response_does_not_leak_creds(authed_client):
    r = authed_client.get("/_defender/dashboard")
    body = r.get_data(as_text=True).lower()
    assert "s3cret" not in body
    assert "watcher" not in body


def test_no_auth_by_default(tmp_path):
    """Backward-compat: dashboard_auth defaults to None (no auth)."""
    a = Flask(__name__)
    FlaskHoneypot(a, log_path=str(tmp_path / "c.jsonl"))
    r = a.test_client().get("/_defender/dashboard")
    assert r.status_code == 200


def test_decoy_routes_unaffected_by_dashboard_auth(authed_client):
    """Auth gates /_defender/* only; bait routes stay open."""
    for path in ("/", "/admin", "/api/docs", "/.env", "/robots.txt"):
        r = authed_client.get(path)
        assert r.status_code == 200, f"{path} unexpectedly gated"


def test_callable_auth_allows_when_true(tmp_path):
    a = Flask(__name__)
    FlaskHoneypot(
        a,
        log_path=str(tmp_path / "c.jsonl"),
        dashboard_auth=lambda: request.headers.get("X-Token") == "ok",
    )
    c = a.test_client()
    assert c.get("/_defender/dashboard",
                 headers={"X-Token": "ok"}).status_code == 200
    assert c.get("/_defender/dashboard").status_code == 401


def test_callable_auth_can_check_ip(tmp_path):
    a = Flask(__name__)
    FlaskHoneypot(
        a,
        log_path=str(tmp_path / "c.jsonl"),
        dashboard_auth=lambda: request.remote_addr == "127.0.0.1",
    )
    # Flask test client reports 127.0.0.1 by default
    r = a.test_client().get("/_defender/dashboard")
    assert r.status_code == 200


def test_invalid_auth_type_raises_runtime_error(tmp_path):
    a = Flask(__name__)
    a.testing = True  # propagate exceptions so pytest.raises can catch them
    FlaskHoneypot(
        a,
        log_path=str(tmp_path / "c.jsonl"),
        dashboard_auth=12345,  # type: ignore[arg-type]
    )
    with pytest.raises(TypeError):
        a.test_client().get("/_defender/dashboard")
