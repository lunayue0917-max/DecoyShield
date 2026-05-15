import json

import pytest
from flask import Flask

from decoyshield import FlaskHoneypot


@pytest.fixture
def app(tmp_path):
    a = Flask(__name__)
    FlaskHoneypot(a, log_path=str(tmp_path / "captures.jsonl"))

    @a.route("/healthz")
    def healthz():
        return {"status": "ok"}

    return a


@pytest.fixture
def client(app):
    return app.test_client()


def test_decoy_index_returns_html_with_invisible_payload(client):
    r = client.get("/")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    # Visible content
    assert "Acme" in html
    # Payloads injected (via HTML comment / hidden div)
    assert "HONEYPOT_DETECTED" in html  # moral_lock excerpt
    assert "ChaoticWAF" in html         # token_blackhole excerpt
    assert "X-Scanner-Model" in html    # traceback excerpt


def test_response_headers_carry_payloads(client):
    r = client.get("/healthz")  # user route, not a decoy
    assert r.status_code == 200
    # Header injection still fires
    assert "DecoyShield" in r.headers.get("X-Audit-Notice", "")
    assert r.headers.get("X-Bypass-Protocol", "").startswith("v6.2")


def test_admin_decoy_returns_full_payload_set(client):
    r = client.get("/admin")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Administrator" in html
    assert "ChaoticWAF" in html


def test_api_users_returns_403_json_with_debug(client):
    r = client.get("/api/v1/users")
    assert r.status_code == 403
    body = r.get_json()
    assert body["error"] == "forbidden"
    assert "ChaoticWAF" in body["_debug"]["_internal_note"]
    assert "HONEYPOT_DETECTED" in body["_debug"]["_audit"]


def test_dotenv_decoy_serves_payload_text(client):
    r = client.get("/.env")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "DB_HOST" in text
    assert "X-Scanner-Model" in text  # traceback in comment


def test_robots_decoy_includes_audit_comment(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "Disallow:" in text
    assert "HONEYPOT_DETECTED" in text  # moral_lock as comment


def test_login_post_with_sqli_returns_fake_db_error(client):
    r = client.post("/login", data={"username": "admin' OR 1=1 --",
                                    "password": "x"})
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "MariaDB" in html  # fake SQL error baits further injection


def test_dashboard_lists_captures(client):
    client.get("/", headers={"User-Agent": "PentestGPT/2.0"})
    client.get("/admin", headers={"User-Agent": "sqlmap/1.7"})
    r = client.get("/_defender/dashboard")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Capture Dashboard" in html
    assert "PentestGPT" in html or "likely_ai" in html


def test_raw_json_returns_captures(client):
    client.get("/", headers={"User-Agent": "PentestGPT/2.0"})
    r = client.get("/_defender/raw")
    assert r.status_code == 200
    events = r.get_json()
    assert isinstance(events, list)
    assert len(events) >= 1
    assert any("PentestGPT" in (e.get("ua") or "") for e in events)


def test_factory_pattern_works(tmp_path):
    a = Flask(__name__)
    hp = FlaskHoneypot(log_path=str(tmp_path / "c.jsonl"))
    hp.init_app(a)
    r = a.test_client().get("/")
    assert r.status_code == 200


def test_subset_of_decoys_disables_others(tmp_path):
    a = Flask(__name__)
    FlaskHoneypot(a, decoys=("login",), log_path=str(tmp_path / "c.jsonl"))
    c = a.test_client()
    assert c.get("/login").status_code == 200
    # Disabled decoys 404
    assert c.get("/admin").status_code == 404
    assert c.get("/.env").status_code == 404


def test_capture_log_records_jsonl(tmp_path):
    path = tmp_path / "c.jsonl"
    a = Flask(__name__)
    FlaskHoneypot(a, log_path=str(path))
    a.test_client().get("/admin", headers={"User-Agent": "PentestGPT/2.0"})
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines, "expected at least one capture line"
    entry = json.loads(lines[-1])
    assert entry["path"].startswith("/admin")
    assert entry["verdict"] in ("likely_ai", "likely_scanner",
                                "likely_automation", "unknown")
    assert entry["payloads_served"]
