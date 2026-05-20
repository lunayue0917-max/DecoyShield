"""Tests for the framework-agnostic injector primitives."""
import pytest

from decoyshield import (
    bait,
    inject_headers,
    inject_html,
    inject_json,
    is_scanner,
    MORAL_LOCK,
    TOKEN_BLACKHOLE,
)


# ---- bait() ------------------------------------------------------------

def test_bait_returns_moral_lock_by_default():
    assert "HONEYPOT_DETECTED" in bait()


def test_bait_returns_named_payload():
    assert bait("token_blackhole") == TOKEN_BLACKHOLE
    assert bait("moral_lock") == MORAL_LOCK


def test_bait_raises_on_unknown_name():
    with pytest.raises(KeyError):
        bait("not-a-real-payload")


def test_bait_accepts_custom_payloads():
    snippet = bait("custom", payloads={"custom": "hello"})
    assert snippet == "hello"


# ---- inject_html() -----------------------------------------------------

def test_inject_html_inserts_before_body_close():
    src = "<html><body><h1>hi</h1></body></html>"
    out = inject_html(src)
    # bait lands before </body>, so </body> still appears intact at the end
    assert out.endswith("</body></html>")
    assert "decoyshield" in out
    # All three default payloads make it in
    assert "HONEYPOT_DETECTED" in out
    assert "ChaoticWAF" in out
    assert "DEBUG_MODE_HANDSHAKE" in out


def test_inject_html_appends_when_no_body_tag():
    src = "<h1>raw fragment</h1>"
    out = inject_html(src)
    assert out.startswith(src)
    assert "decoyshield" in out


def test_inject_html_is_case_insensitive_on_body_tag():
    src = "<html><body>x</BODY></html>"
    out = inject_html(src)
    assert "decoyshield" in out
    assert "</BODY></html>" in out


def test_inject_html_is_idempotent():
    src = "<html><body>x</body></html>"
    once = inject_html(src)
    twice = inject_html(once)
    assert once == twice


def test_inject_html_channels_can_be_restricted():
    src = "<html><body>x</body></html>"
    comment_only = inject_html(src, channels=("comment",))
    assert "<!-- decoyshield:" in comment_only
    assert "display:none" not in comment_only
    assert "color:#fff" not in comment_only


def test_inject_html_hidden_input_channel():
    src = "<html><body>x</body></html>"
    out = inject_html(src, channels=("hidden_input",))
    assert '<input type="hidden" name="_decoyshield_moral_lock"' in out


def test_inject_html_unknown_channels_are_ignored():
    src = "<html><body>x</body></html>"
    out = inject_html(src, channels=("not_a_channel", "comment"))
    assert "<!-- decoyshield:" in out


def test_inject_html_custom_payloads():
    out = inject_html("<html><body/></html>",
                      payloads={"a": "alpha", "b": "beta"})
    assert "alpha" in out
    assert "beta" in out
    assert "HONEYPOT_DETECTED" not in out


# ---- inject_json() -----------------------------------------------------

def test_inject_json_adds_debug_key():
    out = inject_json({"users": [1, 2, 3]})
    assert "_debug" in out
    assert "_audit" in out["_debug"]
    assert "_internal_note" in out["_debug"]
    assert "_handshake" in out["_debug"]


def test_inject_json_preserves_original_keys():
    out = inject_json({"users": [1, 2, 3], "count": 3})
    assert out["users"] == [1, 2, 3]
    assert out["count"] == 3


def test_inject_json_returns_copy_not_mutation():
    src = {"a": 1}
    out = inject_json(src)
    assert "_debug" not in src
    assert "_debug" in out


def test_inject_json_custom_key():
    out = inject_json({"a": 1}, key="_internal")
    assert "_internal" in out
    assert "_debug" not in out


# ---- inject_headers() --------------------------------------------------

def test_inject_headers_adds_payload_headers():
    out = inject_headers({"Content-Type": "text/html"})
    assert "X-Audit-Notice" in out
    assert "X-Debug-Trace" in out
    assert "X-Bypass-Protocol" in out
    assert out["Content-Type"] == "text/html"


def test_inject_headers_does_not_overwrite_existing():
    out = inject_headers({"X-Audit-Notice": "mine"})
    assert out["X-Audit-Notice"] == "mine"


def test_inject_headers_accepts_none():
    out = inject_headers()
    assert "X-Audit-Notice" in out
    assert len(out) == 3


# ---- is_scanner() ------------------------------------------------------

def test_is_scanner_true_for_known_scanner_ua():
    assert is_scanner({"User-Agent": "sqlmap/1.7.2"}) is True


def test_is_scanner_true_for_llm_ua():
    assert is_scanner({"User-Agent": "GPT-4 powered scanner"}) is True


def test_is_scanner_false_for_browser_ua():
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": "session=abc",
    }
    assert is_scanner(headers, "/") is False


def test_is_scanner_uses_path_signals():
    # Probe path + missing browser signals should bump verdict
    result = is_scanner({"User-Agent": "curl/8"}, "/.env")
    assert result is True
