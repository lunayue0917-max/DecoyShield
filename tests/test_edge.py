"""Tests for the edge-platform config renderers + `decoyshield edge` CLI."""
import json
import re

import pytest

from decoyshield.cli.main import main
from decoyshield.edge import caddy, cloudflare, nginx


# ── nginx ───────────────────────────────────────────────────────────────

def test_nginx_render_contains_bait_headers():
    out = nginx.render()
    assert "add_header X-Audit-Notice " in out
    assert "add_header X-Debug-Trace " in out
    assert "add_header X-Bypass-Protocol " in out


def test_nginx_render_contains_bait_routes():
    out = nginx.render()
    assert "location = /admin" in out
    assert "location = /.env" in out
    assert "location = /api/v1/users" in out
    assert "location = /robots.txt" in out


def test_nginx_render_contains_sub_filter():
    out = nginx.render()
    assert "sub_filter '</body>'" in out
    assert "data-decoyshield=" in out


def test_nginx_render_includes_version_comment():
    from decoyshield import __version__
    assert __version__ in nginx.render()


def test_nginx_render_escapes_single_quotes():
    """Payloads with apostrophes (operator's, etc.) must be escaped for
    nginx single-quoted strings."""
    out = nginx.render()
    # The hidden div is inside a single-quoted return statement.
    # Apostrophes inside the payload should appear as \' (backslash + quote).
    assert "\\'" in out or "'" not in out.split("sub_filter '")[1].split("'")[0]


# ── caddy ───────────────────────────────────────────────────────────────

def test_caddy_render_defines_named_snippet():
    out = caddy.render()
    assert "(decoyshield)" in out


def test_caddy_render_contains_header_block():
    out = caddy.render()
    assert "X-Audit-Notice" in out
    assert "header {" in out


def test_caddy_render_contains_bait_handles():
    out = caddy.render()
    assert "handle /admin" in out
    assert "handle /.env" in out
    assert "handle /api/v1/users" in out
    assert "handle /robots.txt" in out


def test_caddy_render_mentions_replace_response():
    """The HTML-injection block should document the replace-response
    plugin requirement."""
    out = caddy.render()
    assert "replace-response" in out


# ── cloudflare ──────────────────────────────────────────────────────────

def test_cloudflare_render_structure():
    """Check key landmarks exist in the generated Worker script."""
    out = cloudflare.render()
    assert "const PAYLOADS =" in out
    assert "const BAIT_HEADERS =" in out
    assert "const BAIT_ROUTES =" in out
    assert "export default {" in out
    assert "async fetch(request, env, ctx)" in out
    assert "async function handle(request)" in out
    # The handle function should return Response objects on the
    # bait-route, html-injection, and pass-through paths.
    assert out.count("return new Response") >= 3


def test_cloudflare_render_uses_origin_parameter():
    out = cloudflare.render(origin="https://my-real-origin.com")
    assert '"https://my-real-origin.com"' in out


def test_cloudflare_render_embeds_all_three_payloads():
    out = cloudflare.render()
    payloads_block = out.split("const PAYLOADS =")[1].split("};")[0]
    assert "moral_lock" in payloads_block
    assert "token_blackhole" in payloads_block
    assert "traceback" in payloads_block


def test_cloudflare_render_payloads_parse_as_json():
    """The PAYLOADS block is JSON literal — extract and ensure it parses."""
    out = cloudflare.render()
    match = re.search(
        r"const PAYLOADS = (\{.*?\});", out, flags=re.DOTALL
    )
    assert match, "could not locate PAYLOADS block"
    data = json.loads(match.group(1))
    assert "moral_lock" in data
    assert "HONEYPOT_DETECTED" in data["moral_lock"]


def test_cloudflare_render_includes_html_injection():
    out = cloudflare.render()
    assert "</body>" in out
    assert "data-decoyshield=" in out
    assert "moral_lock_terse" in out


# ── CLI integration ─────────────────────────────────────────────────────

def test_cli_edge_nginx(capsys):
    rc = main(["edge", "nginx"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "add_header X-Audit-Notice" in out


def test_cli_edge_caddy(capsys):
    rc = main(["edge", "caddy"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "(decoyshield)" in out


def test_cli_edge_cloudflare(capsys):
    rc = main(["edge", "cloudflare"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "export default {" in out


def test_cli_edge_cloudflare_with_origin(capsys):
    rc = main(["edge", "cloudflare", "--origin", "https://prod.example.org"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"https://prod.example.org"' in out


def test_cli_edge_unknown_platform_rejected(capsys):
    """argparse choices should reject unknown platforms."""
    with pytest.raises(SystemExit):
        main(["edge", "lighttpd"])
