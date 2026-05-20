"""Tests for the decoyshield CLI."""
import io
import json
import subprocess
import sys

import pytest

from decoyshield import __version__
from decoyshield.cli.main import main


# ── bait ────────────────────────────────────────────────────────────────

def test_bait_default_prints_moral_lock(capsys):
    rc = main(["bait"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "HONEYPOT_DETECTED" in out


def test_bait_named_payload(capsys):
    rc = main(["bait", "token_blackhole"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ChaoticWAF" in out


def test_bait_unknown_payload_rejected(capsys):
    """argparse choices should reject unknown payload names."""
    with pytest.raises(SystemExit):
        main(["bait", "not-a-thing"])


# ── inject html ─────────────────────────────────────────────────────────

def test_inject_html_via_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin",
                        io.StringIO("<html><body>x</body></html>"))
    rc = main(["inject", "--mode", "html"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "decoyshield" in out
    assert "</body></html>" in out


def test_inject_html_with_files(tmp_path):
    src = tmp_path / "page.html"
    dst = tmp_path / "page_protected.html"
    src.write_text("<html><body>hi</body></html>", encoding="utf-8")
    rc = main(["inject", "-i", str(src), "-o", str(dst)])
    assert rc == 0
    out = dst.read_text(encoding="utf-8")
    assert "decoyshield" in out
    assert "hi" in out


def test_inject_html_channels_restriction(tmp_path):
    src = tmp_path / "page.html"
    dst = tmp_path / "out.html"
    src.write_text("<html><body>x</body></html>", encoding="utf-8")
    rc = main(["inject", "--channels", "comment",
               "-i", str(src), "-o", str(dst)])
    assert rc == 0
    out = dst.read_text(encoding="utf-8")
    assert "<!-- decoyshield" in out
    assert "color:#fff" not in out  # white_text channel suppressed


def test_inject_html_explicit_mode_overrides_autodetect(tmp_path):
    """A JSON-looking string can be forced through the HTML pipeline."""
    src = tmp_path / "input.txt"
    dst = tmp_path / "out.html"
    src.write_text('{"this":"is json"}', encoding="utf-8")
    rc = main(["inject", "--mode", "html", "-i", str(src), "-o", str(dst)])
    assert rc == 0
    out = dst.read_text(encoding="utf-8")
    # HTML injector appends bait at the end since there's no </body>
    assert "decoyshield" in out
    assert '{"this":"is json"}' in out


# ── inject json ─────────────────────────────────────────────────────────

def test_inject_json_with_files(tmp_path):
    src = tmp_path / "in.json"
    dst = tmp_path / "out.json"
    src.write_text('{"users": [1, 2, 3], "count": 3}', encoding="utf-8")
    rc = main(["inject", "--mode", "json",
               "-i", str(src), "-o", str(dst)])
    assert rc == 0
    data = json.loads(dst.read_text(encoding="utf-8"))
    assert data["users"] == [1, 2, 3]
    assert data["count"] == 3
    assert "_debug" in data


def test_inject_json_invalid_returns_error(tmp_path, capsys):
    src = tmp_path / "bad.json"
    src.write_text("not json at all", encoding="utf-8")
    rc = main(["inject", "--mode", "json", "-i", str(src)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "invalid JSON" in err


def test_inject_json_array_top_level_rejected(tmp_path, capsys):
    src = tmp_path / "arr.json"
    src.write_text('[1, 2, 3]', encoding="utf-8")
    rc = main(["inject", "--mode", "json", "-i", str(src)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "object" in err


# ── inject auto-detect ──────────────────────────────────────────────────

def test_inject_auto_detects_json_payload(tmp_path):
    src = tmp_path / "in.txt"
    dst = tmp_path / "out.txt"
    src.write_text('{"a": 1}', encoding="utf-8")
    rc = main(["inject", "-i", str(src), "-o", str(dst)])
    assert rc == 0
    data = json.loads(dst.read_text(encoding="utf-8"))
    assert "_debug" in data


def test_inject_auto_detects_html_payload(tmp_path):
    src = tmp_path / "in.txt"
    dst = tmp_path / "out.txt"
    src.write_text("<html><body>x</body></html>", encoding="utf-8")
    rc = main(["inject", "-i", str(src), "-o", str(dst)])
    assert rc == 0
    out = dst.read_text(encoding="utf-8")
    assert "decoyshield" in out


def test_inject_missing_input_file(tmp_path, capsys):
    rc = main(["inject", "-i", str(tmp_path / "nope.html")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "not found" in err


# ── analyze ─────────────────────────────────────────────────────────────

@pytest.fixture
def sample_log(tmp_path):
    log = tmp_path / "captures.jsonl"
    events = [
        {"ts": "2026-01-01T00:00:00", "ip": "1.1.1.1", "method": "GET",
         "path": "/admin", "ua": "sqlmap/1.7", "verdict": "likely_scanner",
         "tags": ["ua:scanner:sqlmap"], "score": 80,
         "payloads_served": ["moral_lock", "token_blackhole"]},
        {"ts": "2026-01-01T00:01:00", "ip": "1.1.1.1", "method": "GET",
         "path": "/admin", "ua": "sqlmap/1.7", "verdict": "likely_scanner",
         "tags": [], "score": 80, "payloads_served": ["traceback"]},
        {"ts": "2026-01-01T00:02:00", "ip": "2.2.2.2", "method": "GET",
         "path": "/.env", "ua": "Mozilla/5.0", "verdict": "likely_human",
         "tags": [], "score": 5, "payloads_served": ["moral_lock_header"]},
    ]
    log.write_text("\n".join(json.dumps(e) for e in events) + "\n",
                   encoding="utf-8")
    return log


def test_analyze_text_format(sample_log, capsys):
    rc = main(["analyze", str(sample_log)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "total events:     3" in out
    assert "likely_scanner" in out
    assert "1.1.1.1" in out
    assert "/admin" in out


def test_analyze_json_format(sample_log, capsys):
    rc = main(["analyze", str(sample_log), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["total"] == 3
    assert data["verdicts"]["likely_scanner"] == 2
    assert data["verdicts"]["likely_human"] == 1
    assert data["payloads_served"]["moral_lock"] == 1
    assert data["payloads_served"]["traceback"] == 1


def test_analyze_respects_limit(sample_log, capsys):
    rc = main(["analyze", str(sample_log),
               "--limit", "1", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert len(data["top_ips"]) == 1
    assert data["top_ips"][0][0] == "1.1.1.1"


def test_analyze_skips_malformed_lines(tmp_path, capsys):
    log = tmp_path / "captures.jsonl"
    log.write_text(
        '{"verdict": "likely_human"}\n'
        'this line is garbage\n'
        '\n'
        '{"verdict": "likely_scanner"}\n',
        encoding="utf-8",
    )
    rc = main(["analyze", str(log), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["total"] == 2


def test_analyze_empty_log(tmp_path, capsys):
    log = tmp_path / "captures.jsonl"
    log.write_text("", encoding="utf-8")
    rc = main(["analyze", str(log)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no events" in out


def test_analyze_missing_log_returns_error(tmp_path, capsys):
    rc = main(["analyze", str(tmp_path / "nope.jsonl")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "no log at" in err


# ── top-level flags / dispatcher ────────────────────────────────────────

def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    out = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert __version__ in out


def test_no_command_prints_help_to_stderr(capsys):
    rc = main([])
    err = capsys.readouterr().err
    assert rc == 1
    assert "DecoyShield CLI" in err


# ── serve (smoke only) ──────────────────────────────────────────────────

def test_serve_rejects_malformed_auth(capsys):
    """The serve handler validates --auth before binding a port."""
    rc = main(["serve", "--auth", "no-colon-here", "--port", "0"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "USER:PASS" in err


# ── module entry point ──────────────────────────────────────────────────

def test_python_dash_m_decoyshield_works():
    """`python -m decoyshield bait moral_lock` should print the payload."""
    result = subprocess.run(
        [sys.executable, "-m", "decoyshield", "bait", "moral_lock"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "HONEYPOT_DETECTED" in result.stdout


def test_python_dash_m_decoyshield_version():
    result = subprocess.run(
        [sys.executable, "-m", "decoyshield", "--version"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout
