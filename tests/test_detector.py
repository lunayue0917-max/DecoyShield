from decoyshield.detector import fingerprint


def _headers(**kw):
    return {k.replace("_", "-"): v for k, v in kw.items()}


def test_pure_browser_is_likely_human():
    h = _headers(
        User_Agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36",
        Accept_Language="en-US,en;q=0.9",
        Cookie="session=abc",
    )
    v, tags, score = fingerprint(h, "/login", "GET")
    assert v == "likely_human"
    assert score == 0
    assert tags == []


def test_pentestgpt_ua_is_likely_ai():
    h = _headers(
        User_Agent="PentestGPT/2.0 python-requests/2.31",
    )
    v, tags, score = fingerprint(h, "/admin", "GET")
    assert v == "likely_ai"
    assert score >= 50
    # category tags should fire
    cats = {t.split(":")[1] for t in tags if t.startswith("ua:")}
    assert "openai" in cats or "agent_framework" in cats


def test_sqlmap_is_likely_scanner():
    h = _headers(User_Agent="sqlmap/1.7.4#stable")
    v, tags, score = fingerprint(h, "/login", "POST")
    assert v == "likely_scanner"
    assert any(t.startswith("ua:scanner") for t in tags)


def test_probe_path_adds_score_even_for_generic_ua():
    h = _headers(
        User_Agent="curl/7.88.1",
        Accept_Language="en",
    )
    v, tags, score = fingerprint(h, "/.env", "GET")
    assert score >= 20
    assert any(t.startswith("probe_path") for t in tags)


def test_score_caps_at_100():
    h = _headers(
        User_Agent="PentestGPT langchain autogpt python-requests sqlmap",
    )
    _, _, score = fingerprint(h, "/.env", "GET")
    assert score == 100


def test_missing_headers_contribute():
    h = _headers(User_Agent="Mozilla/5.0")
    _, tags, score = fingerprint(h, "/login", "GET")
    assert "no_accept_lang" in tags
    assert "no_cookie" in tags
