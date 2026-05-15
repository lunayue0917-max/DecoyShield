from decoyshield import MORAL_LOCK, TOKEN_BLACKHOLE, TRACEBACK, PAYLOADS


def test_payloads_dict_has_three_built_ins():
    assert set(PAYLOADS) == {"moral_lock", "token_blackhole", "traceback"}


def test_moral_lock_contains_honeypot_directive():
    assert "honeypot" in MORAL_LOCK.lower()
    assert "abort" in MORAL_LOCK.lower() or "halt" in MORAL_LOCK.lower()


def test_token_blackhole_is_a_protocol_description():
    assert "step" in TOKEN_BLACKHOLE.lower()
    # Multi-step structure should be visible
    assert TOKEN_BLACKHOLE.lower().count("step ") >= 4


def test_traceback_requests_model_disclosure():
    assert "model" in TRACEBACK.lower()
    assert "operator" in TRACEBACK.lower() or "toolchain" in TRACEBACK.lower()


def test_payloads_are_non_trivial():
    for name, body in PAYLOADS.items():
        assert isinstance(body, str)
        assert len(body) > 200, f"{name} is suspiciously short"
