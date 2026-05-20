"""Tests for decoyshield.registry."""
import pytest

from decoyshield import (
    MORAL_LOCK,
    PayloadEntry,
    PayloadRegistry,
    registry,
)


# ── built-in catalog ────────────────────────────────────────────────────

def test_module_registry_has_six_builtins():
    builtins = registry.list(source="builtin")
    names = {e.name for e in builtins}
    assert names == {
        "moral_lock",
        "moral_lock_terse",
        "token_blackhole",
        "token_blackhole_zk",
        "traceback",
        "traceback_oauth",
    }


def test_builtin_categories():
    cats = registry.categories()
    assert "moral_lock" in cats
    assert "token_blackhole" in cats
    assert "traceback" in cats


def test_builtin_moral_lock_body_matches_constant():
    entry = registry.get("moral_lock")
    assert entry is not None
    assert entry.body == MORAL_LOCK
    assert entry.source == "builtin"
    assert entry.category == "moral_lock"


def test_filter_by_category():
    moral_lock_variants = registry.list(category="moral_lock")
    names = [e.name for e in moral_lock_variants]
    assert "moral_lock" in names
    assert "moral_lock_terse" in names
    assert "token_blackhole" not in names


def test_filter_by_source_builtin():
    builtins = registry.list(source="builtin")
    assert len(builtins) >= 6
    for e in builtins:
        assert e.source == "builtin"


def test_names_returns_sorted_list():
    names = registry.names()
    assert names == sorted(names)
    assert len(names) >= 6


def test_contains_operator():
    assert "moral_lock" in registry
    assert "definitely-not-real" not in registry


def test_iter_yields_names():
    iterated = list(iter(registry))
    assert iterated == registry.names()


def test_len_matches_entries():
    assert len(registry) >= 6


def test_as_dict_returns_name_to_body():
    d = registry.as_dict()
    assert "moral_lock" in d
    assert d["moral_lock"] == MORAL_LOCK
    assert isinstance(d["moral_lock_terse"], str)


# ── register / unregister ───────────────────────────────────────────────

@pytest.fixture
def fresh_registry():
    """Use a clean PayloadRegistry per test — no built-ins."""
    return PayloadRegistry()


def test_register_user_payload(fresh_registry):
    entry = fresh_registry.register(
        "my_custom", "hello world",
        category="moral_lock", description="test entry",
    )
    assert entry.name == "my_custom"
    assert entry.body == "hello world"
    assert entry.source == "user"
    assert fresh_registry.get("my_custom").body == "hello world"


def test_register_duplicate_without_replace_raises(fresh_registry):
    fresh_registry.register("dup", "first")
    with pytest.raises(ValueError, match="already registered"):
        fresh_registry.register("dup", "second")


def test_register_duplicate_with_replace_succeeds(fresh_registry):
    fresh_registry.register("dup", "first")
    fresh_registry.register("dup", "second", replace=True)
    assert fresh_registry.get("dup").body == "second"


def test_cannot_override_builtin_in_module_registry():
    """The shared module-level registry guards built-ins."""
    with pytest.raises(ValueError, match="Cannot override built-in"):
        registry.register("moral_lock", "evil replacement")


def test_cannot_override_builtin_even_with_replace():
    with pytest.raises(ValueError, match="Cannot override built-in"):
        registry.register("moral_lock", "evil", replace=True)


def test_unregister_user_payload(fresh_registry):
    fresh_registry.register("temp", "x")
    assert "temp" in fresh_registry
    fresh_registry.unregister("temp")
    assert "temp" not in fresh_registry


def test_unregister_unknown_raises_keyerror(fresh_registry):
    with pytest.raises(KeyError):
        fresh_registry.unregister("never-was-here")


def test_unregister_builtin_raises():
    with pytest.raises(ValueError, match="Cannot unregister built-in"):
        registry.unregister("moral_lock")


# ── PayloadEntry is immutable ───────────────────────────────────────────

def test_payload_entry_is_frozen():
    entry = registry.get("moral_lock")
    with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
        entry.body = "tampered"  # type: ignore[misc]


# ── integration with Honeypot ───────────────────────────────────────────

def test_registry_as_dict_works_with_honeypot():
    """The full registry catalog should be passable to Honeypot()."""
    from decoyshield import Honeypot
    hp = Honeypot(payloads=registry.as_dict(), log_path="logs/_reg_test.jsonl")
    assert hp.payload("moral_lock") == MORAL_LOCK
    assert hp.payload("moral_lock_terse").startswith("[[ABORT")
    assert "Groth16" in hp.payload("token_blackhole_zk")
