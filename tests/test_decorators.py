"""Tests for the @protect decorator."""
import pytest

from decoyshield import protect


def test_protect_html_function():
    @protect
    def homepage():
        return "<html><body>hi</body></html>"

    out = homepage()
    assert isinstance(out, str)
    assert "decoyshield" in out
    assert "</body></html>" in out


def test_protect_json_function():
    @protect
    def users_api():
        return {"users": [1, 2, 3]}

    out = users_api()
    assert isinstance(out, dict)
    assert out["users"] == [1, 2, 3]
    assert "_debug" in out


def test_protect_preserves_function_metadata():
    @protect
    def render_page():
        """Original docstring."""
        return "<html></html>"

    assert render_page.__name__ == "render_page"
    assert render_page.__doc__ == "Original docstring."


def test_protect_passes_args_through():
    @protect
    def render(name, greeting="hello"):
        return f"<html><body>{greeting}, {name}</body></html>"

    out = render("world", greeting="hi")
    assert "hi, world" in out
    assert "decoyshield" in out


def test_protect_html_kind_forces_html_path():
    @protect(kind="html")
    def page():
        return "<div>x</div>"

    out = page()
    assert "<div>x</div>" in out
    assert "decoyshield" in out


def test_protect_json_kind_forces_json_path():
    @protect(kind="json")
    def api():
        return {"a": 1}

    out = api()
    assert "_debug" in out


def test_protect_rejects_unknown_kind():
    with pytest.raises(ValueError):
        @protect(kind="binary")
        def f():
            return b""


def test_protect_handles_tuple_html_response():
    @protect
    def view():
        return ("<html><body>x</body></html>", 200, {"X-Foo": "bar"})

    body, status, headers = view()
    assert "decoyshield" in body
    assert status == 200
    assert headers == {"X-Foo": "bar"}


def test_protect_handles_tuple_json_response():
    @protect
    def view():
        return ({"a": 1}, 403)

    body, status = view()
    assert "_debug" in body
    assert status == 403


def test_protect_leaves_unknown_types_alone():
    @protect
    def bytes_view():
        return b"\x00\x01\x02"

    assert bytes_view() == b"\x00\x01\x02"
