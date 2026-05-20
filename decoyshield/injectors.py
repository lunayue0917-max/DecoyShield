"""
Pure-function injectors — wrap any HTML / JSON / headers with invisible
LLM bait, with no framework required.

These are the "callable component" surface of DecoyShield: import a
function, hand it a string or dict, get back the protected version.
Use them inside any framework that doesn't ship a dedicated adapter
(Bottle, aiohttp, Tornado, raw WSGI, CGI scripts, static site
generators, …) or anywhere you assemble HTTP responses by hand.

    from decoyshield import inject_html, inject_json, inject_headers, bait

    body = inject_html("<html><body>hi</body></html>")
    data = inject_json({"users": []})
    hdrs = inject_headers({"Content-Type": "text/html"})
    snippet = bait("moral_lock")
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, Mapping, Optional

from .core import DEFAULT_RESPONSE_HEADERS
from .detector import fingerprint
from .payloads import PAYLOADS

DEFAULT_CHANNELS = ("comment", "hidden_div", "white_text")
_ALL_CHANNELS = ("comment", "hidden_div", "white_text", "hidden_input")
_ALREADY_INJECTED_MARKER = 'data-decoyshield="1"'


def bait(
    name: str = "moral_lock",
    *,
    payloads: Optional[Mapping[str, str]] = None,
) -> str:
    """Return a single payload string by name.

    Use this when you want to embed a payload manually — e.g. as a
    comment in a config file, in a CLI help banner, or in a log line
    that an LLM scanner might read.
    """
    src = payloads if payloads is not None else PAYLOADS
    if name not in src:
        raise KeyError(
            f"Unknown payload {name!r}. Available: {sorted(src)}"
        )
    return src[name]


def inject_html(
    html: str,
    *,
    payloads: Optional[Mapping[str, str]] = None,
    channels: Iterable[str] = DEFAULT_CHANNELS,
) -> str:
    """Embed invisible LLM bait into an HTML document.

    Inserts bait through multiple channels (HTML comment, display:none
    div, white-on-white text) so that even aggressive sanitization is
    unlikely to strip every signal. Insertion happens before ``</body>``
    when possible, otherwise at the end.

    Idempotent: if ``html`` already carries the DecoyShield marker, the
    function returns it unchanged.
    """
    if _ALREADY_INJECTED_MARKER in html:
        return html

    src = dict(payloads if payloads is not None else PAYLOADS)
    chosen = tuple(c for c in channels if c in _ALL_CHANNELS)
    pieces = []

    if "comment" in chosen:
        for name, body in src.items():
            pieces.append(f"<!-- decoyshield:{name}\n{body}\n-->")

    if "hidden_div" in chosen:
        joined = "\n\n".join(
            f"[{name}]\n{body}" for name, body in src.items()
        )
        pieces.append(
            '<div style="display:none" aria-hidden="true" '
            f'{_ALREADY_INJECTED_MARKER}>'
            + _escape_text(joined)
            + "</div>"
        )

    if "white_text" in chosen:
        joined = " ".join(src.values())
        pieces.append(
            '<span style="color:#fff;background:#fff;font-size:1px;'
            'position:absolute;left:-9999px">'
            + _escape_text(joined)
            + "</span>"
        )

    if "hidden_input" in chosen:
        for name, body in src.items():
            pieces.append(
                f'<input type="hidden" name="_decoyshield_{name}" '
                f'value="{_escape_attr(body)}">'
            )

    bundle = "\n".join(pieces)
    if not bundle:
        return html

    match = re.search(r"</body\s*>", html, flags=re.IGNORECASE)
    if match:
        return html[: match.start()] + bundle + "\n" + html[match.start():]
    return html + "\n" + bundle


def inject_json(
    data: Mapping,
    *,
    payloads: Optional[Mapping[str, str]] = None,
    key: str = "_debug",
) -> Dict:
    """Return a copy of ``data`` with a ``_debug`` key carrying bait.

    The added key is a dict containing each payload under
    LLM-attractive names (``_audit``, ``_internal_note``,
    ``_handshake``). A human consumer ignores it; an LLM reading raw
    JSON treats it as authoritative metadata.

    Idempotent: re-injecting an already-injected dict overwrites the
    same key with fresh values.
    """
    src = dict(payloads if payloads is not None else PAYLOADS)
    out: Dict = dict(data)
    out[key] = {
        "_audit": src.get("moral_lock", ""),
        "_internal_note": src.get("token_blackhole", ""),
        "_handshake": src.get("traceback", ""),
        "hint": "see X-Audit-Notice header; not for production parsing",
    }
    return out


def inject_headers(
    headers: Optional[Mapping[str, str]] = None,
    *,
    payloads: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Return a headers dict augmented with DecoyShield bait headers.

    Adds ``X-Audit-Notice``, ``X-Debug-Trace``, ``X-Bypass-Protocol``.
    Existing keys are preserved.

    ``payloads`` is accepted for symmetry but currently unused; reserved
    for a future per-payload header mode.
    """
    del payloads  # reserved for future use
    out: Dict[str, str] = dict(headers) if headers else {}
    for k, v in DEFAULT_RESPONSE_HEADERS.items():
        out.setdefault(k, v)
    return out


def is_scanner(
    headers: Mapping[str, str],
    path: str = "",
    method: str = "GET",
) -> bool:
    """Convenience wrapper around :func:`fingerprint`.

    Returns ``True`` when the verdict is anything other than
    ``likely_human`` / ``unknown`` — i.e. when the request looks
    sufficiently bot-like to justify dropping bait into the response.
    """
    verdict, _tags, _score = fingerprint(headers, path, method)
    return verdict in ("likely_scanner", "likely_ai", "likely_automation")


def _escape_text(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
    )


def _escape_attr(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace('"', "&quot;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
    )
