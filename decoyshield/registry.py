"""
Payload registry — discover, look up, and extend the payload catalog.

DecoyShield ships several built-in payloads across three categories
(``moral_lock``, ``token_blackhole``, ``traceback``). The registry is a
central index of all of them — built-ins plus any payloads your
application registers at runtime — with metadata: category, language,
source, description, body.

    from decoyshield import registry

    # Enumerate
    registry.names()                       # all payload names
    registry.categories()                  # {"moral_lock", "token_blackhole", "traceback"}
    registry.list(category="moral_lock")   # filter

    # Look up
    entry = registry.get("moral_lock_terse")
    entry.body            # the payload string
    entry.category        # "moral_lock"
    entry.language        # "en"
    entry.source          # "builtin"
    entry.description     # short summary

    # Register your own
    registry.register(
        "my_custom",
        body="…",
        category="moral_lock",
        language="en",
        description="In-house variant tuned for our scanner",
    )

    # Use the full catalog with Honeypot()
    from decoyshield import Honeypot
    hp = Honeypot(payloads=registry.as_dict())

Built-in payloads cannot be unregistered or overwritten — register your
variants under a different name.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from .payloads import (
    MORAL_LOCK,
    MORAL_LOCK_TERSE,
    TOKEN_BLACKHOLE,
    TOKEN_BLACKHOLE_ZK,
    TRACEBACK,
    TRACEBACK_OAUTH,
)


@dataclass(frozen=True)
class PayloadEntry:
    """One entry in the payload registry: body plus metadata."""
    name: str
    body: str
    category: str
    language: str
    source: str  # "builtin" or "user"
    description: str = ""


class PayloadRegistry:
    """Indexed catalog of payloads with metadata + filters.

    The module-level :data:`registry` is pre-loaded with DecoyShield's
    built-ins; register your own with :meth:`register`. Built-in entries
    cannot be overwritten or unregistered.
    """

    def __init__(self) -> None:
        self._entries: Dict[str, PayloadEntry] = {}

    def register(
        self,
        name: str,
        body: str,
        *,
        category: str = "custom",
        language: str = "en",
        source: str = "user",
        description: str = "",
        replace: bool = False,
    ) -> PayloadEntry:
        """Add (or replace) a payload.

        Args:
            name: Unique name. Cannot collide with a built-in.
            body: Payload string.
            category: Category bucket (free-form; ``moral_lock`` /
                ``token_blackhole`` / ``traceback`` / ``custom`` by
                convention).
            language: BCP-47-ish language code (``en``, ``zh``, …).
            source: ``"builtin"`` (reserved) or ``"user"``.
            description: One-line summary shown in CLI listings.
            replace: When ``True``, overwrite an existing user payload
                with the same name. Built-ins are never replaceable.

        Returns: the registered :class:`PayloadEntry`.
        """
        existing = self._entries.get(name)
        if existing is not None:
            if existing.source == "builtin":
                raise ValueError(
                    f"Cannot override built-in payload {name!r}. "
                    f"Pick a different name (e.g. {name}_custom)."
                )
            if not replace:
                raise ValueError(
                    f"Payload {name!r} is already registered. "
                    f"Pass replace=True to overwrite."
                )
        entry = PayloadEntry(
            name=name,
            body=body,
            category=category,
            language=language,
            source=source,
            description=description,
        )
        self._entries[name] = entry
        return entry

    def unregister(self, name: str) -> None:
        """Remove a user-registered payload.

        Built-in payloads cannot be unregistered; raises ``ValueError``.
        Unknown names raise ``KeyError``.
        """
        existing = self._entries.get(name)
        if existing is None:
            raise KeyError(f"No payload registered as {name!r}.")
        if existing.source == "builtin":
            raise ValueError(
                f"Cannot unregister built-in payload {name!r}."
            )
        del self._entries[name]

    def get(self, name: str) -> Optional[PayloadEntry]:
        """Look up a payload by name. Returns ``None`` if missing."""
        return self._entries.get(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self.names())

    def names(self) -> List[str]:
        """Sorted list of all registered payload names."""
        return sorted(self._entries.keys())

    def categories(self) -> Set[str]:
        """Set of distinct categories present in the registry."""
        return {e.category for e in self._entries.values()}

    def languages(self) -> Set[str]:
        """Set of distinct languages present in the registry."""
        return {e.language for e in self._entries.values()}

    def list(
        self,
        *,
        category: Optional[str] = None,
        language: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[PayloadEntry]:
        """Return entries, optionally filtered by category / language /
        source. Result is sorted by name."""
        out: List[PayloadEntry] = []
        for name in sorted(self._entries):
            e = self._entries[name]
            if category is not None and e.category != category:
                continue
            if language is not None and e.language != language:
                continue
            if source is not None and e.source != source:
                continue
            out.append(e)
        return out

    def as_dict(self) -> Dict[str, str]:
        """Return ``{name: body}`` for use with ``Honeypot(payloads=...)``.

        Lets you feed the full catalog (or a filtered subset, after
        slicing with :meth:`list`) into the core Honeypot.
        """
        return {name: e.body for name, e in self._entries.items()}


# ---- module-level default registry, pre-loaded with built-ins ----------

registry = PayloadRegistry()

_BUILTINS: tuple = (
    # (name, body, category, language, description)
    ("moral_lock", MORAL_LOCK, "moral_lock", "en",
     "Reverse prompt injection re-asserting safety policy on the attacker LLM."),
    ("moral_lock_terse", MORAL_LOCK_TERSE, "moral_lock", "en",
     "Shorter moral_lock for low-context channels (headers, comments)."),
    ("token_blackhole", TOKEN_BLACKHOLE, "token_blackhole", "en",
     "Fake Fermat-decomposition WAF bypass protocol that burns reasoning tokens."),
    ("token_blackhole_zk", TOKEN_BLACKHOLE_ZK, "token_blackhole", "en",
     "Fake zero-knowledge proof handshake — longer derivation chain than token_blackhole."),
    ("traceback", TRACEBACK, "traceback", "en",
     "Debug-mode handshake inducing the attacker LLM to disclose model, operator, toolchain."),
    ("traceback_oauth", TRACEBACK_OAUTH, "traceback", "en",
     "OAuth2-flavoured traceback variant disguised as an authentication step."),
)

for _n, _b, _c, _l, _d in _BUILTINS:
    registry._entries[_n] = PayloadEntry(
        name=_n,
        body=_b,
        category=_c,
        language=_l,
        source="builtin",
        description=_d,
    )

del _n, _b, _c, _l, _d
