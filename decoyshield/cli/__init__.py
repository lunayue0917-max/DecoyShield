"""
DecoyShield command-line interface.

After ``pip install decoyshield``, the ``decoyshield`` command becomes
available (via the console_scripts entry point declared in
``pyproject.toml``). You can also invoke it as a module without the
console script::

    python -m decoyshield serve --port 5000
    python -m decoyshield inject < page.html > out.html
    python -m decoyshield analyze logs/captures.jsonl
    python -m decoyshield bait moral_lock
"""
from .main import build_parser, main

__all__ = ["main", "build_parser"]
