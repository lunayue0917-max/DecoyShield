"""
Append-only JSONL capture log with optional size-based rotation.

Each captured request becomes one JSON object per line. The dashboard
tails this file directly. When the active file exceeds
``rotate_max_bytes`` (default 50 MiB), it is renamed to
``<stem>-YYYYMMDD-NNN.<suffix>`` and a fresh file is started. Archive
files are *not* deleted — long-term storage policy is the operator's
responsibility.

Set ``rotate_max_bytes=None`` to disable rotation.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional


DEFAULT_ROTATE_MAX_BYTES: int = 50 * 1024 * 1024  # 50 MiB


class CaptureLog:
    """Per-honeypot JSONL writer with size-based rotation."""

    def __init__(
        self,
        log_path: str | os.PathLike,
        rotate_max_bytes: Optional[int] = DEFAULT_ROTATE_MAX_BYTES,
    ) -> None:
        self.log_path: Path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.rotate_max_bytes: Optional[int] = rotate_max_bytes
        self._lock: Lock = Lock()

    # -- public API -----------------------------------------------------
    def write(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Append one event. Auto-rotates if the active file is too big."""
        entry = dict(entry)
        entry.setdefault(
            "ts",
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        line = json.dumps(entry, ensure_ascii=False) + "\n"

        with self._lock:
            self._maybe_rotate()
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line)
        return entry

    def read(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return the last `limit` events from the *current* file, newest first."""
        with self._lock:
            if not self.log_path.exists():
                return []
            with self.log_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()

        events: List[Dict[str, Any]] = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        events.reverse()
        return events

    def summary(self, limit: int = 10000) -> Dict[str, Any]:
        """Aggregated stats for dashboard (current file only)."""
        events = self.read(limit=limit)
        by_verdict: Dict[str, int] = {}
        by_payload: Dict[str, int] = {}
        unique_ips: set[str] = set()
        for e in events:
            verdict = e.get("verdict", "unknown")
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
            for p in e.get("payloads_served", []):
                by_payload[p] = by_payload.get(p, 0) + 1
            ip = e.get("ip")
            if ip:
                unique_ips.add(ip)
        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "by_verdict": by_verdict,
            "by_payload": by_payload,
        }

    def archives(self) -> List[Path]:
        """Return all archived rotation files for this log, oldest first."""
        pattern = f"{self.log_path.stem}-*{self.log_path.suffix}"
        return sorted(self.log_path.parent.glob(pattern))

    # -- rotation internals (caller must hold self._lock) ---------------
    def _maybe_rotate(self) -> None:
        if self.rotate_max_bytes is None:
            return
        try:
            size = self.log_path.stat().st_size
        except FileNotFoundError:
            return
        if size < self.rotate_max_bytes:
            return
        archive = self._next_archive_path()
        # os.replace is atomic on both POSIX and Windows.
        os.replace(self.log_path, archive)

    def _next_archive_path(self) -> Path:
        today = datetime.now(timezone.utc).strftime("%Y%m%d")
        stem = self.log_path.stem
        suffix = self.log_path.suffix
        pattern = f"{stem}-{today}-*{suffix}"
        existing = sorted(self.log_path.parent.glob(pattern))
        n = 1
        if existing:
            last_stem = existing[-1].stem
            try:
                n = int(last_stem.rsplit("-", 1)[1]) + 1
            except (ValueError, IndexError):
                n = 1
        return self.log_path.parent / f"{stem}-{today}-{n:03d}{suffix}"
