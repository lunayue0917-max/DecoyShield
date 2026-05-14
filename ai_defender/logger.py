"""
Append-only JSONL capture log.

Each captured request is one JSON object per line. Designed to be tailed
by the dashboard, shipped to Loki/ELK, or read directly for analysis.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class CaptureLog:
    """Per-honeypot append-only log writer."""

    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def write(self, entry):
        """entry: dict to serialise as one JSONL line."""
        entry = dict(entry)
        entry.setdefault(
            "ts",
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        with self._lock, self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def read(self, limit=200):
        """Return the last `limit` events, newest first."""
        if not self.log_path.exists():
            return []
        with self.log_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        events = []
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

    def summary(self, limit=10000):
        """Aggregated stats for dashboard."""
        events = self.read(limit=limit)
        by_verdict = {}
        by_payload = {}
        unique_ips = set()
        for e in events:
            by_verdict[e.get("verdict", "unknown")] = (
                by_verdict.get(e.get("verdict", "unknown"), 0) + 1
            )
            for p in e.get("payloads_served", []):
                by_payload[p] = by_payload.get(p, 0) + 1
            if e.get("ip"):
                unique_ips.add(e["ip"])
        return {
            "total_events": len(events),
            "unique_ips": len(unique_ips),
            "by_verdict": by_verdict,
            "by_payload": by_payload,
        }
