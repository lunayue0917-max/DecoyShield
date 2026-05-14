"""Tests for capture-log rotation."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ai_defender.logger import CaptureLog


def _bytes_in_file(p: Path) -> int:
    return p.stat().st_size if p.exists() else 0


def test_no_rotation_under_threshold(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=10_000)
    for _ in range(20):
        log.write({"k": "v"})
    assert (tmp_path / "c.jsonl").exists()
    assert log.archives() == []


def test_rotates_when_threshold_exceeded(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=200)
    # write enough lines to exceed 200 bytes
    for i in range(50):
        log.write({"event": i, "data": "x" * 20})

    archives = log.archives()
    assert len(archives) >= 1, "expected at least one rotation"
    # The current file should still exist after rotation
    assert (tmp_path / "c.jsonl").exists()


def test_archive_naming_includes_date_and_index(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=100)
    for i in range(40):
        log.write({"event": i, "data": "x" * 50})
    archives = log.archives()
    assert archives, "rotation never fired"
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    for archive in archives:
        assert today in archive.name
        # NNN suffix exists
        suffix_part = archive.stem.rsplit("-", 1)[1]
        assert suffix_part.isdigit()
        assert len(suffix_part) == 3


def test_multiple_rotations_increment_index(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=100)
    # write enough to force >=2 rotations
    for i in range(200):
        log.write({"event": i, "blob": "y" * 80})
    archives = log.archives()
    assert len(archives) >= 2
    indices = [int(a.stem.rsplit("-", 1)[1]) for a in archives]
    assert indices == sorted(indices)
    assert indices == list(range(1, len(indices) + 1))


def test_read_returns_only_current_file(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=120)
    for i in range(30):
        log.write({"event": i, "tail": "z" * 60})

    current_lines = (tmp_path / "c.jsonl").read_text(
        encoding="utf-8"
    ).strip().splitlines()
    events = log.read(limit=10000)
    assert len(events) == len(current_lines)
    # All returned events should be the most recent ones
    last_event_id = json.loads(current_lines[-1])["event"]
    assert events[0]["event"] == last_event_id


def test_rotate_disabled(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=None)
    for i in range(100):
        log.write({"event": i, "data": "x" * 200})
    assert log.archives() == []
    assert _bytes_in_file(tmp_path / "c.jsonl") > 10_000


def test_archive_files_are_complete_jsonl(tmp_path):
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=150)
    for i in range(40):
        log.write({"event": i, "data": "x" * 70})
    for archive in log.archives():
        for line in archive.read_text(encoding="utf-8").splitlines():
            json.loads(line)  # must parse without error


def test_concurrent_writes_do_not_corrupt(tmp_path):
    """Stress test for thread safety."""
    import threading
    log = CaptureLog(tmp_path / "c.jsonl", rotate_max_bytes=2_000)

    def writer(thread_id):
        for i in range(100):
            log.write({"thread": thread_id, "i": i, "filler": "p" * 30})

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Every line in current + every archive must be valid JSON
    files = [tmp_path / "c.jsonl"] + log.archives()
    total = 0
    for f in files:
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                json.loads(line)
                total += 1
    assert total == 5 * 100  # 5 threads × 100 events
