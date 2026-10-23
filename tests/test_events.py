from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from interlink.events import MAX_FIELD_CHARS, RunLog
from interlink.security import Redactor


def test_emit_sequences_and_persists(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "events.jsonl")
    log.emit("text", text="hi")
    log.emit("tool_use", tool="x")
    lines = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert [e["seq"] for e in lines] == [1, 2]
    assert lines[0]["type"] == "text"


def test_unknown_types_become_raw(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "e.jsonl")
    event = log.emit("weird", x=1)
    assert event["type"] == "raw" and event["native_type"] == "weird"


def test_redaction_and_bounds(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "e.jsonl", Redactor({"K": "topsecret123"}))
    event = log.emit("text", text="topsecret123 " + "x" * (MAX_FIELD_CHARS * 2))
    assert "topsecret123" not in json.dumps(event)
    assert len(event["text"]) < MAX_FIELD_CHARS * 2
    assert "topsecret123" not in (tmp_path / "e.jsonl").read_text()


def test_cursor_reads_and_long_poll(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "e.jsonl")
    log.state = "running"
    for n in range(5):
        log.emit("text", text=str(n))
    first = log.read(0, 2)
    assert [e["text"] for e in first["events"]] == ["0", "1"] and first["more"]
    rest = log.read(first["next_cursor"], 10)
    assert [e["text"] for e in rest["events"]] == ["2", "3", "4"] and not rest["more"]
    threading.Timer(0.2, lambda: log.emit("text", text="late")).start()
    started = time.monotonic()
    late = log.read(5, 10, wait=5)
    assert late["events"][0]["text"] == "late" and time.monotonic() - started < 4


def test_text_prefers_result(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "e.jsonl")
    log.emit("text", text="thinking")
    assert log.text() == "thinking"
    log.emit("result", text="final")
    assert log.text() == "final"


def test_wait_done(tmp_path: Path) -> None:
    log = RunLog(tmp_path / "e.jsonl")
    assert log.wait_done(0.1) is False
    threading.Timer(0.1, lambda: log.set_state("complete")).start()
    assert log.wait_done(5) is True and log.done
