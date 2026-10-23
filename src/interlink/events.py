"""Normalized event stream for one run.

Every adapter, whatever its native output looks like, emits events of this shape::

    {"seq": 7, "at": 1761234567.123, "type": "text", "text": "..."}

Types: ``status`` ``text`` ``tool_use`` ``tool_result`` ``question`` ``stderr``
``result`` ``raw`` ``error`` ``interlink`` (Interlink's own bookkeeping).
Events are appended to ``events.jsonl`` as they arrive and kept in memory for
cursor-based ``observe`` calls. Text fields are bounded and secrets redacted.
"""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from interlink.security import Redactor

EVENT_TYPES = frozenset(
    {
        "status",
        "text",
        "tool_use",
        "tool_result",
        "question",
        "stderr",
        "result",
        "raw",
        "error",
        "interlink",
    }
)
TERMINAL_STATES = frozenset({"complete", "failed", "cancelled", "timed_out", "error"})
MAX_EVENTS = 20_000
MAX_FIELD_CHARS = 16_000


def _bound(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + " [truncated]"
    if depth > 6:
        return "[nested too deep]"
    if isinstance(value, list):
        return [_bound(item, depth + 1) for item in value[:200]]
    if isinstance(value, dict):
        return {str(k)[:128]: _bound(v, depth + 1) for k, v in list(value.items())[:200]}
    return value


class RunLog:
    def __init__(self, path: Path, redactor: Redactor | None = None) -> None:
        self.path = path
        self.redactor = redactor or Redactor()
        self.events: list[dict[str, Any]] = []
        self.dropped = 0
        self.state = "pending"
        self.exit_code: int | None = None
        self.detail: dict[str, Any] = {}
        self._changed = threading.Condition()

    # -- writing -------------------------------------------------------------------------

    def emit(self, type_: str, **fields: Any) -> dict[str, Any] | None:
        if type_ not in EVENT_TYPES:
            fields = {"native_type": type_, **fields}
            type_ = "raw"
        with self._changed:
            if len(self.events) >= MAX_EVENTS:
                self.dropped += 1
                return None
            event = {
                "seq": len(self.events) + 1,
                "at": round(time.time(), 3),
                "type": type_,
                **self.redactor.scrub_value(_bound(fields)),
            }
            self.events.append(event)
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._changed.notify_all()
            return event

    def set_state(self, state: str, **detail: Any) -> None:
        with self._changed:
            self.state = state
            self.detail.update(self.redactor.scrub_value(_bound(detail)))
            self._changed.notify_all()

    # -- reading -------------------------------------------------------------------------

    @property
    def done(self) -> bool:
        return self.state in TERMINAL_STATES

    def read(self, after: int = 0, limit: int = 64, wait: float = 0.0) -> dict[str, Any]:
        deadline = time.monotonic() + max(0.0, wait)
        with self._changed:
            while not self.done and len(self.events) <= after:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(remaining)
            window = self.events[after : after + limit]
            pending = max(0, len(self.events) - after - len(window))
            return {
                "state": self.state,
                "done": self.done,
                "exit_code": self.exit_code,
                "events": [dict(e) for e in window],
                "next_cursor": window[-1]["seq"] if window else after,
                "more": pending > 0,
                "dropped": self.dropped,
                "detail": dict(self.detail),
            }

    def wait_done(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._changed:
            while not self.done:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._changed.wait(remaining)
            return True

    def text(self) -> str:
        """The run's final answer: the result text if any, else all text events."""
        with self._changed:
            for event in reversed(self.events):
                if (
                    event["type"] == "result"
                    and isinstance(event.get("text"), str)
                    and event["text"]
                ):
                    return event["text"]
            return "".join(
                e.get("text", "") + ("" if e.get("partial") else "\n")
                for e in self.events
                if e["type"] == "text"
            ).strip()

    def counts(self) -> dict[str, int]:
        with self._changed:
            return dict(Counter(e["type"] for e in self.events))
