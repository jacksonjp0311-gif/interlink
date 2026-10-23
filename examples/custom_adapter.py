"""A custom harness adapter in ~30 lines.

Use it from interlink.toml without packaging anything:

    [harness.shout]
    adapter = "custom_adapter:ShoutAdapter"   # module must be importable (PYTHONPATH)

Or ship it as a plugin with an entry point in your own pyproject.toml:

    [project.entry-points."interlink.adapters"]
    shout = "custom_adapter:ShoutAdapter"
"""

from __future__ import annotations

import sys
from typing import ClassVar

from interlink.adapters.base import AdapterOptions, RunContext
from interlink.adapters.command import CommandAdapter, CommandOptions


class ShoutOptions(CommandOptions):
    # Any CLI works; here a tiny Python one-liner stands in for "your agent".
    argv: list[str] = [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"]
    output: str = "text"  # type: ignore[assignment]


class ShoutAdapter(CommandAdapter):
    kind: ClassVar[str] = "command"
    summary: ClassVar[str] = "Example: echoes the prompt back in capitals."
    Options: ClassVar[type[AdapterOptions]] = ShoutOptions

    def parse_line(self, line: str, ctx: RunContext) -> None:
        # Turn every non-empty output line into a normalized `text` event.
        if line.strip():
            ctx.emit("text", text=f"SHOUT: {line}")
