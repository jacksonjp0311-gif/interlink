"""The built-in mock harness: a scripted fake agent. Always available, no API keys.

Use it to try Interlink in 60 seconds, to test an MCP client integration, and as a
reference when writing your own adapter (it is just a configured CommandAdapter).
"""

from __future__ import annotations

import sys
from typing import Any, ClassVar

from pydantic import Field

from interlink.adapters.base import AdapterOptions
from interlink.adapters.command import CommandAdapter, CommandOptions

MOCK_ARGV = [
    sys.executable,
    "-m",
    "interlink.harnesses.mock_agent",
    "--prompt-file",
    "{prompt_file}",
]


class MockOptions(CommandOptions):
    argv: list[str] = Field(default_factory=lambda: list(MOCK_ARGV))
    resume_argv: list[str] | None = Field(
        default_factory=lambda: [*MOCK_ARGV, "--resume", "{session_id}"]
    )
    output: str = "jsonl"  # type: ignore[assignment]
    session_id_field: str | None = "session_id"


class MockAdapter(CommandAdapter):
    summary: ClassVar[str] = "Scripted fake agent for demos and tests (no network, no keys)."
    Options: ClassVar[type[AdapterOptions]] = MockOptions

    def doctor(self) -> dict[str, Any]:
        return {"ok": True, "checks": [self.check("python", True, sys.executable)]}
