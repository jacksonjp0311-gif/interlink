"""Generic one-process-per-prompt adapter. Drives almost any agent CLI.

Example ``interlink.toml``::

    [harness.my-agent]
    adapter = "command"
    argv = ["my-agent", "run", "--prompt-file", "{prompt_file}"]
    output = "jsonl"                 # or "text"
    session_id_field = "session_id"  # remember this from output for the next turn
    resume_argv = ["my-agent", "run", "--resume", "{session_id}", "--prompt-file", "{prompt_file}"]

Placeholders: ``{prompt}`` ``{prompt_file}`` ``{workspace}`` ``{home}`` ``{run_id}``
``{instance_id}`` ``{session_id}``. If neither ``{prompt}`` nor ``{prompt_file}``
appears, the prompt is written to the process's stdin.
"""

from __future__ import annotations

import json
import time
from typing import Any, ClassVar, Literal

from pydantic import Field

from interlink.adapters.base import (
    AdapterOptions,
    HarnessAdapter,
    RunContext,
    RunOutcome,
    substitute,
)
from interlink.events import EVENT_TYPES


class CommandOptions(AdapterOptions):
    argv: list[str] = Field(min_length=1, description="Command and arguments (no shell).")
    resume_argv: list[str] | None = Field(
        None, description="Used instead of argv once a session id is known."
    )
    output: Literal["text", "jsonl"] = "text"
    session_id_field: str | None = None
    success_exit_codes: list[int] = Field(default_factory=lambda: [0])


class CommandAdapter(HarnessAdapter):
    kind: ClassVar[str] = "command"
    summary: ClassVar[str] = "Any CLI: one process per prompt, text or JSONL output."
    Options: ClassVar[type[AdapterOptions]] = CommandOptions
    options: CommandOptions

    # -- override points -----------------------------------------------------------------

    def build_argv(self, ctx: RunContext) -> list[str]:
        session_id = ctx.instance.session.get("session_id")
        template = (
            self.options.resume_argv
            if session_id and self.options.resume_argv
            else self.options.argv
        )
        return substitute(template, self.placeholders(ctx))

    def placeholders(self, ctx: RunContext) -> dict[str, str]:
        return {
            "prompt": ctx.prompt,
            "prompt_file": str(ctx.prompt_file),
            "workspace": str(ctx.instance.workspace.work),
            "home": str(ctx.instance.workspace.home),
            "run_id": ctx.run_id,
            "instance_id": ctx.instance.id,
            "session_id": str(ctx.instance.session.get("session_id", "")),
        }

    def uses_stdin(self, ctx: RunContext) -> bool:
        template = " ".join(self.options.argv + (self.options.resume_argv or []))
        return "{prompt}" not in template and "{prompt_file}" not in template

    def parse_line(self, line: str, ctx: RunContext) -> None:
        """Translate one stdout line into zero or more normalized events."""
        if self.options.output == "text":
            if line.strip():
                ctx.emit("text", text=line)
            return
        value = _json_object(line)
        if value is None:
            if line.strip():
                ctx.emit("raw", text=line)
            return
        self.remember_session(value, ctx)
        kind = value.get("type")
        if isinstance(kind, str) and kind in EVENT_TYPES:
            ctx.emit(kind, **{k: v for k, v in value.items() if k not in ("type", "seq", "at")})
        else:
            ctx.emit("raw", data=value)

    def remember_session(self, value: dict[str, Any], ctx: RunContext) -> None:
        name = self.options.session_id_field
        if name and isinstance(value.get(name), str) and value[name]:
            ctx.instance.session["session_id"] = value[name]

    def classify(self, exit_code: int | None, reason: str, ctx: RunContext) -> RunOutcome:
        if reason == "timeout":
            return RunOutcome("timed_out", exit_code)
        if reason == "cancelled":
            return RunOutcome("cancelled", exit_code)
        if exit_code in self.options.success_exit_codes:
            return RunOutcome("complete", exit_code)
        return RunOutcome("failed", exit_code)

    # -- engine entry point --------------------------------------------------------------

    def run(self, ctx: RunContext) -> RunOutcome:
        argv = self.build_argv(ctx)
        stdin_text = ctx.prompt if self.uses_stdin(ctx) else None
        ctx.emit("interlink", event="spawn", program=argv[0], argc=len(argv))
        started = time.monotonic()
        process = ctx.spawn(
            argv,
            stdout_sink=lambda line: self.parse_line(line, ctx),
            stdin_text=stdin_text,
        )
        exit_code, reason = process.wait(deadline=ctx.deadline, cancelled=ctx.cancelled)
        outcome = self.classify(exit_code, reason, ctx)
        outcome.detail.setdefault("duration_s", round(time.monotonic() - started, 3))
        outcome.detail.setdefault("pid", process.pid)
        return outcome

    def doctor(self) -> dict[str, Any]:
        program = self.options.argv[0]
        found = self.which(program)
        return {
            "ok": bool(found),
            "checks": [self.check("executable", bool(found), found or f"{program} not on PATH")],
        }


def _json_object(line: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text.startswith("{"):
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None
