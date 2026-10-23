"""Claude Code as the harness *under test*, via ``claude -p --output-format stream-json``.

This is the reverse direction of the usual setup: some MCP client drives Interlink,
and Interlink drives a headless Claude Code inside a throwaway copy of a project.

With ``isolate_home = true`` (default) Claude Code cannot see your login in ~/.claude,
so put ``ANTHROPIC_API_KEY`` under ``secrets`` (the default here) or set
``isolate_home = false`` knowingly. Status: parser covered by fixture tests; not yet
exercised against a live ``claude`` binary in CI.
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import Field

from interlink.adapters.base import AdapterOptions, RunContext, RunOutcome
from interlink.adapters.command import CommandAdapter, CommandOptions, _json_object


class ClaudeCodeOptions(CommandOptions):
    command: str = "claude"
    argv: list[str] = Field(default_factory=lambda: ["claude"])  # derived; see build_argv
    model: str | None = None
    permission_mode: str | None = Field(
        None, description="e.g. 'acceptEdits' or 'plan'. Default: Claude Code's own default."
    )
    allowed_tools: list[str] = Field(default_factory=list)
    max_turns: int | None = Field(None, ge=1, le=500)
    extra_args: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=lambda: ["ANTHROPIC_API_KEY"])
    output: str = "jsonl"  # type: ignore[assignment]


class ClaudeCodeAdapter(CommandAdapter):
    summary: ClassVar[str] = "Headless Claude Code (`claude -p --output-format stream-json`)."
    Options: ClassVar[type[AdapterOptions]] = ClaudeCodeOptions
    options: ClaudeCodeOptions

    def build_argv(self, ctx: RunContext) -> list[str]:
        o = self.options
        argv = [o.command, "-p", "--output-format", "stream-json", "--verbose"]
        if o.model:
            argv += ["--model", o.model]
        if o.permission_mode:
            argv += ["--permission-mode", o.permission_mode]
        if o.allowed_tools:
            argv += ["--allowedTools", ",".join(o.allowed_tools)]
        if o.max_turns:
            argv += ["--max-turns", str(o.max_turns)]
        session = ctx.instance.session.get("session_id")
        if session:
            argv += ["--resume", str(session)]
        return argv + list(o.extra_args)

    def uses_stdin(self, ctx: RunContext) -> bool:
        return True  # prompt goes to stdin: never on the command line

    def parse_line(self, line: str, ctx: RunContext) -> None:
        value = _json_object(line)
        if value is None:
            if line.strip():
                ctx.emit("raw", text=line)
            return
        if isinstance(value.get("session_id"), str) and value["session_id"]:
            ctx.instance.session["session_id"] = value["session_id"]
        kind = value.get("type")
        if kind == "system":
            ctx.emit("status", subtype=value.get("subtype"), model=value.get("model"))
        elif kind in ("assistant", "user"):
            for block in (value.get("message") or {}).get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    ctx.emit("text", text=str(block.get("text", "")))
                elif block.get("type") == "tool_use":
                    ctx.emit(
                        "tool_use",
                        tool=block.get("name"),
                        input=block.get("input"),
                        id=block.get("id"),
                    )
                elif block.get("type") == "tool_result":
                    ctx.emit(
                        "tool_result",
                        id=block.get("tool_use_id"),
                        is_error=block.get("is_error", False),
                        content=block.get("content"),
                    )
        elif kind == "result":
            if value.get("is_error"):
                ctx.instance.state[f"result_error:{ctx.run_id}"] = True
            ctx.emit(
                "result",
                text=value.get("result"),
                is_error=value.get("is_error"),
                subtype=value.get("subtype"),
                num_turns=value.get("num_turns"),
                duration_ms=value.get("duration_ms"),
                total_cost_usd=value.get("total_cost_usd"),
            )
        else:
            ctx.emit("raw", data=value)

    def classify(self, exit_code: int | None, reason: str, ctx: RunContext) -> RunOutcome:
        outcome = super().classify(exit_code, reason, ctx)
        # Claude Code can exit 0 while reporting an error result (e.g. "Not logged in").
        if outcome.state == "complete" and ctx.instance.state.pop(
            f"result_error:{ctx.run_id}", False
        ):
            outcome.state = "failed"
            outcome.detail["claude"] = "result reported is_error"
        return outcome

    def doctor(self) -> dict[str, Any]:
        found = self.which(self.options.command)
        return {
            "ok": bool(found),
            "checks": [self.check("executable", bool(found), found or "claude not on PATH")],
        }
